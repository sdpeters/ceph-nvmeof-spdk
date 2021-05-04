/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is a redirector bdev, and part of the Adaptive Distributed NVMe-oF
 * Namespaces (ADNN) system.
 *
 * ADNN adapts NVMe-oF to distributed block storage systems. When a volume is
 * scattered over several storage nodes, point to point protocols like NVMe-oF
 * can't get host IO directly to every LBA of that volume. These systems typically
 * use custom block layer clients in the hosts, or route IO to a gateway that
 * forwards it to the right storage node. ADNN extends NVMe-oF by exposing these
 * volumes from NVMe-oF targets in all the storage nodes, and enabling hosts to
 * learn which volume extents are located on which targets.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_null_hash.h"
#include "vbdev_redirector_ceph_hash.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector_target_state.h"
#include "vbdev_redirector_target_admin_cmd.h"
#include "vbdev_redirector_hint_learning.h"
#include "vbdev_redirector_rule_table.h"
#include "vbdev_redirector_channel.h"
#include "vbdev_redirector_nvme_hints.h"
#include "vbdev_redirector_process_nvme_admin.h"
#include "vbdev_redirector_json.h"
#include "vbdev_redirector_data_plane.h"
#include "vbdev_redirector.h"
#include "spdk/bdev.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/conf.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/bdev_module.h"
#include "spdk/version.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

static int vbdev_redirector_init(void);
static int vbdev_redirector_get_ctx_size(void);
static void vbdev_redirector_examine(struct spdk_bdev *bdev);
static void vbdev_redirector_finish(void);
static void vbdev_redirector_finish_start(void);

struct spdk_bdev_module redirector_if = {
	.name = "redirector",
	.module_init = vbdev_redirector_init,
	.config_text = NULL,
	.get_ctx_size = vbdev_redirector_get_ctx_size,
	.examine_config = vbdev_redirector_examine,
	.fini_start = vbdev_redirector_finish_start,
	.module_fini = vbdev_redirector_finish,
	.config_json = vbdev_redirector_config_json
};

SPDK_BDEV_MODULE_REGISTER(redirector, &redirector_if)

struct redirector_all_config_tailq g_redirector_config =
	TAILQ_HEAD_INITIALIZER(g_redirector_config);
struct redirector_all_tailq	g_redirector_bdevs =
	TAILQ_HEAD_INITIALIZER(g_redirector_bdevs);

bool g_shutdown_started = false;

struct redirector_completion_ctx {
	redirector_completion_cb cb_fn;
	void *cb_ctx;
};

const struct spdk_uuid null_uuid = {};

const char *
rd_th_name(void)
{
	const struct spdk_thread *thread = spdk_get_thread();

	if (thread) {
		return spdk_thread_get_name(thread);
	} else {
		return "unknown thread";
	}
}

static bool
redirector_config_unlinked(struct redirector_config *n)
{
	return ((NULL == n->config_link.tqe_next) &&
		(NULL == n->config_link.tqe_prev));
}

static void
free_redirector_config(struct redirector_config *n)
{
	if (n->redirector_bdev) {
		n->redirector_bdev->config = NULL;
	}
	g_sequence_free(n->targets_by_nqn);
	g_sequence_free(n->targets);
	g_sequence_free(n->hints);
	/* hash_hint_tables.* is freed above with the hints that contain them. */
	free(n->redirector_name);
	free(n->nqn);
	n->config_link.tqe_next = NULL;
	n->config_link.tqe_prev = NULL;
	free(n);
}

/* Callback for unregistering the IO device. */
static void
_device_unregister_cb(void *io_device)
{
	struct redirector_bdev *rd_node  = io_device;
	struct redirector_config *config = rd_node->config;

	spdk_poller_unregister(&rd_node->hint_poller);

	/* Done with this rd_node. */
	if (config && (config->redirector_bdev == rd_node)) {
		config->redirector_bdev = NULL;
		if (redirector_config_unlinked(config)) {
			free_redirector_config(config);
		}
	}
	if (rd_node->locations) {
		g_sequence_free(rd_node->locations);
	}
	g_sequence_free(rd_node->applied_rules);
	if (rd_node->replaced_rules) {
		g_sequence_free(rd_node->replaced_rules);
	}
	free(rd_node->hint_page.buf);
	free(rd_node->hint_page.applied_buf);
	free(rd_node->hint_page.replaced_buf);
	free(rd_node->redirector_bdev.name);
	free(rd_node);
}

/* Called after we've unregistered following a hot remove callback.
 * Our finish entry point will be called next.
 */
int
vbdev_redirector_destruct(void *ctx)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;
	size_t target_bdev_index;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Destroying redirector %s\n",
		      rd_node->config->redirector_name);

	/* It is important to follow this exact sequence of steps for destroying
	 * a vbdev...
	 */

	TAILQ_REMOVE(&g_redirector_bdevs, rd_node, bdev_link);

	for (target_bdev_index = 0;
	     target_bdev_index < rd_node->num_rd_targets;
	     target_bdev_index++) {

		if (rd_node->targets[target_bdev_index].bdev) {
			/* Unclaim the underlying bdev. */
			spdk_bdev_module_release_bdev(rd_node->targets[target_bdev_index].bdev);

			/* Close the underlying bdev. */
			spdk_bdev_close(rd_node->targets[target_bdev_index].desc);
		}

	}

	/* Unregister the io_device. */
	spdk_io_device_unregister(rd_node, _device_unregister_cb);

	return 0;
}

static void
free_redirector_completion_ctx(struct redirector_completion_ctx *ctx)
{
	free(ctx);
}

void
redirector_call_completions(GSList **pcompletions, const int status)
{
	struct redirector_completion_ctx *ctx;

	assert(pcompletions);
	while (*pcompletions) {
		ctx = (*pcompletions)->data;
		*pcompletions = g_slist_remove(*pcompletions, ctx);
		if (ctx->cb_fn) {
			ctx->cb_fn(ctx->cb_ctx, status);
		}
		free_redirector_completion_ctx(ctx);
	}
}

void
redirector_schedule_completion(GSList **pcompletions, redirector_completion_cb cb_fn, void *cb_ctx)
{
	struct redirector_completion_ctx *ctx;

	assert(pcompletions);
	if (cb_fn) {
		ctx = calloc(1, sizeof(*ctx));
		if (!ctx) {
			cb_fn(cb_ctx, -ENOMEM);
			return;
		}
		ctx->cb_fn = cb_fn;
		ctx->cb_ctx = cb_ctx;
		*pcompletions = g_slist_prepend(*pcompletions, ctx);
	}
}

struct redirector_config *vbdev_redirector_find_config(const char *redirector_name)
{
	struct redirector_config *config;

	TAILQ_FOREACH(config, &g_redirector_config, config_link) {
		assert(config != config->config_link.tqe_next);
		if (strcmp(redirector_name, config->redirector_name) == 0) {
			return config;
		}
	}
	return NULL;
}

/* Create the redirector association from the bdev and vbdev name and insert
 * on the global list. */
static int
vbdev_redirector_insert_config(const struct rpc_construct_redirector_bdev *req,
			       struct redirector_config **new_config)
{
	struct redirector_config *config;
	struct redirector_target *target;
	size_t i = 0;

	if (new_config) {
		*new_config = NULL;
	}

	if (vbdev_redirector_find_config(req->name)) {
		SPDK_ERRLOG("redirector bdev %s already exists\n", req->name);
		return -EEXIST;
	}

	config = calloc(1, sizeof(struct redirector_config));
	if (!config) {
		SPDK_ERRLOG("could not allocate redirector_config\n");
		return -ENOMEM;
	}
	config->targets = g_sequence_new(redirector_target_destroy_fn);
	config->targets_by_nqn = g_sequence_new(NULL); /* No destruct when removed from this list */
	config->hints = g_sequence_new(location_hint_destroy_fn);

	config->redirector_name = strdup(req->name);
	if (!config->redirector_name) {
		SPDK_ERRLOG("could not allocate name->redirector_name\n");
		free_redirector_config(config);
		return -ENOMEM;
	}

	spdk_uuid_copy(&config->uuid, &req->uuid);

	if (req->nqn) {
		config->nqn = strdup(req->nqn);
	}

	if (req->size_configured) {
		config->size_configured = true;
		config->blockcnt = req->size_config.blockcnt;
		config->blocklen = req->size_config.blocklen;
		config->required_alignment = req->size_config.required_alignment;
		config->optimal_io_boundary = req->size_config.optimal_io_boundary;
	}

	for (i = 0; i < req->default_targets.num_default_targets; i++) {
		target = redirector_config_find_target(config, req->default_targets.default_target_names[i]);
		if (target) {
			SPDK_WARNLOG("Duplicate redirector target %s ignored\n",
				     req->default_targets.default_target_names[i]);
			continue;
		}
		target = alloc_redirector_target(req->default_targets.default_target_names[i],
						 RD_DEFAULT_TARGET_PRIORITY,
						 true,	/* Default targets persisted in config */
						 true,	/* Default targets required for start */
						 true,	/* Default target must be a redirector */
						 false);/* Default target will be probed to confirm it's a redirector */
		if (!target) {
			SPDK_ERRLOG("could not allocate redirector target for %s\n",
				    req->default_targets.default_target_names[i]);
			free_redirector_config(config);
			return -ENOMEM;
		}
		redirector_config_add_target(config, target);
	}

	assert(config->config_link.tqe_next == NULL);
	assert(config->config_link.tqe_prev == NULL);
	TAILQ_INSERT_TAIL(&g_redirector_config, config, config_link);

	if (new_config) {
		*new_config = config;
	}
	return 0;
}

/* On init, just parse config file and build list of rd vbdevs and bdev name pairs. */
static int
vbdev_redirector_init(void)
{
	/* spdk_log_set_flag("vbdev_redirector"); */
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "vbdev_redirector_init\n");

	return 0;
}

/* Called when the entire module is being torn down. */
static void
vbdev_redirector_finish_start(void)
{
	struct redirector_bdev *rd_node, *tmp;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "vbdev_redirector_finish_start\n");
	g_shutdown_started = true;
	TAILQ_FOREACH_SAFE(rd_node, &g_redirector_bdevs, bdev_link, tmp) {
		/* Wait for a channel update with g_shutdown_started set */
		vbdev_redirector_update_channel_state_sync(rd_node);
	}
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "vbdev_redirector_finish_start done\n");
}

/* Called when the entire module is being torn down. */
static void
vbdev_redirector_finish(void)
{
	struct redirector_config *config;

	while ((config = TAILQ_FIRST(&g_redirector_config))) {
		TAILQ_REMOVE(&g_redirector_config, config, config_link);
		free_redirector_config(config);
	}
}

/* When we register our bdev this is how we specify our entry points. */
static const struct spdk_bdev_fn_table vbdev_redirector_fn_table = {
	.destruct		= vbdev_redirector_destruct,
	.submit_request		= vbdev_redirector_submit_request,
	.io_type_supported	= vbdev_redirector_io_type_supported,
	.get_io_channel		= vbdev_redirector_get_io_channel,
	.dump_info_json		= vbdev_redirector_dump_info_json,
};

#define RD_HINT_POLL_INTERVAL_US (uint64_t)(5 * 1000 * 1000)

static void
vbdev_redirector_register_finish(void *ctx, int rc)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;
	int status = rc;

	if (status) {
		SPDK_ERRLOG("Not registering redirector %s. Callback status=%d\n",
			    rd_node->config->redirector_name, rc);
	} else {
		rd_node->hint_poller =
			spdk_poller_register(vbdev_redirector_hint_poll, rd_node, RD_HINT_POLL_INTERVAL_US);
		assert(NULL != rd_node->hint_poller);
		rd_node->registered = true;
		status = spdk_bdev_register(&rd_node->redirector_bdev);
		if (status) {
			SPDK_ERRLOG("could not register redirector %s. register failed with %d\n",
				    rd_node->config->redirector_name, rc);
		}
	}
	if (status) {
		vbdev_redirector_destruct(rd_node);
		return;
	}
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s] Redirector %s created\n",
		      rd_th_name(), rd_node->config->redirector_name);
}

static void
vbdev_redirector_register_continue(void *ctx, int status)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s initial target identification complete\n", rd_node->config->redirector_name);

	/* Set the redirector bdev's UUID. If we're inferring the LN NGUID from the targets, do that now. It may
	 * affect how hints are applied, if hints refer to namespace IDs. */
	if (!rd_uuid_known(rd_node->config)) {
		GSequenceIter *target_iter;
		struct redirector_target *iter_target = NULL;

		target_iter = g_sequence_get_begin_iter(rd_node->config->targets);
		while (!g_sequence_iter_is_end(target_iter)) {
			iter_target = (struct redirector_target *)g_sequence_get(target_iter);
			if (iter_target->confirmed_redir && rd_target_uuid_known(iter_target)) {
				/* First nonempty UUID from a confirmed redirector */
				char uuid_str[SPDK_UUID_STRING_LEN];
				int rc = spdk_uuid_fmt_lower(uuid_str, sizeof(uuid_str), &iter_target->uuid);
				assert(rc == 0);
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s inherits UUID %s of confirmed redirector target %s\n",
					      rd_node->config->redirector_name, uuid_str, iter_target->name);
				spdk_uuid_copy(&rd_node->config->uuid, &iter_target->uuid);
				rd_node->config->uuid_inherited = true;
				break;
			}
			target_iter = g_sequence_iter_next(target_iter);
		}
	}

	/* If the UUID is still unknown, generate one */
	if (!rd_uuid_known(rd_node->config)) {
		char uuid_str[SPDK_UUID_STRING_LEN];
		int rc;
		spdk_uuid_generate(&rd_node->config->uuid);
		rd_node->config->uuid_generated = true;
		rc = spdk_uuid_fmt_lower(uuid_str, sizeof(uuid_str), &rd_node->config->uuid);
		assert(rc == 0);
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s uses generated UUID %s\n",
			      rd_node->config->redirector_name, uuid_str);
	}

	/* However we got this UUID, put it in our bdev */
	spdk_uuid_copy(&rd_node->redirector_bdev.uuid, &rd_node->config->uuid);

	/* Ensure there's a rule table in the bdev before IO can start. */
	vbdev_redirector_update_locations(rd_node);
	vbdev_redirector_update_channel_state(rd_node, vbdev_redirector_register_finish, rd_node);

	if (!rd_node->registered) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s creation in progress\n", rd_node->config->redirector_name);
	}
}

/*
 * Create/register a redirector if it has all of its required targets
 */
int
vbdev_redirector_register(struct redirector_config *config)
{
	struct redirector_bdev *rd_node;
	GSequenceIter *target_iter;
	struct redirector_target *iter_target;
	struct spdk_bdev *other_redirector_target;
	int rc = 0;
	bool all_matched = true;	/* All required targets have been registered */
	bool auth_targets = false;	/* Targets of all authoritative hints are configured */

	/* Have we now found all the required targets? */
	target_iter = g_sequence_get_begin_iter(config->targets);
	while (!g_sequence_iter_is_end(target_iter)) {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		/* If target is missing and required, we'll wait for it */
		if (iter_target->required && !iter_target->bdev) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s required target %s not yet registered\n",
				      config->redirector_name, iter_target->name);
			all_matched = false;
		}
		target_iter = g_sequence_iter_next(target_iter);
	}

	/* Do all auth hints have configured targets? */
	if (config->auth_hints) {
		GSequenceIter *hint_iter;
		struct location_hint *iter_hint;
		struct redirector_target *target;

		auth_targets = true;
		hint_iter = g_sequence_get_begin_iter(config->hints);
		while (!g_sequence_iter_is_end(hint_iter)) {
			iter_hint = g_sequence_get(hint_iter);
			if (iter_hint->authoritative) {
				target = redirector_config_find_target(config, location_hint_target_name(iter_hint));
				if (!target) {
					SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
						      "Auth target %s not configured yet\n",
						      location_hint_target_name(iter_hint));
					auth_targets = false;
					break;
				}
			}
			hint_iter = g_sequence_iter_next(hint_iter);
		}
	}

	if (config->auth_hints) {
		/* If we have auth hints, we don't start until all the auth targets are configured */
		if (!auth_targets) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s waiting for all targets of auth hints to register\n",
				      config->redirector_name);
			return rc;
		}
	} else {
		/* If we don't have auth hints, we start when all the required targets can be opened */
		if (!all_matched) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s with no auth hints waiting for all required targets to register\n",
				      config->redirector_name);
			return rc;
		}
	}

	/* If the size isn't configured, we need one of the required targets to inherit that from */
	if (!all_matched && !config->size_configured) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s with no configured size awaiting a redirector target to inherit from\n",
			      config->redirector_name);
		return rc;
	}

	if (all_matched) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] All required targets for redirector %s have registered\n",
			      rd_th_name(), config->redirector_name);
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] Targets of authoritative location hints for redirector %s have registered\n",
			      rd_th_name(), config->redirector_name);
	}

	if (!vbdev_redirector_default_target(config)) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] No default target available for redirector %s\n",
			      rd_th_name(), config->redirector_name);
		return rc;
	}

	rd_node = calloc(1, sizeof(struct redirector_bdev));
	if (!rd_node) {
		rc = -ENOMEM;
		SPDK_ERRLOG("could not allocate rd_node\n");
		return rc;
	}

	config->redirector_bdev = rd_node;
	rd_node->config = config;
	rd_node->locations = g_sequence_new(location_hint_destroy_fn);
	rd_node->applied_rules = g_sequence_new(location_hint_destroy_fn);
	rd_node->replaced_rules = NULL;

	rd_node->redirector_bdev.name = strdup(config->redirector_name);
	if (!rd_node->redirector_bdev.name) {
		rc = -ENOMEM;
		SPDK_ERRLOG("could not allocate redirector_bdev config\n");
		free(rd_node);
		return rc;
	}
	rd_node->redirector_bdev.product_name = "redirector";
	rd_node->redirector_bdev.split_on_optimal_io_boundary = true;

	/* Find a redirector target to inherit properties from */
	target_iter = g_sequence_get_begin_iter(config->targets);
	other_redirector_target = NULL;
	while (!g_sequence_iter_is_end(target_iter)) {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		if (iter_target->bdev && !iter_target->removing &&
		    iter_target->redirector && !other_redirector_target) {
			other_redirector_target = iter_target->bdev;
			/* Use the first one we find */
			break;
		}
		target_iter = g_sequence_iter_next(target_iter);
	}

	/* Some targets may have a write cache */
	rd_node->redirector_bdev.write_cache = true;

	if (config->size_configured) {
		/* Use configured properties */
		rd_node->redirector_bdev.required_alignment = spdk_u32log2(config->required_alignment);
		rd_node->redirector_bdev.optimal_io_boundary = config->optimal_io_boundary / config->blocklen;
		rd_node->redirector_bdev.blocklen = config->blocklen;
		rd_node->redirector_bdev.blockcnt = config->blockcnt;
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s gets size properties from configuration\n",
			      config->redirector_name);
	} else {
		if (other_redirector_target) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s inherits properties from other redirector %s\n",
				      config->redirector_name, spdk_bdev_get_name(other_redirector_target));
		} else {
			SPDK_ERRLOG("None of the initial targets of redirector %s are redirectors\n",
				    config->redirector_name);
			vbdev_redirector_destruct(rd_node);
			return (-EINVAL);
		}

		/* Copy some properties from the underlying target bdev. */
		if (other_redirector_target->required_alignment) {
			rd_node->redirector_bdev.required_alignment = other_redirector_target->required_alignment;
		} else {
			rd_node->redirector_bdev.required_alignment = other_redirector_target->blocklen;
		}
		rd_node->redirector_bdev.optimal_io_boundary = other_redirector_target->optimal_io_boundary;
		rd_node->redirector_bdev.blocklen = other_redirector_target->blocklen;
		rd_node->redirector_bdev.blockcnt = other_redirector_target->blockcnt;
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s: blocklen=%"PRId32" blockcnt=%"PRId64" "
		      "required_alignment=%"PRId32" optimal_io_boundary=%"PRId32"\n",
		      config->redirector_name,
		      rd_node->redirector_bdev.blocklen,
		      rd_node->redirector_bdev.blockcnt,
		      rd_node->redirector_bdev.required_alignment,
		      rd_node->redirector_bdev.optimal_io_boundary);

	rd_node->redirector_bdev.ctxt = rd_node;
	rd_node->redirector_bdev.fn_table = &vbdev_redirector_fn_table;
	rd_node->redirector_bdev.module = &redirector_if;
	TAILQ_INSERT_TAIL(&g_redirector_bdevs, rd_node, bdev_link);

	spdk_io_device_register(rd_node, redirector_bdev_ch_create_cb, redirector_bdev_ch_destroy_cb,
				sizeof(struct redirector_bdev_io_channel),
				config->redirector_name);
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s io_device=%p\n", config->redirector_name, rd_node);

	/* Construct redirector target list from configured targets that have appeared */
	target_iter = g_sequence_get_begin_iter(config->targets);
	while (!g_sequence_iter_is_end(target_iter)) {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		if ((iter_target->bdev || target_index_sticky(iter_target)) && !iter_target->removing) {
			rc = redirector_assign_target_index(rd_node, iter_target);
			if (rc) {
				vbdev_redirector_destruct(rd_node);
				return (rc);
			}
		}
		target_iter = g_sequence_iter_next(target_iter);
	}

	/* Continue redirector init once all the in-flight target admin commands complete */
	redirector_schedule_tgt_adm_cmd_in_flight_cpl(rd_node, vbdev_redirector_register_continue, rd_node);

	return rc;
}

/* Create the redirector disk from the given bdev and vbdev name. */
int
create_redirector(const struct rpc_construct_redirector_bdev *req)
{
	struct spdk_bdev *bdev = NULL;
	int rc = 0;
	size_t target_bdev_index;
	bool all_targets_present = true;
	int register_rc;
	struct redirector_target *target;
	struct redirector_config *new_config;

	/* Insert the bdev into our global name list even if it doesn't exist yet,
	 * it may show up soon...
	 */
	rc = vbdev_redirector_insert_config(req, &new_config);
	if (rc) {
		return rc;
	}

	/* Register all the redirector target devs that already exist with the redirector */
	for (target_bdev_index = 0;
	     target_bdev_index < req->default_targets.num_default_targets;
	     target_bdev_index++) {

		target = redirector_config_find_target(new_config,
						       req->default_targets.default_target_names[target_bdev_index]);
		bdev = spdk_bdev_get_by_name(req->default_targets.default_target_names[target_bdev_index]);
		if (bdev || target_index_sticky(target)) {
			register_rc = vbdev_redirector_register_target(
					      req->default_targets.default_target_names[target_bdev_index], bdev);
			/* fail create on first target vdev register fail */
			if (register_rc) {
				return register_rc;
			}
		} else {
			all_targets_present = false;
		}
	}

	if (!all_targets_present) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s creation deferred pending required target arrival\n",
			      req->name);
	}
	return 0;
}

int
delete_redirector(const struct rpc_delete_redirector *req, const spdk_bdev_unregister_cb cb_fn,
		  void *cb_arg)
{
	struct redirector_config *config;
	struct spdk_bdev *bdev;
	bool found_config = false;
	int ret = 0;

	/* Remove the association (vbdev, bdev) from g_redirector_config. This is required so that the
	 * vbdev does not get re-created if the same bdev is constructed at some other time,
	 * unless the underlying bdev was hot-removed.
	 */
	TAILQ_FOREACH(config, &g_redirector_config, config_link) {
		assert(config != config->config_link.tqe_next);
		if (strcmp(config->redirector_name, req->name) == 0) {
			found_config = true;
			TAILQ_REMOVE(&g_redirector_config, config, config_link);
			/* Mark config for deletion in _device_unregister_cb() */
			config->config_link.tqe_next = NULL;
			config->config_link.tqe_prev = NULL;
			break;
		}
	}

	bdev = spdk_bdev_get_by_name(req->name);
	if (!bdev || bdev->module != &redirector_if) {
		if (found_config) {
			free_redirector_config(config);
			cb_fn(cb_arg, 0);
		} else {
			ret = -ENODEV;
			cb_fn(cb_arg, -ENODEV);
		}
		return ret;
	}

	/* Additional cleanup happens in the destruct callback,
	   including freeing the now unlinked config struct. */
	spdk_bdev_unregister(bdev, cb_fn, cb_arg);

	return 0;
}

/* Because we specified this function in our rd bdev function table when we
 * registered our rd bdev, we'll get this call anytime a new bdev shows up.
 * Here we need to decide if we care about it and if so what to do. We
 * parsed the config file at init so we check the new bdev against the list
 * we built up at that time and if the user configured us to attach to this
 * bdev, here's where we do it.
 */
static void
vbdev_redirector_examine(struct spdk_bdev *bdev)
{
	vbdev_redirector_register_target(spdk_bdev_get_name(bdev), bdev);

	spdk_bdev_module_examine_done(&redirector_if);
}

SPDK_LOG_REGISTER_COMPONENT("vbdev_redirector", SPDK_LOG_VBDEV_REDIRECTOR)
