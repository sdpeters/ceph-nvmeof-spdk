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
 * The set of configured targets is maanaged here. Each target is
 * configured by bdev name or NQN, and the redirector attmpts to
 * connect to all of them. The target connections themselves are
 * managed elsewhere. Here we're concerned with ensuring we remove
 * hints to targets the redirector won't connect to, and ensuring
 * there's at least one viable default target for the redirector's IO.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector.h"
#include "spdk_internal/log.h"

struct redirector_target *
alloc_redirector_target(const char *target_name,
			const int priority,
			const bool persistent,
			const bool required,
			const bool redirector,
			const bool dont_probe)
{
	struct redirector_target *target;

	target = calloc(1, sizeof(struct redirector_target));
	if (!target) {
		SPDK_ERRLOG("could not allocate redirector target\n");
		return NULL;
	}

	target->name = strdup(target_name);
	if (!target->name) {
		SPDK_ERRLOG("could not allocate redirector target name\n");
		free(target);
		return NULL;
	}

	target->priority = priority;
	target->persistent = persistent;
	target->required = required;
	target->redirector = redirector;
	target->dont_probe = dont_probe;
	target->target_index = -1; /* Unknown index */
	return target;
}

static void
free_redirector_target(struct redirector_target *target)
{
	free(target->name);
	free(target->nqn);
	free(target);
}

static void
redirector_target_destroy(gpointer data)
{
	free_redirector_target((struct redirector_target *)data);
}

/* Mostly to assert that redirector_target_destroy has the right prototype */
const GDestroyNotify redirector_target_destroy_fn = redirector_target_destroy;

/*
 * Compare target for sorting in targets list (GSequence)
 *
 * Targets are sorted by name, which must be unique.
 */
static int
redirector_target_compare(const struct redirector_target *lhs, const struct redirector_target *rhs)
{
	return strcmp(lhs->name, rhs->name);
}

static gint
redirector_target_data_compare(gconstpointer lhs, gconstpointer rhs, gpointer ignored)
{
	return redirector_target_compare((const struct redirector_target *)lhs,
					 (const struct redirector_target *)rhs);
}

const GCompareDataFunc redirector_target_data_compare_fn = redirector_target_data_compare;

/*
 * Compare target for sorting in targets_by_nqn list (GSequence). This GSequence contains only targets that have
 * nqn strings.
 *
 * Targets are sorted by nqn string (which may not be unique), then by target priority (numerically increasing,
 * also not necessarily unique), and finally by the address of the target structure.
 *
 * The address of the target struct is included in the key to enables quick lookup and removal of specific
 * targets in this GSequence.
 */
static int
redirector_target_by_nqn_compare(const struct redirector_target *lhs,
				 const struct redirector_target *rhs,
				 const bool compare_priority,
				 const bool compare_addr)
{
	int result;

	assert(lhs->nqn);
	assert(rhs->nqn);
	result = strcmp(lhs->nqn, rhs->nqn);
	if (result) {
		return result;
	}

	if (compare_priority) {
		if (lhs->priority != rhs->priority) {
			if (lhs->priority < rhs->priority) {
				return -1;
			} else {
				return 1;
			}
		}
	}

	if (compare_addr) {
		if (lhs != rhs) {
			if (lhs < rhs) {
				return -1;
			} else {
				return 1;
			}
		}
	}

	return 0;
}

struct redirector_target_by_nqn_data_compare_opts {
	bool	compare_priority;
	bool	compare_addresses;
};

static gint
redirector_target_by_nqn_data_compare(gconstpointer lhs, gconstpointer rhs, gpointer opts)
{
	struct redirector_target_by_nqn_data_compare_opts *l_opts =
		(struct redirector_target_by_nqn_data_compare_opts *) opts;

	return redirector_target_by_nqn_compare((struct redirector_target *)lhs,
						(struct redirector_target *)rhs,
						(l_opts ? l_opts->compare_priority : true),
						(l_opts ? l_opts->compare_addresses : false));
}

const GCompareDataFunc redirector_target_by_nqn_data_compare_fn =
	redirector_target_by_nqn_data_compare;

/* Compare entire target for duplicate detection and display */
static int
redirector_target_equal(const struct redirector_target *lhs, const struct redirector_target *rhs,
			const bool ignore_flags)
{
	int result = redirector_target_compare(lhs, rhs);

	if (result) {
		return result;
	}

	if (!ignore_flags) {
		if (lhs->required != rhs->required) {
			if (lhs->required) {
				return -1;
			} else {
				return 1;
			}
		}

		if (lhs->persistent != rhs->persistent) {
			if (lhs->persistent) {
				return -1;
			} else {
				return 1;
			}
		}

		if (lhs->redirector != rhs->redirector) {
			if (lhs->redirector) {
				return -1;
			} else {
				return 1;
			}
		}

		if (lhs->dont_probe != rhs->dont_probe) {
			if (lhs->dont_probe) {
				return -1;
			} else {
				return 1;
			}
		}
	}

	return 0;
}

static void
redirector_unassign_target_index(struct redirector_bdev *rd_node, struct redirector_target *target)
{
	struct redirector_target *target_config;

	if (!target_index_unassigned(target)) {
		bool had_bdev;

		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Unassigning target index (%d) of target %s on redirector %s\n",
			      target->target_index, target->name, rd_node->config->redirector_name);

		if (!target_index_sticky(target)) {
			assert(target->target_index >= 0);
			assert(rd_node->targets[target->target_index].bdev);
		}
		if (!rd_node->targets[target->target_index].bdev) {
			assert(target_index_sticky(target));
		}
		assert(rd_node->targets[target->target_index].drain);
		target_config = rd_node->targets[target->target_index].target_config;
		assert(target_config);
		had_bdev = rd_node->targets[target->target_index].bdev != NULL;
		if (had_bdev) {
			/* Unclaim the target bdev */
			spdk_bdev_module_release_bdev(rd_node->targets[target->target_index].bdev);
			rd_node->targets[target->target_index].bdev = NULL;

			/* Close the target bdev */
			spdk_bdev_close(rd_node->targets[target->target_index].desc);
			rd_node->targets[target->target_index].desc = NULL;
		}

		rd_node->targets[target->target_index].max_qd = 0;

		/* Clear draining flag before we do the next update */
		rd_node->targets[target->target_index].drain = false;

		if (!target_index_sticky(target)) {
			/* Mark index as reusable */
			rd_node->targets[target->target_index].free_index = true;

			rd_node->targets[target->target_index].target_config = NULL;

			target->target_index = -1;

			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Unassigned target index of target %s on redirector %s\n",
				      target->name, rd_node->config->redirector_name);
		} else {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Closed target bdev of auth target %s on redirector %s. "
				      "Index %d remains assigned.\n",
				      target->name, rd_node->config->redirector_name,
				      target->target_index);
		}
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Target index of target %s on redirector %s already unassigned\n",
			      target->name, rd_node->config->redirector_name);
	}
}

void
redirector_config_add_target(struct redirector_config *config, struct redirector_target *target)
{
	assert(config);
	assert(target);
	g_sequence_insert_sorted(config->targets, (gpointer)target, redirector_target_data_compare_fn,
				 NULL);
}

static GSequenceIter *
redirector_config_find_target_iter(const struct redirector_config *config, const char *name)
{
	struct redirector_target lookup = {
		.name = (char *) name
	};

	return g_sequence_lookup(config->targets, &lookup, redirector_target_data_compare_fn, NULL);
}

/* Target NQNs aren't necessarily unique. Return the iter for the first target in the by_nqn sequence with the
 * matching nqn */
GSequenceIter *
redirector_config_find_first_target_by_nqn_iter(const struct redirector_config *config,
		const char *nqn)
{
	struct redirector_target_by_nqn_data_compare_opts l_opts = {
		.compare_priority = false,
		.compare_addresses = false
	};
	struct redirector_target lookup = {
		.nqn = (char *) nqn
	};
	static GSequenceIter *search_iter;
	static GSequenceIter *prev_iter;
	struct redirector_target *prev_target;
	int comp_result;

	if (RD_DEBUG_LOG_NQN_TARGET) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s nqn=%s\n", config->redirector_name, nqn);
	}
	search_iter = g_sequence_lookup(config->targets_by_nqn, &lookup,
					redirector_target_by_nqn_data_compare_fn, &l_opts);
	if (!search_iter) {
		/* No targets have this NQN */
		if (RD_DEBUG_LOG_NQN_TARGET) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s nqn=%s not found\n",
				      config->redirector_name, nqn);
		}
		return NULL;
	}
	if (RD_DEBUG_LOG_NQN_TARGET) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s nqn=%s looking back from %s\n",
			      config->redirector_name, nqn, ((struct redirector_target *)g_sequence_get(search_iter))->name);
	}

	/* Target at search_iter has matching nqn, but might not be the first */
	do {
		if (g_sequence_iter_is_begin(search_iter)) {
			prev_iter = NULL;
		} else {
			prev_iter = g_sequence_iter_prev(search_iter);
		}
		if (prev_iter) {
			prev_target = g_sequence_get(prev_iter);
			if (RD_DEBUG_LOG_NQN_TARGET) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s nqn=%s considering %s\n",
					      config->redirector_name, nqn, prev_target->name);
			}
			comp_result = redirector_target_by_nqn_compare(&lookup, prev_target, false, false);
			if (0 == comp_result) {
				/* Previous target also has this NQN */
				search_iter = prev_iter;
			} else {
				/* Previous target has different NQN. This is the first match. */
				if (RD_DEBUG_LOG_NQN_TARGET) {
					SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
						      "Redirector %s nqn=%s first_match=%s\n",
						      config->redirector_name, nqn,
						      ((struct redirector_target *)g_sequence_get(search_iter))->name);
				}
				return search_iter;
			}
		}
	} while (prev_iter);

	/* There was no previous target, so search_iter is the first match */
	if (RD_DEBUG_LOG_NQN_TARGET) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s nqn=%s first_match=%s\n",
			      config->redirector_name, nqn, ((struct redirector_target *)g_sequence_get(search_iter))->name);
	}
	return search_iter;
}

/* Returns next iter if that target has the same NQN as iter, or NULL
 * if it is different. May also return is_end() */
GSequenceIter *
redirector_config_find_next_target_by_nqn_iter(const struct redirector_config *config,
		GSequenceIter *iter)
{
	struct redirector_target *iter_target;
	static GSequenceIter *next_iter;
	struct redirector_target *next_target;
	int comp_result;

	assert(iter);
	if (g_sequence_iter_is_end(iter)) {
		return NULL;
	}
	iter_target = g_sequence_get(iter);
	assert(iter_target->nqn);
	if (RD_DEBUG_LOG_NQN_TARGET) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s nqn=%s target=%s\n", config->redirector_name, iter_target->nqn, iter_target->name);
	}
	next_iter = g_sequence_iter_next(iter);
	if (g_sequence_iter_is_end(next_iter)) {
		if (RD_DEBUG_LOG_NQN_TARGET) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn=%s target=%s no next\n",
				      config->redirector_name, iter_target->nqn, iter_target->name);
		}
		return next_iter;
	}

	next_target = g_sequence_get(next_iter);
	if (RD_DEBUG_LOG_NQN_TARGET) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s nqn=%s considering %s\n",
			      config->redirector_name, iter_target->nqn, next_target->name);
	}
	comp_result = redirector_target_by_nqn_compare(iter_target, next_target, false, false);
	if (0 == comp_result) {
		/* Next target also has this NQN */
		if (RD_DEBUG_LOG_NQN_TARGET) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn=%s next target %s matches\n",
				      config->redirector_name, iter_target->nqn, next_target->name);
		}
		return next_iter;
	} else {
		/* The last target with this NQN was at iter. No Next */
		if (RD_DEBUG_LOG_NQN_TARGET) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn=%s next target %s has different NQN %s\n",
				      config->redirector_name, iter_target->nqn, next_target->name, next_target->nqn);
		}
		return NULL;
	}
}

/* Find the iter for this specific target structure */
static GSequenceIter *
redirector_config_find_this_target_by_nqn_iter(const struct redirector_config *config,
		struct redirector_target *target)
{
	struct redirector_target_by_nqn_data_compare_opts l_opts = {
		.compare_priority = true,
		.compare_addresses = true
	};

	return g_sequence_lookup(config->targets_by_nqn, target, redirector_target_by_nqn_data_compare_fn,
				 &l_opts);
}

static struct redirector_target *
redirector_config_find_target_and_iters(const struct redirector_config *config,
					const char *lookup_name,
					GSequenceIter **target_iter_out, GSequenceIter **target_by_nqn_iter_out)
{
	GSequenceIter *target_iter;
	GSequenceIter *target_by_nqn_iter = NULL;
	struct redirector_target *target = NULL;

	target_iter = redirector_config_find_target_iter(config, lookup_name);
	if (target_iter_out != NULL) {
		*target_iter_out = target_iter;
	}
	if (target_iter) {
		target = g_sequence_get(target_iter);
		if (target->nqn && target_by_nqn_iter_out) {
			target_by_nqn_iter = redirector_config_find_this_target_by_nqn_iter(config, target);
		}
	}
	if (target_by_nqn_iter_out) {
		*target_by_nqn_iter_out = target_by_nqn_iter;
	}
	return target;
}

struct redirector_target *
redirector_config_find_target(const struct redirector_config *config, const char *name)
{
	return redirector_config_find_target_and_iters(config, name, NULL, NULL);
}

static int
_redirector_config_mark_or_remove_target(struct redirector_config *config, const char *target_name,
		bool remove, bool hotremove, bool remove_config)
{
	GSequenceIter *existing_target_iter;
	GSequenceIter *existing_target_by_nqn_iter;
	struct redirector_target *existing_target;

	assert(config);
	assert(target_name);
	existing_target = redirector_config_find_target_and_iters(config, target_name,
			  &existing_target_iter, &existing_target_by_nqn_iter);
	if (!existing_target) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Target %s not found on redirector %s\n",
			      target_name, config->redirector_name);
		return -ENODEV;
	}
	if (!existing_target->removing) {
		existing_target->stats.removed_count++;
		if (hotremove) {
			existing_target->stats.hot_removed_count++;
		}
	}
	existing_target->removing |= true;
	existing_target->hotremove |= hotremove;
	existing_target->persistent &= !remove_config;

	if (remove) {
		if (existing_target_by_nqn_iter) {
			/* targets_by_nqn GSequence has NULL destructor. Do this first */
			g_sequence_remove(existing_target_by_nqn_iter);
		}
		/* Target destruct triggered by removal from targets GSequence */
		g_sequence_remove(existing_target_iter);
	}
	return 0;
}

static int
redirector_config_set_target_removing(struct redirector_config *config, const char *target_name,
				      const bool hotremove, bool remove_config)
{
	return _redirector_config_mark_or_remove_target(config, target_name, false, hotremove,
			remove_config);
}

int
redirector_config_remove_target(struct redirector_config *config, const char *target_name)
{
	return _redirector_config_mark_or_remove_target(config, target_name, true, false, true);
}

int
redirector_add_target(struct rpc_redirector_add_target *req)
{
	struct redirector_config *config;
	struct redirector_target *new_target;
	struct redirector_target *existing_target;
	struct spdk_bdev *bdev;
	int ret = 0;

	/* SPDK_NOTICELOG("Looking for redirector %s\n", req.redirector_name); */
	config = vbdev_redirector_find_config(req->redirector_name);
	if (!config) {
		SPDK_NOTICELOG("Redirector %s not found\n", req->redirector_name);
		return -ENODEV;
	}

	/* TODO: Add priority option to (NQN) targets */
	new_target = alloc_redirector_target(req->target_name, RD_DEFAULT_TARGET_PRIORITY,
					     req->persistent, req->required, req->redirector, req->dont_probe);
	if (!new_target) {
		SPDK_ERRLOG("Failed to allocate new target\n");
		return -ENOMEM;
	}

	existing_target = redirector_config_find_target(config, req->target_name);
	if (existing_target) {
		if (0 == redirector_target_equal(new_target, existing_target, false)) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Ignoring add of identical target %s on redirector %s\n",
				      req->target_name, config->redirector_name);
		} else {
			SPDK_ERRLOG("Target %s already exists on redirector %s\n",
				    req->target_name, config->redirector_name);
			ret = -EEXIST;
		}
		free_redirector_target(new_target);
		return ret;
	}

	redirector_config_add_target(config, new_target);

	if (config->auth_hints) {
		/*
		 * If any of the auth hints name this target, mark the target as auth. The target indexes of
		 * auth targets don't get unassigned, which is important for the ability to start groups
		 * of redirectors with auth hints pointing to each other because at least one of them has to
		 * start with zero connected targets.
		 *
		 * TODO: This only works for auth hints that refer to targtes by bdev name. Target NQNs are
		 * discovered when they come up. We should repeat this auth target marking in the target
		 * identify cb. Since hash hints only refer to their targets by NQN, that's where we'd mark
		 * the targets of an authoritative hash hint, but since the set of hash hint targets is
		 * dynamic we really don't want auth target behavior (sticky indexes) for those.
		 */
		GSequenceIter *hint_iter;
		struct location_hint *iter_hint;

		hint_iter = g_sequence_get_begin_iter(config->hints);
		while (!g_sequence_iter_is_end(hint_iter)) {
			iter_hint = g_sequence_get(hint_iter);
			if (location_hint_single_target(iter_hint) &&
			    0 == strcmp(req->target_name, location_hint_target_name(iter_hint))) {
				if (iter_hint->authoritative) {
					SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
						      "Marking target %s as the destination of auithoritative "
						      "location hints\n", req->target_name);
					new_target->auth_target = true;
				}
				break;
			}
			hint_iter = g_sequence_iter_next(hint_iter);
		}
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Added target %s to redirector %s (persistent=%d, required=%d, redirector=%d, dont_probe=%d)\n",
		      req->target_name, config->redirector_name, req->persistent, req->required, req->redirector,
		      req->dont_probe);

	bdev = spdk_bdev_get_by_name(req->target_name);
	if (bdev || new_target->auth_target) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "[%s] Activating%s target %s on redirector %s\n",
			      rd_th_name(),
			      new_target->auth_target ? " auth" : "",
			      req->target_name, config->redirector_name);
		/* Add target to target table */
		vbdev_redirector_register_target(new_target->name, bdev);
	}

	return ret;
}

int
redirector_target_set_nqn(struct redirector_config *config,
			  struct redirector_target *target,
			  char *nqn_buf, size_t nqn_len)
{
	struct redirector_target_by_nqn_data_compare_opts l_opts = {
		.compare_priority = true,
		.compare_addresses = true
	};
	assert(config);
	assert(target);

	if (target->nqn) {
		SPDK_ERRLOG("Redirector %s target %s already has nqn\n",
			    config->redirector_name, target->name);
		return -EINVAL;
	}
	target->nqn = strndup(nqn_buf, nqn_len);
	g_sequence_insert_sorted(config->targets_by_nqn, (gpointer)target,
				 redirector_target_by_nqn_data_compare_fn, &l_opts);
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s target %s nqn set to %s\n",
		      config->redirector_name, target->name, target->nqn);
	/* Target index of hints that refer to this NQN will be updated in vbdev_redirector_update_locations() */
	return 0;
}

struct redirector_remove_target_ctx {
	struct redirector_config *config;
	char *target_name;
	bool retain_hints;
	bool remain_configured;
	bool hotremove;
	vbdev_redirector_remove_target_cb usr_cb_fn;
	void *usr_cb_ctx;
};

static void
free_redirector_remove_target_ctx(struct redirector_remove_target_ctx *ctx)
{
	free(ctx->target_name);
	free(ctx);
}

static void
redirector_remove_target_cpl(void *cb_ctx, int rc)
{
	struct redirector_remove_target_ctx *ctx = cb_ctx;
	int ret = rc;
	struct redirector_target *target;
	struct redirector_bdev *rd_node = ctx->config->redirector_bdev;

	if (ret) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Removal of target %s on redirector %s failed during channel update (%d)\n",
			      ctx->target_name, ctx->config->redirector_name, ret);
		goto completion;
	}

	if (!rd_node) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Removal of target %s on redirector %s failed: redirector is not open\n",
			      ctx->target_name, ctx->config->redirector_name);
		ret = -ENODEV;
		goto completion;
	}

	target = redirector_config_find_target(ctx->config, ctx->target_name);
	if (!target) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Removal of target %s on redirector %s failed: target no longer present\n",
			      ctx->target_name, ctx->config->redirector_name);
		ret = -EINVAL;
		goto completion;
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s] Finishing removal of target %s on redirector %s\n",
		      rd_th_name(), ctx->target_name, ctx->config->redirector_name);

	/* Remove target bdev bdev from bdev/channel target table */
	redirector_unassign_target_index(rd_node, target);

	if (ctx->remain_configured) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] Retaining configuration of %sremoved target %s on redirector %s\n",
			      rd_th_name(), ctx->hotremove ? "hot-" : "",
			      ctx->target_name, ctx->config->redirector_name);
		target->removing = false;
		target->hotremove = false;
		target->registered = target_index_sticky(target);
		target->bdev = NULL;
	} else {
		assert(target_index_unassigned(target));
		ret = redirector_config_remove_target(ctx->config, ctx->target_name);
		if (ret) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Removal of target %s on redirector %s failed during config removal (%d)\n",
				      ctx->target_name, ctx->config->redirector_name, ret);
		}
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s] Finished removal of target %s on redirector %s\n",
		      rd_th_name(), ctx->target_name, ctx->config->redirector_name);

completion:
	if (ctx->usr_cb_fn) {
		ctx->usr_cb_fn(ctx->usr_cb_ctx, ret);
	}
	free_redirector_remove_target_ctx(ctx);
}

/*
 * Hotplug path calls this with remain_configured true, to leave the
 * target in the configuration, and re-register it if it reappears.
 *
 * The JSON-RPC path calls this with remain_configured false, because
 * the intent there is to stop using this target whether it's working
 * or not. Remove fails if authoritative hints name the target (TODO)
 *
 * If authoritative hints name a hot-removed target, the redirector
 * should queue IOs to that target for a while, then fail them if the
 * target doesn't return or the rule table doesn't specify another
 * destination in a reasonable amount of time.
 */
void
redirector_remove_target(struct redirector_config *config,
			 const char *target_name,
			 const bool retain_hints,
			 const bool remain_configured,
			 const bool hotremove,
			 const vbdev_redirector_remove_target_cb cb_fn,
			 void *cb_ctx)
{
	struct redirector_remove_target_ctx *ctx;
	struct redirector_target *target;
	int ret;

	ret = redirector_config_set_target_removing(config, target_name, hotremove, !remain_configured);
	if (ret) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "%sRemoval of target %s on redirector %s failed: %d\n",
			      hotremove ? "HOT " : "", target_name, config->redirector_name, ret);
		if (cb_fn) {
			cb_fn(cb_ctx, ret);
		}
		return;
	}
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "[%s] Started removal of target %s on redirector %s\n",
		      rd_th_name(), target_name, config->redirector_name);

	target = redirector_config_find_target(config, target_name);

	if (!retain_hints) {
		redirector_config_remove_hints_to_target(config, target_name);

		/* If we know the NQN of the target being removed, remove hints to that NQN */
		if (target && target->nqn) {
			redirector_config_remove_hints_to_target(config, target->nqn);
		}
	}

	if (!remain_configured) {
		redirector_config_remove_hints_from_target(config, target_name);

		/* If we know the NQN of the target being removed, remove hints from that NQN */
		if (target && target->nqn) {
			redirector_config_remove_hints_from_target(config, target->nqn);
		}
	}

	if (config->redirector_bdev) {
		ctx = calloc(1, sizeof(*ctx));
		if (!ctx) {
			ret = -ENOMEM;
			if (cb_fn) {
				cb_fn(cb_ctx, ret);
			}
			return;
		}

		ctx->config = config;
		ctx->target_name = strdup(target_name);
		ctx->retain_hints = retain_hints;
		ctx->remain_configured = remain_configured;
		ctx->hotremove = hotremove;
		ctx->usr_cb_fn = cb_fn;
		ctx->usr_cb_ctx = cb_ctx;

		if (hotremove) {
			config->redirector_bdev->stats.hot_removes++;
		}

		/* Update rule table now that no rules will refer to the removing target */
		vbdev_redirector_update_locations(config->redirector_bdev);

		/* update target and rule tables in channels */
		config->redirector_bdev->target_update_pending = true;
		vbdev_redirector_update_channel_state(config->redirector_bdev,
						      redirector_remove_target_cpl, ctx);
	} else {
		if (!remain_configured) {
			ret = redirector_config_remove_target(config, target_name);
		}
		if (cb_fn) {
			cb_fn(cb_ctx, ret);
		}
	}
	return;
}

struct redirector_target *
vbdev_redirector_default_target(struct redirector_config *config)
{
	GSequenceIter *target_iter;
	struct redirector_target *iter_target = NULL;
	struct redirector_target *default_target = NULL;

	/* Find first target in config that is a redirector, has a bdev, has a
	 * target index, has the same NS UUID as this redirector, and isn't
	 * being removed. Make that the default rule. */
	target_iter = g_sequence_get_begin_iter(config->targets);
	while (!g_sequence_iter_is_end(target_iter)) {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		/* Default must be redirector ... */
		if (iter_target->redirector &&
		    /* ... and either have a bdev ... */
		    (iter_target->bdev ||
		     /* ... or have an index assigned anyway ... */
		     !target_index_unassigned(iter_target) ||
		     /* ... or be a target that never has its index unassigned ... */
		     target_index_sticky(iter_target)) &&
		    /* ... and either not have a bdev ... */
		    (!iter_target->bdev ||
		     /* ... or the redirector has no UUID ... */
		     !rd_uuid_known(config) ||
		     /* ... or the target is not confirmed to be a redirector ... */
		     !iter_target->confirmed_redir ||
		     /* ... or the target is confirmed to be a redirector but has no UUID ... */
		     (iter_target->confirmed_redir && !rd_target_uuid_known(iter_target)) ||
		     /* ... or the target and redirector UUIDs match ... */
		     target_ns_uuid_matches_rd(config, iter_target)) &&
		    /* ... and not be in the process of being removed */
		    !iter_target->removing) {
			if (iter_target->bdev || (default_target == NULL)) {
				default_target = iter_target;
				if (iter_target->bdev) {
					break;
				}
			}
		}
		target_iter = g_sequence_iter_next(target_iter);
	}
	return default_target;
}


