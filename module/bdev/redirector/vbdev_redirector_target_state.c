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
 * The state of the targets connected to this redirector is maintained
 * here. This includes the initial attempt to open newly configured
 * targets, and examining newly created bdevs to see if they're one of
 * the configured targets.
 *
 * Manages the assignment of target indexes to connected targets, and
 * the state necessary to deploy the array of target states to the
 * redirector data plane (channels).
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector_target_state.h"
#include "vbdev_redirector_target_admin_cmd.h"
#include "vbdev_redirector_channel.h"
#include "vbdev_redirector_hint_learning.h"
#include "vbdev_redirector.h"
#include "spdk/bdev.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

static int g_normal_target_qd = REDIRECTOR_NORMAL_TARGET_QD;

/* Called when the underlying target bdev goes away. */
void
vbdev_redirector_target_bdev_hotremove_cb(void *ctx)
{
	struct redirector_bdev *rd_node, *tmp;
	struct spdk_bdev *hotremove_bdev = ctx;
	size_t target_bdev_index;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "[%s (%p)] start\n", rd_th_name(), spdk_get_thread());
	TAILQ_FOREACH_SAFE(rd_node, &g_redirector_bdevs, bdev_link, tmp) {
		for (target_bdev_index = 0;
		     target_bdev_index < rd_node->num_rd_targets;
		     target_bdev_index++) {
			if (hotremove_bdev == rd_node->targets[target_bdev_index].bdev) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "[%s (%p)] redirector %s target %s\n",
					      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name,
					      spdk_bdev_get_name(hotremove_bdev));
				redirector_remove_target(rd_node->config,
							 spdk_bdev_get_name(hotremove_bdev),
							 true, true, true, NULL, NULL);
			}
		}
	}
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "[%s (%p)] done\n", rd_th_name(), spdk_get_thread());
}

static void
vbdev_redirector_identify_target_ns_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct redirector_admin_cmd_ctx *ctx = cb_arg;
	struct spdk_nvme_cmd *identify_target_ns_ctx = ctx->cb_ctx;
	struct redirector_bdev_target *rd_target = &ctx->rd_node->targets[ctx->target_bdev_index];
	struct spdk_nvme_ns_id_desc *id_desc = (void *)ctx->data;

	uint32_t resp_cdw0;
	int resp_sct;
	int resp_sc;
	bool nvme_success;
	bool id_success;

	spdk_bdev_io_get_nvme_status(bdev_io, &resp_cdw0, &resp_sct, &resp_sc);
	nvme_success = (resp_sct == SPDK_NVME_SCT_GENERIC) && (resp_sc == SPDK_NVME_SC_SUCCESS);
	id_success = success && nvme_success;

	if (!success || id_success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %s namespace of target %s\n",
			      ctx->rd_node->config->redirector_name,
			      success ? "identified" : "FAILED to identify",
			      spdk_bdev_get_name(rd_target->bdev));
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %s namespace of target %s: %s, %s (%0xd)\n",
			      ctx->rd_node->config->redirector_name,
			      "FAILED to identify",
			      spdk_bdev_get_name(rd_target->bdev),
			      get_spdk_nvme_status_code_type_name(resp_sct),
			      get_spdk_nvme_command_status_code_name(resp_sct, resp_sc),
			      resp_sc);
	}

	if (!id_success) {
		goto fail;
	}

	while (id_desc->nidl) {
		switch (id_desc->nidt) {
		case SPDK_NVME_NIDT_EUI64:
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s ignoring EUI64 for target %s\n",
				      ctx->rd_node->config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
			break;
		case SPDK_NVME_NIDT_NGUID:
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s ignoring NGUID for target %s\n",
				      ctx->rd_node->config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
			break;
		case SPDK_NVME_NIDT_UUID: {
			char uuid_str[SPDK_UUID_STRING_LEN];
			int rc = spdk_uuid_fmt_lower(uuid_str, sizeof(uuid_str),
						     (struct spdk_uuid *)&id_desc->nid);
			assert(rc == 0);
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s UUID %s for target %s\n",
				      ctx->rd_node->config->redirector_name, uuid_str,
				      spdk_bdev_get_name(rd_target->bdev));
			if (uuid_not_zero((struct spdk_uuid *)&id_desc->nid)) {
				/* We'll set this targets UUID to what came
				 * back, but warn if it seems to be changing */
				if (rd_target_uuid_known(rd_target->target_config) &&
				    !uuids_match((struct spdk_uuid *)&id_desc->nid,
						 &rd_target->target_config->uuid)) {
					char old_uuid_str[SPDK_UUID_STRING_LEN];
					int rc = spdk_uuid_fmt_lower(old_uuid_str, sizeof(old_uuid_str),
								     &rd_target->target_config->uuid);
					assert(rc == 0);
					SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
						      "Redirector %s UUID of target %s changed from %s to %s\n",
						      ctx->rd_node->config->redirector_name,
						      spdk_bdev_get_name(rd_target->bdev),
						      old_uuid_str, uuid_str);
				}
				spdk_uuid_copy(&rd_target->target_config->uuid, (struct spdk_uuid *)&id_desc->nid);
				/* Warn if this redirector has a UUID, and this target has a different one.
				 * We won't be able to forward IO for this NS to this target unless a location
				 * hint points to this namespace UUID */
				if (rd_uuid_known(ctx->rd_node->config)) {
					rd_target->target_config->uuid_mismatch =
						!target_ns_uuid_matches_rd(ctx->rd_node->config,
									   rd_target->target_config);
					if (rd_target->target_config->uuid_mismatch) {
						SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
							      "Redirector %s UUID differs from UUID of target %s\n",
							      ctx->rd_node->config->redirector_name,
							      spdk_bdev_get_name(rd_target->bdev));
					}
				}
			}
		}
		break;
		default:
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s unknown ID type %d for target %s\n",
				      ctx->rd_node->config->redirector_name, (int)id_desc->nidt,
				      spdk_bdev_get_name(rd_target->bdev));
			break;
		}
		id_desc = (void *)id_desc + sizeof(*id_desc) + id_desc->nidl;
	}

fail:
	assert(identify_target_ns_ctx);
	spdk_free(identify_target_ns_ctx);
	spdk_bdev_free_io(bdev_io);
	free_redirector_admin_cmd_ctx(ctx);
}

static int
vbdev_redirector_identify_target_ns(struct redirector_bdev *rd_node, size_t target_bdev_index)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[target_bdev_index];
	struct spdk_nvme_cmd *cmd;
	int rc;
	uint32_t transfer;
	uint32_t num_dwords;

	transfer = sizeof(((struct redirector_admin_cmd_ctx *)NULL)->data);
	cmd = rd_alloc_nvme_cmd();
	if (!cmd) {
		return -ENOMEM;
	}
	num_dwords = (transfer >> 2) - 1;
	cmd->opc = SPDK_NVME_OPC_IDENTIFY;
	/* cmd.nsid will be supplied from the nvme bdev */
	cmd->cdw10 = ((num_dwords & 0xFFFFu) << 16) + SPDK_NVME_IDENTIFY_NS_ID_DESCRIPTOR_LIST;
	cmd->cdw11 = (num_dwords >> 16) & 0xFFFFu;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s identifying namespace of target %s\n",
		      rd_node->config->redirector_name,
		      spdk_bdev_get_name(rd_target->bdev));

	rc = vbdev_redirector_send_admin_cmd(rd_node, target_bdev_index, cmd,
					     vbdev_redirector_identify_target_ns_cb, cmd);
	if (rc) {
		spdk_free(cmd);
	}

	return rc;
}

static void strntrim(char *s, size_t maxlen)
{
	size_t len = strnlen(s, maxlen);

	while (len > 0 && isspace(s[len - 1])) {
		s[len - 1] = '\0';
		len--;
	}
}

static void
vbdev_redirector_identify_target_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct redirector_admin_cmd_ctx *ctx = cb_arg;
	struct spdk_nvme_cmd *identify_target_ctx = ctx->cb_ctx;
	struct redirector_bdev_target *rd_target = &ctx->rd_node->targets[ctx->target_bdev_index];
	struct redirector_target *target = rd_target->target_config;
	struct spdk_nvme_ctrlr_data *ctrlr = (void *)ctx->data;
	uint32_t resp_cdw0;
	int resp_sct;
	int resp_sc;
	bool nvme_success;
	bool id_success;

	spdk_bdev_io_get_nvme_status(bdev_io, &resp_cdw0, &resp_sct, &resp_sc);
	nvme_success = (resp_sct == SPDK_NVME_SCT_GENERIC) && (resp_sc == SPDK_NVME_SC_SUCCESS);
	id_success = success && nvme_success;

	if (!success || id_success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %s target %s\n",
			      ctx->rd_node->config->redirector_name,
			      id_success ? "identified" : "FAILED to identify",
			      spdk_bdev_get_name(rd_target->bdev));
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %s target %s: %s, %s (%0xd)\n",
			      ctx->rd_node->config->redirector_name,
			      "FAILED to identify",
			      spdk_bdev_get_name(rd_target->bdev),
			      get_spdk_nvme_status_code_type_name(resp_sct),
			      get_spdk_nvme_command_status_code_name(resp_sct, resp_sc),
			      resp_sc);
	}

	if (!id_success) {
		goto fail;
	}

	strntrim(ctrlr->mn, SPDK_NVME_CTRLR_MN_LEN);
	strntrim(ctrlr->sn, SPDK_NVME_CTRLR_SN_LEN);
	strntrim(ctrlr->fr, SPDK_NVME_CTRLR_FR_LEN);

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s target %s nqn=%.*s mn=%.*s sn=%.*s fr=%.*s\n",
		      ctx->rd_node->config->redirector_name, spdk_bdev_get_name(rd_target->bdev),
		      (int)strnlen(ctrlr->subnqn, sizeof(ctrlr->subnqn)), ctrlr->subnqn,
		      (int)strnlen(ctrlr->mn, SPDK_NVME_CTRLR_MN_LEN), ctrlr->mn,
		      (int)strnlen(ctrlr->sn, SPDK_NVME_CTRLR_SN_LEN), ctrlr->sn,
		      (int)strnlen(ctrlr->fr, SPDK_NVME_CTRLR_FR_LEN), ctrlr->fr);

	memcpy(&rd_target->target_config->ctrlr_data, ctrlr, sizeof(rd_target->target_config->ctrlr_data));

	if (strnlen(ctrlr->subnqn, sizeof(ctrlr->subnqn))) {
		if (target) {
			if (!target->nqn) {
				redirector_target_set_nqn(ctx->rd_node->config, target,
							  ctrlr->subnqn, sizeof(ctrlr->subnqn));
			} else if (strncmp(target->nqn, ctrlr->subnqn, sizeof(ctrlr->subnqn))) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s target %s nqn changed from %s to %.*s\n",
					      ctx->rd_node->config->redirector_name, spdk_bdev_get_name(rd_target->bdev),
					      target->nqn,
					      (int)strnlen(ctrlr->subnqn, sizeof(ctrlr->subnqn)), ctrlr->subnqn);
			}
		}
	}

fail:
	assert(identify_target_ctx);
	spdk_free(identify_target_ctx);
	spdk_bdev_free_io(bdev_io);
	free_redirector_admin_cmd_ctx(ctx);
}

static int
vbdev_redirector_identify_target(struct redirector_bdev *rd_node, size_t target_bdev_index)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[target_bdev_index];
	struct spdk_nvme_cmd *cmd;
	int rc;
	uint32_t transfer;
	uint32_t num_dwords;

	transfer = sizeof(((struct redirector_admin_cmd_ctx *)NULL)->data);
	cmd = rd_alloc_nvme_cmd();
	if (!cmd) {
		return -ENOMEM;
	}
	num_dwords = (transfer >> 2) - 1;
	cmd->opc = SPDK_NVME_OPC_IDENTIFY;
	/* cmd->nsid will be supplied from the nvme bdev */
	cmd->cdw10 = ((num_dwords & 0xFFFFu) << 16) + SPDK_NVME_IDENTIFY_CTRLR;
	cmd->cdw11 = (num_dwords >> 16) & 0xFFFFu;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s identifying controller of target %s\n",
		      rd_node->config->redirector_name,
		      spdk_bdev_get_name(rd_target->bdev));

	rc = vbdev_redirector_send_admin_cmd(rd_node, target_bdev_index, cmd,
					     vbdev_redirector_identify_target_cb, cmd);
	if (rc) {
		spdk_free(cmd);
	}

	return rc;
}

/*
 * Open/claim the specified target index, and begin the target ID process (a series of
 * admin commands).
 */
static int
vbdev_redirector_open_target(struct redirector_bdev *rd_node, size_t target_bdev_index)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[target_bdev_index];
	int rc = 0;

	rd_target->target_config->hint_stats.generation = 0;
	rc = spdk_bdev_open(rd_target->bdev,
			    true, vbdev_redirector_target_bdev_hotremove_cb,
			    rd_target->bdev, &rd_target->desc);
	if (rc) {
		SPDK_ERRLOG("could not open bdev %s\n",
			    spdk_bdev_get_name(rd_target->bdev));
		return rc;
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s opened target %s\n",
		      rd_node->config->redirector_name,
		      spdk_bdev_get_name(rd_target->bdev));

	rc = spdk_bdev_module_claim_bdev(rd_target->bdev, rd_target->desc,
					 rd_node->redirector_bdev.module);
	if (rc) {
		SPDK_ERRLOG("could not claim bdev %s\n",
			    spdk_bdev_get_name(rd_target->bdev));
		spdk_bdev_close(rd_target->desc);
		rd_target->desc = NULL;
		return rc;
	}

	if (!rd_target->target_config->dont_probe) {
		rc = vbdev_redirector_identify_target(rd_node, target_bdev_index);
		if (rc) {
			SPDK_ERRLOG("could not identify target bdev %s\n",
				    spdk_bdev_get_name(rd_target->bdev));
			spdk_bdev_close(rd_target->desc);
			rd_target->desc = NULL;
			return rc;
		}

		rc = vbdev_redirector_identify_target_ns(rd_node, target_bdev_index);
		if (rc) {
			SPDK_ERRLOG("could not identify target bdev %s namespace\n",
				    spdk_bdev_get_name(rd_target->bdev));
			spdk_bdev_close(rd_target->desc);
			rd_target->desc = NULL;
			return rc;
		}

		rc = vbdev_redirector_get_hints(rd_node, target_bdev_index);
		if (rc) {
			SPDK_ERRLOG("could not read hints from target bdev %s\n",
				    spdk_bdev_get_name(rd_target->bdev));
			spdk_bdev_close(rd_target->desc);
			rd_target->desc = NULL;
			return rc;
		}
	}

	return rc;
}

static size_t
vbdev_redirector_alloc_target_index(struct redirector_bdev *rd_node)
{
	size_t target_bdev_index;

	for (target_bdev_index = 0;
	     target_bdev_index < rd_node->num_rd_targets;
	     target_bdev_index++) {
		if (rd_node->targets[target_bdev_index].free_index) {
			rd_node->targets[target_bdev_index].free_index = false;
			return target_bdev_index;
		}
	}
	assert(rd_node->num_rd_targets <= REDIRECTOR_MAX_TARGET_BDEVS);
	target_bdev_index = rd_node->num_rd_targets++;
	bzero(&rd_node->targets[target_bdev_index], sizeof(rd_node->targets[target_bdev_index]));
	return target_bdev_index;
}

static int
redirector_open_target_bdev(struct redirector_bdev *rd_node,
			    struct redirector_target *target)
{
	int rc;

	assert(!target_index_unassigned(target));
	rc = vbdev_redirector_open_target(rd_node, target->target_index);
	if (rc) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s target %s status %d\n",
			      rd_node->config->redirector_name, target->name, rc);
		if (!target_index_sticky(target)) {
			target->target_index = -1;
			rd_node->targets[target->target_index].target_config = NULL;
		}
		rd_node->targets[target->target_index].bdev = NULL;
	} else {
		/* Successful open, allow >0 QD */
		rd_node->targets[target->target_index].max_qd = g_normal_target_qd;
	}

	return rc;
}

/*
 * Ensures this target has a target index. This may make it immediately usable in
 * the data path. This also begins the target identification process, which confirms
 * the target is a redirector (or not). Peer redirectors may not be usable until this
 * ID process completes.
 *
 * Target ID includes reading and applying location hints from targts that are redirectors.
 * That may require several RTTs to complete if there are a lot.
 *
 * Target ID and hint polling will probably not complete before this function returns.
 * Things that must wait until all target ID activity completes can schedule themselves
 * via redirector_schedule_tgt_adm_cmd_in_flight_cpl(). That relies on target identification
 * maintaining at last one in-flight target admin command until targe ID completes.
 */
int
redirector_assign_target_index(struct redirector_bdev *rd_node,
			       struct redirector_target *target)
{
	int rc;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "[%s] Redirector %s target %s%s\n",
		      rd_th_name(), rd_node->config->redirector_name, target->name,
		      target->auth_target ? " [AUTH]" : "");

	if (target_index_unassigned(target)) {
		size_t assigned_index;

		assigned_index = vbdev_redirector_alloc_target_index(rd_node);
		target->target_index = assigned_index;
		rd_node->targets[assigned_index].target_config = target;
		rd_node->targets[assigned_index].desc = NULL;
		rd_node->targets[assigned_index].bdev = target->bdev;
	} else {
		/* Auth target assignments are sticky, so we're just opening or re-opening this target
		 * which already had an index assigned. */
		assert(target_index_sticky(target));
		assert(rd_node->targets[target->target_index].target_config == target);
		if (!target->bdev) {
			assert(rd_node->targets[target->target_index].desc == NULL);
			assert(rd_node->targets[target->target_index].bdev == NULL);
		} else {
			assert(!rd_node->targets[target->target_index].bdev);
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s auth target %s index %d bdev has appeared\n",
				      rd_node->config->redirector_name, target->name, target->target_index);
			assert(rd_node->targets[target->target_index].desc == NULL);
			rd_node->targets[target->target_index].bdev = target->bdev;
		}
	}
	rd_node->targets[target->target_index].max_qd = 0; /* Queue IO until target opened */
	rd_node->targets[target->target_index].drain = false;
	if (rd_node->targets[target->target_index].bdev) {
		rc = redirector_open_target_bdev(rd_node, target);
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s target %s index %d NULL bdev, QD0\n",
			      rd_node->config->redirector_name, target->name, target->target_index);
		rc = 0;
	}

	return rc;
}

static void
vbdev_redirector_register_target_finish(void *ctx, int rc)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s (%p)] Target registration on redirector %s completed with status %d\n",
		      rd_th_name(), spdk_get_thread(),
		      rd_node->config->redirector_name, rc);
}

static void
vbdev_redirector_register_target_continue(void *ctx, int status)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s (%p)] Redirector %s target identification complete\n",
		      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name);

	/* Update rule table now that target identification has completed. There may be hints that
	 * match this target by its NGUID or EUI64 which wasn't known until now. */
	vbdev_redirector_update_locations(rd_node);
	rd_node->target_update_pending = true;
	/* Update target and rule tables in channels */
	vbdev_redirector_update_channel_state(rd_node, vbdev_redirector_register_target_finish, rd_node);
}

/*
 * If this bdev matches a target of any configured redirector, link
 * this bdev to that target. Once all the required targets for a
 * redirector are found, bring up the redirector.
 */
int
vbdev_redirector_register_target(const char *target_name, struct spdk_bdev *bdev)
{
	struct redirector_config *config;
	struct redirector_target *matched_target;
	int rc = 0;

	/* Check every configured redirector */
	TAILQ_FOREACH(config, &g_redirector_config, config_link) {
		assert(config != config->config_link.tqe_next);
		matched_target = redirector_config_find_target(config, target_name);

		/* Didn't match any of the redirector's target bdevs */
		if (!matched_target) {
			continue;
		}

		if (matched_target->registered) {
			if (matched_target->bdev) {
				SPDK_ERRLOG("bdev %s already registered to redirector %s\n",
					    target_name, config->redirector_name);
				return (-EINVAL);
			} else if (bdev) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "[%s] Auth target %s of redirector %s has registered\n",
					      rd_th_name(),
					      target_name, config->redirector_name);
			}
		} else {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s] Target %s of redirector %s %s\n",
				      rd_th_name(),
				      target_name, config->redirector_name,
				      bdev ? "has registered" : "pre-registered");
		}
		matched_target->bdev = bdev;

		if (!config->redirector_bdev) {
			matched_target->registered = true;
			/* Create redirector now if possible */
			rc = vbdev_redirector_register(config);
			if (rc) {
				return (rc);
			}
		} else {
			/* Adding target to a running redirector */
			if (matched_target->registered && bdev) {
				/* The (auth) target is already registered, but the bdev wasn't known until now */
			} else {
				/* Target bdev may still be NULL if this is an auth target */
				matched_target->registered = true;
			}
			rc = redirector_assign_target_index(config->redirector_bdev, matched_target);
			if (rc) {
				SPDK_ERRLOG("could not open target %s\n", spdk_bdev_get_name(bdev));
				return (rc);
			}
			config->redirector_bdev->target_update_pending = true;
			/* Update target and rule tables in channels now that this index is assigned */
			vbdev_redirector_update_locations(config->redirector_bdev);
			vbdev_redirector_update_channel_state(config->redirector_bdev, NULL, NULL);
			/* Continue target add once all the in-flight target admin commands complete */
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s (%p)] Redirector %s waiting for target identification completion\n",
				      rd_th_name(), spdk_get_thread(), config->redirector_bdev->config->redirector_name);
			redirector_schedule_tgt_adm_cmd_in_flight_cpl(config->redirector_bdev,
					vbdev_redirector_register_target_continue,
					config->redirector_bdev);
		}
	}

	return rc;
}
