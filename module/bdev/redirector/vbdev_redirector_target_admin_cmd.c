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
 * Functions for sending NVMe admin commands to the redirector
 * targets.
 *
 * Includes a self-ref mechanism on the redirector bdev to ensure it
 * isn't hotplugged before all the command completion functions run.
 *
 * Provides a mechanism for scheduling work when the number of
 * in-flight targt admin commands reachs zero.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_target_admin_cmd.h"
#include "vbdev_redirector.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

/*
 * Call this cb_fn(cb_ctx) immediately, or when the number of in flight target admin commands
 * reaches zero.
 *
 * This does not guarantee the number of in flight target admin commands will still be zero
 * when cb_fn(cb_ctx) is called, only that it was or became zero at some point after this
 * function was called. Callbacks that require there to be zero in flight target admin commands
 * will have to tst for that themselves, and reschedule themselves if they find any.
 */
void
redirector_schedule_tgt_adm_cmd_in_flight_cpl(struct redirector_bdev *rd_node,
		redirector_completion_cb cb_fn, void *cb_ctx)
{
	assert(rd_node->tgt_adm_cmd_in_flight >= 0);
	if (cb_fn == NULL) {
		return;
	}
	if (rd_node->tgt_adm_cmd_in_flight == 0) {
		cb_fn(cb_ctx, 0);
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] Redirector %s deferring completion %p for %d in-flight admin commands\n",
			      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name, cb_ctx,
			      rd_node->tgt_adm_cmd_in_flight);
		redirector_schedule_completion(&rd_node->tgt_adm_cmd_cpl, cb_fn, cb_ctx);
	}
}

static void
redirector_tgt_adm_cmd_in_flight_cpl(struct redirector_bdev *rd_node)
{
	GSList *completions = NULL;

	assert(rd_node->tgt_adm_cmd_in_flight > 0);
	if (--rd_node->tgt_adm_cmd_in_flight == 0) {
		/* Completions waiting for all target admin commands (IDENTIFY, etc.) to complete */
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s all target admin commands completed\n",
			      rd_node->config->redirector_name);
		completions = rd_node->tgt_adm_cmd_cpl;
		rd_node->tgt_adm_cmd_cpl = NULL;
		redirector_call_completions(&completions, 0);
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s %d target admin commands remain in flight\n",
			      rd_node->config->redirector_name, rd_node->tgt_adm_cmd_in_flight);
	}
}

void
free_redirector_admin_cmd_ctx(struct redirector_admin_cmd_ctx *ctx)
{
	struct redirector_bdev *rd_node;

	if (!ctx) { return; }
	rd_node = ctx->rd_node;
	if (ctx->ch) {
		spdk_put_io_channel(ctx->ch);
	}
	redirector_tgt_adm_cmd_in_flight_cpl(ctx->rd_node);
	if (ctx->self_desc) {
		spdk_bdev_close(ctx->self_desc);
		rd_node->num_self_ref--;
		if (RD_DEBUG_LOG_BDEV_SELF_REF) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s (%p)] Redirector %s num_self_ref=%d\n",
				      rd_th_name(), spdk_get_thread(),
				      rd_node->config->redirector_name, rd_node->num_self_ref);
		}

	}
	spdk_free(ctx->data);
	free(ctx);
}

int
vbdev_redirector_send_admin_cmd(struct redirector_bdev *rd_node,
				size_t target_bdev_index,
				struct spdk_nvme_cmd *cmd,
				spdk_bdev_io_completion_cb cb,
				void *cb_ctx)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[target_bdev_index];
	struct redirector_admin_cmd_ctx *ctx;
	int rc;

	assert(rd_target->target_config);
	assert(rd_target->desc);
	if (!spdk_bdev_io_type_supported(rd_target->bdev, SPDK_BDEV_IO_TYPE_NVME_ADMIN)) {
		return 0;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return -ENOMEM;
	}
	ctx->data = rd_alloc_nvme_admin_cmd_ctx_data();
	if (!ctx->data) {
		free(ctx);
		return -ENOMEM;
	}
	ctx->rd_node = rd_node;
	ctx->target_bdev_index = target_bdev_index;
	ctx->ch = spdk_bdev_get_io_channel(rd_target->desc);
	ctx->cb_ctx = cb_ctx;
	/* Reduce later in redirector_tgt_adm_cmd_in_flight_cpl() */
	assert(rd_node->tgt_adm_cmd_in_flight >= 0);
	rd_node->tgt_adm_cmd_in_flight++;
	if (rd_node->registered) {
		/* Hold a desc on this bdev during this async operation */
		rc = spdk_bdev_open(&rd_node->redirector_bdev, false, NULL, NULL, &ctx->self_desc);
		if (rc) {
			SPDK_ERRLOG("Redirector %s failed to open self R/O\n",
				    rd_node->config->redirector_name);
			goto fail;
		}
		rd_node->num_self_ref++;
		if (RD_DEBUG_LOG_BDEV_SELF_REF) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s (%p)] Redirector %s num_self_ref=%d\n",
				      rd_th_name(), spdk_get_thread(),
				      rd_node->config->redirector_name, rd_node->num_self_ref);
		}
	}
	rc = spdk_bdev_nvme_admin_passthru(rd_target->desc, ctx->ch, cmd,
					   ctx->data, sizeof(*(ctx->data)), cb, ctx);

fail:
	if (rc) {
		free_redirector_admin_cmd_ctx(ctx);
	}

	return rc;
}
