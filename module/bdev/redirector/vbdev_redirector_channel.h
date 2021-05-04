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

#ifndef SPDK_VBDEV_REDIRECTOR_CHANNEL_H
#define SPDK_VBDEV_REDIRECTOR_CHANNEL_H

#include "spdk/likely.h"
#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_targets.h"
#include "spdk_internal/log.h"

struct spdk_io_channel *vbdev_redirector_get_io_channel(void *ctx);

int redirector_bdev_ch_create_cb(void *io_device, void *ctx_buf);

void redirector_bdev_ch_destroy_cb(void *io_device, void *ctx_buf);

void
vbdev_redirector_update_channel_state_sync(struct redirector_bdev *rd_node);

static inline void
_ch_target_mark_drained(struct redirector_bdev_io_channel *rd_ch,
			struct redirector_bdev_io_channel_target *rd_ch_target)
{
	if (rd_ch_target->draining) {
		rd_ch_target->draining = false;
		rd_ch_target->drained = true;
		assert(rd_ch->num_draining);
		assert(rd_ch->num_draining <= REDIRECTOR_MAX_TARGET_BDEVS);
		rd_ch->num_draining--;
	}
}

/* Continue any in-progress state update if there was one waiting for this channel to drain */
static inline void
_ch_state_update_continue_if_drained(struct redirector_bdev *rd_node,
				     struct redirector_bdev_io_channel *rd_ch)
{
	struct spdk_io_channel_iter *state_update_iter = rd_ch->state_update_iter;

	if (state_update_iter && rd_ch->num_draining == 0) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] Target draining completed for redirector %s rd_ch %p. "
			      "Continuing to next channel.\n",
			      rd_th_name(), rd_node->config->redirector_name, rd_ch);
		rd_ch->state_update_iter = NULL;
		spdk_for_each_channel_continue(state_update_iter, 0);
	}
}

static inline void _ch_state_target_drain(struct redirector_bdev *rd_node,
		struct redirector_bdev_io_channel *rd_ch,
		size_t ch_target_index)
{
	if ((rd_ch->targets[ch_target_index].ios_in_flight == 0) &&
	    TAILQ_EMPTY(&rd_ch->targets[ch_target_index].queued_io_tailq)) {
		if (rd_ch->targets[ch_target_index].ch) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s (%p)] Redirector %s (rd_ch %p) releasing drained ch %p for target %s (index %zu).\n",
				      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name, rd_ch,
				      rd_ch->targets[ch_target_index].ch,
				      spdk_bdev_get_name(rd_node->targets[ch_target_index].bdev), ch_target_index);
			spdk_put_io_channel(rd_ch->targets[ch_target_index].ch);
			rd_ch->targets[ch_target_index].ch = NULL;
			rd_ch->targets[ch_target_index].max_qd = 0;
		} else {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s (%p)] Redirector %s (rd_ch %p) finished draining unconnected target %s (index %zu).\n",
				      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name, rd_ch,
				      rd_node->targets[ch_target_index].target_config->name, ch_target_index);
			assert(target_index_sticky(rd_node->targets[ch_target_index].target_config));
		}
		_ch_target_mark_drained(rd_ch, &rd_ch->targets[ch_target_index]);
		_ch_state_update_continue_if_drained(rd_node, rd_ch);
	}
}

/* Submit queued IO for a channel target up to max QD if there is any */
static inline void _ch_target_submit_queued_io(struct spdk_io_channel *ch,
		const size_t target_index)
{
	struct redirector_bdev_io_channel   *rd_ch = spdk_io_channel_get_ctx(ch);
	struct spdk_bdev_io		    *dequeued_io;
	struct redirector_bdev_io	    *dequeued_io_ctx;

	while ((rd_ch->targets[target_index].ios_in_flight <
		rd_ch->targets[target_index].max_qd) &&
	       !TAILQ_EMPTY(&rd_ch->targets[target_index].queued_io_tailq)) {
		dequeued_io = TAILQ_FIRST(&rd_ch->targets[target_index].queued_io_tailq);
		dequeued_io_ctx = (struct redirector_bdev_io *)dequeued_io->driver_ctx;
		assert(dequeued_io_ctx->is_queued);
		assert(dequeued_io_ctx->was_queued);
		if (RD_DEBUG_LOG_CHANNEL_STUFF) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "dequeued_io=%p ios_queued=%d queued_io_count=%"PRIu64"\n",
				      dequeued_io, rd_ch->targets[target_index].ios_queued,
				      rd_ch->targets[target_index].queued_io_count);
		}
		TAILQ_REMOVE(&rd_ch->targets[target_index].queued_io_tailq, dequeued_io, module_link);
		assert(rd_ch->targets[target_index].ios_queued > 0);
		rd_ch->targets[target_index].ios_queued--;
		vbdev_redirector_resubmit_request(ch, dequeued_io);
	}
}

#endif /* SPDK_VBDEV_REDIRECTOR_CHANNEL_H */
