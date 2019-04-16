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
 * Channel state maintenance module. Channel create and delete is
 * handled here, as well as all channel state updates. This includes
 * adding or removing target connections, updating the rule table, and
 * collecting per-channel IO stats.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_channel.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector_rule_table.h"
#include "vbdev_redirector.h"
#include "spdk/bdev.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

static inline bool
vbdev_channel_state_update_pending(struct redirector_bdev *bdev)
{
	return bdev->rule_update_pending || bdev->target_update_pending || bdev->other_update_pending;
}

static inline bool
vbdev_channel_state_update_in_progress(struct redirector_bdev *bdev)
{
	/* Rule replacement and/or target update/drain in progress */
	return bdev->updating_channels;
}

/*
 * Called during channel state update finish, when the channel threads are finished
 * writing to the ch_stats_coll struct, and the next channel update hasn't started yet.
 */
static void
redirector_target_channel_stats_rollup(struct redirector_bdev *bdev)
{
	GSequenceIter *target_iter;
	struct redirector_target *iter_target = NULL;

	target_iter = g_sequence_get_begin_iter(bdev->config->targets);
	while (!g_sequence_iter_is_end(target_iter)) {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		/* Replace with latest */
		iter_target->stats.ios_in_flight = iter_target->ch_stats_coll.ch_ios_in_flight;
		iter_target->ch_stats_coll.ch_ios_in_flight = 0;
		iter_target->stats.ios_queued = iter_target->ch_stats_coll.ch_ios_queued;
		iter_target->ch_stats_coll.ch_ios_queued = 0;
		/* Cumulative */
		iter_target->stats.io_count += iter_target->ch_stats_coll.ch_io_count;
		iter_target->ch_stats_coll.ch_io_count = 0;
		iter_target->stats.queued_io_count += iter_target->ch_stats_coll.ch_queued_io_count;
		iter_target->ch_stats_coll.ch_queued_io_count = 0;
		target_iter = g_sequence_iter_next(target_iter);
	}
}

static inline void
_ch_target_mark_draining(struct redirector_bdev_io_channel *rd_ch,
			 struct redirector_bdev_io_channel_target *rd_ch_target)
{
	if (!rd_ch_target->draining) {
		rd_ch_target->draining = true;
		rd_ch_target->drained = false;
		rd_ch->num_draining++;
		assert(rd_ch->num_draining <= REDIRECTOR_MAX_TARGET_BDEVS);
	}
}

static void
_ch_state_update_finish(struct redirector_bdev *bdev, int status)
{
	GSList *completions = NULL;
	GSequence *to_free = NULL;

	assert(bdev->updating_channels);

	bdev->stats.channel_count = bdev->ch_stats_coll.ch_count;
	bdev->stats.channels_drained += bdev->ch_stats_coll.ch_drain_count;
	bdev->stats.channel_ios_drained += bdev->ch_stats_coll.ch_ios_drained;
	redirector_target_channel_stats_rollup(bdev);
	completions = bdev->ch_update_cpl.in_progress;
	bdev->ch_update_cpl.in_progress = NULL;

	if (bdev->updating_channel_rules) {
		assert(bdev->replaced_rules);
		to_free = bdev->replaced_rules;
		bdev->replaced_rules = NULL;
		/* replaced_buf is probably NULL on the first update */
		free(bdev->hint_page.replaced_buf);
		bdev->hint_page.replaced_buf = NULL;

		/* Hash table and NQN pages may be NULL */
		free(bdev->hint_page.hash_table.replaced_buf);
		bdev->hint_page.hash_table.replaced_buf = NULL;

		free(bdev->hint_page.nqn_list.replaced_buf);
		bdev->hint_page.nqn_list.replaced_buf = NULL;

		bdev->updating_channel_rules = false;
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] Rules update completed for all channels on redirector %s\n",
			      rd_th_name(), bdev->config->redirector_name);
	}

	bdev->stats.channel_updates++;
	bdev->updating_channels = false;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s (%p)] State update completed for all channels on redirector %s\n",
		      rd_th_name(), spdk_get_thread(), bdev->config->redirector_name);

	if (vbdev_channel_state_update_pending(bdev)) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] Starting pending channel rule update on redirector %s\n",
			      rd_th_name(), bdev->config->redirector_name);
		vbdev_redirector_update_channel_state(bdev, NULL, NULL);
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s] Redirector %s. in_progress_cpl=%p\n",
		      rd_th_name(), bdev->config->redirector_name, completions);

	redirector_call_completions(&completions, status);

	if (to_free) {
		g_sequence_free(to_free);
	}
}

static void
_ch_state_update_cpl(struct spdk_io_channel_iter *iter, int status)
{
	_ch_state_update_finish(spdk_io_channel_iter_get_ctx(iter), status);
}

static void
_ch_target_init(struct redirector_bdev *rd_node, struct redirector_bdev_io_channel *rd_ch,
		size_t ch_target_index)
{
	rd_ch->targets[ch_target_index].ios_in_flight = 0;
	rd_ch->targets[ch_target_index].ios_queued = 0;
	if (rd_node->targets[ch_target_index].drain) {
		rd_ch->targets[ch_target_index].max_qd = 0;
	} else {
		rd_ch->targets[ch_target_index].max_qd = rd_node->targets[ch_target_index].max_qd;
	}
	rd_ch->targets[ch_target_index].io_count = 0;
	rd_ch->targets[ch_target_index].queued_io_count = 0;
	if (rd_node->targets[ch_target_index].desc && !rd_node->targets[ch_target_index].drain) {
		rd_ch->targets[ch_target_index].ch =
			spdk_bdev_get_io_channel(rd_node->targets[ch_target_index].desc);
	} else {
		rd_ch->targets[ch_target_index].ch = NULL;
	}
	rd_ch->targets[ch_target_index].drained = false;
	rd_ch->targets[ch_target_index].draining = false;
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s (%p)] Redirector %s (ch %p) initializing ch (%p) for %starget %s at index %zu\n",
		      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name, rd_ch,
		      rd_ch->targets[ch_target_index].ch, rd_node->targets[ch_target_index].drain ? "draining " : "",
		      rd_node->targets[ch_target_index].target_config->name,
		      ch_target_index);
}

static void
_ch_state_update(struct spdk_io_channel_iter *iter)
{
	struct spdk_io_channel *ch = spdk_io_channel_iter_get_channel(iter);
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);
	struct redirector_bdev *rd_node = spdk_io_channel_iter_get_io_device(iter);
	bdev_io_tailq_t	retarget_io_tailq;
	struct spdk_bdev_io *retarget_io;
	size_t ch_target_index;

	assert(rd_ch->state_update_iter == NULL);
	assert(rd_node->updating_channels);
	TAILQ_INIT(&retarget_io_tailq);
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s (%p)] redirector %s ch=%p rd_ch=%p\n",
		      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name, ch, rd_ch);
	if (rd_node->updating_channel_rules) {
		assert(rd_node->replaced_rules);
		assert(rd_node->applied_rules);
		/* Copy applied rules to avoid GLib warnings */
		g_sequence_free(rd_ch->rules);
		rd_ch->rules = rule_table_duplicate(rd_node->applied_rules);
		/* Replaced_buf is probably NULL on the first update */
		assert(rd_node->hint_page.applied_buf);
		rd_ch->hint_log_page = rd_node->hint_page.applied_buf;
		/* Hash table and NQN list pages may be NULL */
		rd_ch->hash_table_log_page = rd_node->hint_page.hash_table.applied_buf;
		rd_ch->nqn_list_log_page = rd_node->hint_page.nqn_list.applied_buf;
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] redirector %s ch=%p rules=%p\n",
			      rd_th_name(), spdk_get_thread(), rd_node->config->redirector_name, rd_ch, rd_ch->rules);
	}
	rd_node->ch_stats_coll.ch_count++; /* count this channel */
	assert(rd_ch->num_ch_targets <= rd_node->num_rd_targets);
	rd_ch->num_ch_targets = rd_node->num_rd_targets;

	/*
	 * We'll make two passes over the target table here. In the first pass we collect all the queued
	 * unsubmitted IOs, update the target QD, and get IO channels for new targets.
	 */
	for (ch_target_index = 0;
	     ch_target_index < rd_node->num_rd_targets;
	     ch_target_index++) {
		/* Dequeue queued IO */
		TAILQ_CONCAT(&retarget_io_tailq, &rd_ch->targets[ch_target_index].queued_io_tailq, module_link);
		rd_ch->targets[ch_target_index].ios_queued = 0;
		/* Update QD */
		if (rd_ch->targets[ch_target_index].max_qd != rd_node->targets[ch_target_index].max_qd) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s] redirector %s (ch %p) max_qd for %s at index %zu changed from %d to %d\n",
				      rd_th_name(), rd_node->config->redirector_name, rd_ch,
				      rd_node->targets[ch_target_index].target_config->name,
				      ch_target_index,
				      rd_ch->targets[ch_target_index].max_qd,
				      rd_node->targets[ch_target_index].max_qd);
			rd_ch->targets[ch_target_index].max_qd = rd_node->targets[ch_target_index].max_qd;
		}
		/* Add new channel */
		if (spdk_unlikely(rd_ch->targets[ch_target_index].ch == NULL &&
				  rd_node->targets[ch_target_index].desc &&
				  rd_node->targets[ch_target_index].bdev &&
				  !rd_node->targets[ch_target_index].drain &&
				  !rd_node->targets[ch_target_index].free_index)) {
			assert(!rd_ch->targets[ch_target_index].draining);
			_ch_target_init(rd_node, rd_ch, ch_target_index);
		}
	}
	/*
	 * Resubmit all the IOs that were queued on targets to apply the latest rule table in their target
	 * selection. New rules may route these queued IOs to a location (hint + target) with a higher QD,
	 * or may put them right back on the target they were queued on when this channel update started.
	 * We resubmit them in the same order they appeared in each target queue.
	 */
	while (!TAILQ_EMPTY(&retarget_io_tailq)) {
		retarget_io = TAILQ_FIRST(&retarget_io_tailq);
		TAILQ_REMOVE(&retarget_io_tailq, retarget_io, module_link);
		if (RD_DEBUG_LOG_CHANNEL_STUFF) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s] Reassigning target for queued IO on redirector %s: io=%p "
				      "LBA=%"PRId64" blocks=%"PRId64"\n",
				      rd_th_name(), rd_node->config->redirector_name, retarget_io,
				      retarget_io->u.bdev.offset_blocks,
				      retarget_io->u.bdev.num_blocks);
		}
		assert(is_redirector_io(retarget_io));
		vbdev_redirector_io_unassign_target(ch, retarget_io);
		vbdev_redirector_resubmit_request(ch, retarget_io);
	}
	/*
	 * Now that queued IOs are all associated with targets again, we make the second pass over the target table.
	 * This time we start the process of draining IOs (including those queued on that target) from targets marked
	 * for draining (e.g. in advance of being removed). This channel update won't complete (continue on the next
	 * channel) until all IOs in progress or queued for targets marked as draining.
	 *
	 * To minimize the duration of the target removal process, it makes sense to use two channel state update
	 * passes. In the first we'll just update the rule table so it doesn't route any IO to the targets we want to
	 * remove. In the second pass we'll drain IOs from the targets being removed. As we wait for draining at each
	 * channel, none of the other channels will be submitting new IO to the targets we'll have to drain when we
	 * get to them.
	 */
	for (ch_target_index = 0;
	     ch_target_index < rd_node->num_rd_targets;
	     ch_target_index++) {
		/* The target max queued depth may have been updated, enabling more IO to be submitted. We do
		 * this here, after the queued IOs have been reassigned to targets according to the (possibly)
		 * new rule table. */
		_ch_target_submit_queued_io(ch, ch_target_index);
		/* Drain selected channels, or all channels on shutdown */
		if (rd_node->targets[ch_target_index].drain ||
		    (g_shutdown_started && !rd_node->targets[ch_target_index].free_index)) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s] Redirector %s (ch %p) draining ch for %s at index %zu "
				      "%zu already draining\n",
				      rd_th_name(), rd_node->config->redirector_name, rd_ch,
				      rd_node->targets[ch_target_index].target_config->name,
				      ch_target_index, rd_ch->num_draining);
			assert(rd_ch->targets[ch_target_index].ch ||
			       target_index_sticky(rd_node->targets[ch_target_index].target_config));
			_ch_target_mark_draining(rd_ch, &rd_ch->targets[ch_target_index]);
			_ch_state_target_drain(rd_node, rd_ch, ch_target_index);
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s] Redirector %s draining ch for %s. "
				      "%d IOs in flight. %zu targets now draining.\n",
				      rd_th_name(), rd_node->config->redirector_name,
				      rd_node->targets[ch_target_index].target_config->name,
				      rd_ch->targets[ch_target_index].ios_in_flight, rd_ch->num_draining);
			/* Accumulate target ch in-flight IOs */
			rd_node->ch_stats_coll.ch_ios_drained +=
				rd_ch->targets[ch_target_index].ios_in_flight;
		}
		/* Collect channel stats */
		if (rd_ch->targets[ch_target_index].ch &&
		    /* Update target stats in ch-thread writable region (if there's anything to report) */
		    rd_node->targets[ch_target_index].target_config) {
			if (rd_ch->targets[ch_target_index].io_count) {
				rd_node->targets[ch_target_index].target_config->ch_stats_coll.ch_io_count +=
					rd_ch->targets[ch_target_index].io_count;
			}
			if (rd_ch->targets[ch_target_index].queued_io_count) {
				rd_node->targets[ch_target_index].target_config->ch_stats_coll.ch_queued_io_count +=
					rd_ch->targets[ch_target_index].queued_io_count;
			}
			if (rd_ch->targets[ch_target_index].ios_in_flight) {
				rd_node->targets[ch_target_index].target_config->ch_stats_coll.ch_ios_in_flight +=
					rd_ch->targets[ch_target_index].ios_in_flight;
			}
			if (rd_ch->targets[ch_target_index].ios_queued) {
				rd_node->targets[ch_target_index].target_config->ch_stats_coll.ch_ios_queued +=
					rd_ch->targets[ch_target_index].ios_queued;
			}
		}
	}
	/* Accumulate draining target channel count */
	rd_node->ch_stats_coll.ch_drain_count += rd_ch->num_draining;
	/* Until state_update_iter has iter, continue_if_drained won't continue */
	rd_ch->state_update_iter = iter;
	_ch_state_update_continue_if_drained(rd_node, rd_ch);
}

void
vbdev_redirector_update_channel_state(struct redirector_bdev *bdev,
				      redirector_completion_cb cb_fn,
				      void *cb_ctx)
{
	size_t target_index;

	if (cb_fn) {
		redirector_schedule_completion(&bdev->ch_update_cpl.starting, cb_fn, cb_ctx);
	}

	if (vbdev_channel_state_update_in_progress(bdev)) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] Deferring channel state update on redirector %s "
			      "until in-progress update completes\n",
			      rd_th_name(), spdk_get_thread(), bdev->config->redirector_name);
		return;
	}

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] redirector %s\n", rd_th_name(), spdk_get_thread(), bdev->config->redirector_name);
	}

	assert(bdev->replaced_rules == NULL);
	assert(bdev->hint_page.replaced_buf == NULL);
	if (bdev->rule_update_pending) {
		/*
		 * The rule table and hint log page buffer are generated and updated together. At some point the log
		 * page contents will be unique per connected host, but for now they all see the same data.
		 *
		 * Once generated, these things are never changed by the control plane here, only replaced with this
		 * mechanism. Here we move the rule table and page buf into fields named "applied", and NULL the old
		 * pointers. Before that we move the current pointer in "applied" to one named "replaced". At this
		 * point these now constant buffers may be read by any channel thread. Some may still be reading what's
		 * pointed to in "replaced", but gradually they'll all begin using the one pointed to by "applied".
		 *
		 * We send an update message to each channel thread with the SPDK foreach API. Each channel replaces
		 * its pointer to the rule table and hint buf with the one now in "applied". The for_each completion
		 * function (which runs back here on this thread) frees the old rule table and hint page buffer (which
		 * no channel thread is now reading).
		 *
		 * The rule table is for now still a GSequence, but it's safe to read without locking from the channel
		 * threads because the control thread won't change it.
		 */
		assert(bdev->locations);
		assert(bdev->hint_page.buf);
		bdev->replaced_rules = bdev->applied_rules;
		bdev->applied_rules = bdev->locations;
		bdev->locations = NULL;

		bdev->hint_page.replaced_buf = bdev->hint_page.applied_buf;
		bdev->hint_page.applied_buf = bdev->hint_page.buf;
		bdev->hint_page.buf = NULL;

		bdev->hint_page.hash_table.replaced_buf = bdev->hint_page.hash_table.applied_buf;
		bdev->hint_page.hash_table.applied_buf = bdev->hint_page.hash_table.buf;
		bdev->hint_page.hash_table.buf = NULL;

		bdev->hint_page.nqn_list.replaced_buf = bdev->hint_page.nqn_list.applied_buf;
		bdev->hint_page.nqn_list.applied_buf = bdev->hint_page.nqn_list.buf;
		bdev->hint_page.nqn_list.buf = NULL;

		bdev->updating_channels = true;
		bdev->updating_channel_rules = true;
		bdev->stats.rule_updates++;
		bdev->rule_update_pending = false;

		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] redirector %s. applied=%p replaced=%p applied_page=%p replaced_page=%p\n",
			      rd_th_name(), spdk_get_thread(), bdev->config->redirector_name, bdev->applied_rules,
			      bdev->replaced_rules, bdev->hint_page.applied_buf, bdev->hint_page.replaced_buf);
	}

	if (bdev->target_update_pending) {
		/* Ensure all removing targets are marked for drain in target table */
		for (target_index = 0;
		     target_index < bdev->num_rd_targets;
		     target_index++) {
			if (bdev->targets[target_index].target_config &&
			    (bdev->targets[target_index].bdev ||
			     target_index_sticky(bdev->targets[target_index].target_config)) &&
			    bdev->targets[target_index].target_config->removing) {

				assert(bdev->targets[target_index].target_config->target_index == (int)target_index);
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "[%s (%p)] Will drain target %s (%d) on redirector %s%s\n",
					      rd_th_name(), spdk_get_thread(),
					      bdev->targets[target_index].target_config->name,
					      bdev->targets[target_index].target_config->target_index,
					      bdev->config->redirector_name,
					      (bdev->targets[target_index].bdev == NULL) ? " [NULL bdev]" : "");

				bdev->targets[target_index].drain = true;
			}
		}

		/* TODO: assert that no rule refers to a draining target */
		bdev->updating_channels = true;
		bdev->stats.target_updates++;
		bdev->target_update_pending = false;
	}

	if (bdev->other_update_pending) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] redirector %s other channel update requested\n",
			      rd_th_name(), spdk_get_thread(), bdev->config->redirector_name);
		bdev->other_update_pending = false;
		bdev->updating_channels = true;
	}

	if (bdev->updating_channels) {
		/* Completions for in-progress updates should be completed before now */
		assert(bdev->ch_update_cpl.in_progress == NULL);

		/* Completions waiting to start now become in-progress */
		bdev->ch_update_cpl.in_progress = bdev->ch_update_cpl.starting;
		bdev->ch_update_cpl.starting = NULL;
		bdev->ch_stats_coll.ch_count = 0;
		bdev->ch_stats_coll.ch_drain_count = 0;
		bdev->ch_stats_coll.ch_ios_drained = 0;
		if (bdev->registered) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s (%p)] channel state update on redirector %s. in_progress_cpl=%p\n",
				      rd_th_name(), spdk_get_thread(), bdev->config->redirector_name, bdev->ch_update_cpl.in_progress);
			spdk_for_each_channel(bdev,
					      _ch_state_update,
					      bdev, /* spdk_io_channel_iter_get_ctx() will return this */
					      _ch_state_update_cpl);
		} else {
			/* If we haven't registered the redirector yet, we skip the for_each_channel() but
			 * use the same completion function to finish the (probably first) state update. */
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "[%s (%p)] channel state update on unregistered redirector %s\n",
				      rd_th_name(), spdk_get_thread(), bdev->config->redirector_name);
			_ch_state_update_finish(bdev, 0);
		}
	}
}

struct vbdev_redirector_update_channel_state_sync_ctx {
	struct redirector_bdev	    *rd_node;
	bool			    complete;
};

static void
vbdev_redirector_update_channel_state_sync_cpl(void *ctx, int status)
{
	struct vbdev_redirector_update_channel_state_sync_ctx *update_ctx = ctx;

	update_ctx->complete = true;
}

/*
 * Wait for a channel update to complete (e.g. to refresh the stats) if possible
*/
void
vbdev_redirector_update_channel_state_sync(struct redirector_bdev *rd_node)
{
	struct spdk_thread *thread = spdk_get_thread();
	struct vbdev_redirector_update_channel_state_sync_ctx update_ctx;
	bool waited;

	if (!rd_node->registered) {
		return;
	}

	if (!thread) {
		return;
	}

	update_ctx.rd_node = rd_node;
	update_ctx.complete = false;
	rd_node->other_update_pending = true;
	vbdev_redirector_update_channel_state(rd_node,
					      vbdev_redirector_update_channel_state_sync_cpl,
					      &update_ctx);
	/* Wait for target remove to complete before returning */
	waited = !update_ctx.complete;
	if (waited) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] Waiting for channel state update on redirector %s\n",
			      rd_th_name(), thread, rd_node->config->redirector_name);
	}
	while (!update_ctx.complete) {
		spdk_thread_poll(thread, 1, 0);
	}
	if (waited) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] Channel state update on redirector %s completed\n",
			      rd_th_name(), thread, rd_node->config->redirector_name);
	}
}

/* We supplied this as an entry point for upper layers who want to communicate to this
 * bdev.  This is how they get a channel. We are passed the same context we provided when
 * we created our redirector vbdev in examine() which, for this bdev, is the address of one of
 * our context nodes. From here we'll ask the SPDK channel code to fill out our channel
 * struct and we'll keep it in our RE node.
 */
struct spdk_io_channel *
vbdev_redirector_get_io_channel(void *ctx)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;
	struct spdk_io_channel *rd_ch = NULL;

	/* The IO channel code will allocate a channel for us which consists of
	 * the SPDK channel structure plus the size of our redirector_bdev_io_channel struct
	 * that we passed in when we registered our IO device. It will then call
	 * our channel create callback to populate any elements that we need to
	 * update.
	 */
	rd_ch = spdk_get_io_channel(rd_node);

	return rd_ch;
}

int
redirector_bdev_ch_create_cb(void *io_device, void *ctx_buf)
{
	struct redirector_bdev_io_channel *rd_ch = ctx_buf;
	struct redirector_bdev *rd_node = io_device;
	size_t ch_target_index;

	assert(rd_node->registered);
	bzero(rd_ch, sizeof(*rd_ch));
	/* Duplicate applied_rules to avoid GLib warnings */
	rd_ch->rules = rule_table_duplicate(rd_node->applied_rules);
	rd_ch->hint_log_page = rd_node->hint_page.applied_buf;
	rd_ch->hash_table_log_page = rd_node->hint_page.hash_table.applied_buf;
	rd_ch->nqn_list_log_page = rd_node->hint_page.nqn_list.applied_buf;
	rd_ch->num_ch_targets = rd_node->num_rd_targets;
	for (ch_target_index = 0;
	     ch_target_index < REDIRECTOR_MAX_TARGET_BDEVS;
	     ch_target_index++) {
		/* Initialize all the table entries */
		TAILQ_INIT(&rd_ch->targets[ch_target_index].queued_io_tailq);

		if ((ch_target_index < rd_node->num_rd_targets) &&
		    (!rd_node->targets[ch_target_index].free_index)) {
			/* Init IO channels for currently populated entries */
			_ch_target_init(rd_node, rd_ch, ch_target_index);
		}
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s] redirector %s ch=%p rd_ch=%p rules=%p\n",
		      rd_th_name(), rd_node->config->redirector_name,
		      spdk_io_channel_from_ctx(rd_ch), rd_ch, rd_ch->rules);

	return 0;
}

void
redirector_bdev_ch_destroy_cb(void *io_device, void *ctx_buf)
{
	struct redirector_bdev_io_channel *rd_ch = ctx_buf;
	struct redirector_bdev *rd_node = io_device;
	size_t target_bdev_index;

	/* Last stats collection from this ch before its freed */
	for (target_bdev_index = 0;
	     target_bdev_index < rd_ch->num_ch_targets;
	     target_bdev_index++) {
		assert(TAILQ_EMPTY(&rd_ch->targets[target_bdev_index].queued_io_tailq));
		if (rd_ch->targets[target_bdev_index].ch) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "redirector %s target %zu ch=%p\n",
				      rd_node->config->redirector_name, target_bdev_index,
				      rd_ch->targets[target_bdev_index].ch);
			spdk_put_io_channel(rd_ch->targets[target_bdev_index].ch);
		}
	}

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s] redirector %s ch=%p rules=%p\n",
		      rd_th_name(), rd_node->config->redirector_name, rd_ch, rd_ch->rules);
}
