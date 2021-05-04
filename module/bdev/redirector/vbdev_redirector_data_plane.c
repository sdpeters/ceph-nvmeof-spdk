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
 * Redirector data plane. Handles submitting an incoming IO to this redirector to the
 * best alternative target based on the rule table currently in effect.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_null_hash.h"
#include "vbdev_redirector_ceph_hash.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector_rule_table.h"
#include "vbdev_redirector_channel.h"
#include "vbdev_redirector_process_nvme_admin.h"
#include "vbdev_redirector_data_plane.h"
#include "vbdev_redirector.h"
#include "spdk/bdev.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

static void
redirector_bdev_io_init(struct redirector_bdev_io *io, struct spdk_io_channel *ch)
{
	bzero(io, sizeof(*io));
	io->ch = ch;
}

/*
 * Wrapper for spdk_bdev_io_complete() that ensures all per-target state is updated
 */
void
vbdev_redirector_io_complete(struct spdk_bdev_io *bdev_io, int status)
{
	struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "bdev_io=%p io_ctx=%p status=%d\n",
			      bdev_io, io_ctx, status);
	}
	if (is_redirector_io(bdev_io)) {
		assert(io_ctx->ch);
		_vbdev_redirector_io_unassign_target(io_ctx->ch, bdev_io, true);
	}
	spdk_bdev_io_complete(bdev_io, status);
}

/* Completion callback for IO that were issued from this bdev. The original bdev_io
 * is passed in as an arg so we'll complete that one with the appropriate status
 * and then free the one that this module issued.
 */
static void
_rd_complete_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	int status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "bdev_io=%p orig_io=%p\n", bdev_io, orig_io);
	}
	if (RD_DEBUG_LOG_TARGET_TRANSLATION || !success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector s: type=%s target=s "
			      "LBA=%"PRId64" blocks=%"PRId64" target LBA="PRId64" "
			      "io=%p rd_ioctx=p%s\n",
			      spdk_bdev_io_type_name[orig_io->type],
			      orig_io->u.bdev.offset_blocks,
			      orig_io->u.bdev.num_blocks, orig_io,
			      success ? "" : " FAILED");
	}

	/* Complete the original IO and then free the one that we created here
	 * as a result of issuing an IO via submit_reqeust.
	 */
	vbdev_redirector_io_complete(orig_io, status);
	spdk_bdev_free_io(bdev_io);
}

static void
vbdev_redirector_resubmit_io(void *arg)
{
	struct spdk_bdev_io *bdev_io = (struct spdk_bdev_io *)arg;
	struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "bdev_io=%p io_ctx=%p\n", bdev_io, io_ctx);
	}
	bdev_io->module_link.tqe_next = NULL;
	bdev_io->module_link.tqe_prev = NULL;
	vbdev_redirector_submit_request(io_ctx->ch, bdev_io);
}

static void
vbdev_redirector_queue_io(struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;
	int rc;

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "IO queued for bdev %s: type=%s "
			      "LBA=%"PRId64" blocks=%"PRId64" "
			      "io=%p rd_ioctx=%p\n",
			      spdk_bdev_get_name(bdev_io->bdev),
			      spdk_bdev_io_type_name[bdev_io->type],
			      bdev_io->u.bdev.offset_blocks,
			      bdev_io->u.bdev.num_blocks,
			      bdev_io, io_ctx);
	}

	io_ctx->bdev_io_wait.bdev = bdev_io->bdev;
	io_ctx->bdev_io_wait.cb_fn = vbdev_redirector_resubmit_io;
	io_ctx->bdev_io_wait.cb_arg = bdev_io;

	rc = spdk_bdev_queue_io_wait(bdev_io->bdev, io_ctx->ch, &io_ctx->bdev_io_wait);
	if (spdk_unlikely(rc != 0)) {
		SPDK_ERRLOG("Queue io failed in vbdev_redirector_queue_io, rc=%d.\n", rc);
		vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
	}
}

struct algorithmic_hint_target_for_lba {
	uint64_t	lba;
	char		*name;
	int		target_index;
	uint64_t	target_lba;
};

static inline uint64_t
hash_hint_lba_to_object_number(struct redirector_bdev *rd_node,
			       const struct location_hint *hint,
			       const uint64_t lba)
{
	uint64_t byte_to_object_shift = (1 + spdk_u64log2(hint->hash.object_bytes - 1));
	uint64_t lba_to_object_shift = byte_to_object_shift - (1 + spdk_u64log2(
					       rd_node->redirector_bdev.blocklen - 1));
	return lba >> lba_to_object_shift;
}

static inline int
get_hash_hint_target_for_lba(struct redirector_bdev *rd_node,
			     const struct location_hint *hint,
			     const uint64_t lba,
			     struct algorithmic_hint_target_for_lba *result)
{
	uint64_t object_number;
	uint64_t bucket_num;
	uint64_t nqn_num;
	int rc;

	assert(result);
	assert(location_hint_type(hint) == RD_HINT_TYPE_HASH_NQN_TABLE);
	object_number = hash_hint_lba_to_object_number(rd_node, hint, lba);
	result->lba = lba;
	/* Hash hints don't translate LBAs - IO is submitted to any target at its original LBA */
	result->target_lba = (lba - hint->extent.start_lba);	/* Offset into hint LBA range */
	switch (hint->hash.hash_function_id) {
	case RD_HASH_FN_ID_NULL:
		rc = vbdev_redirector_get_null_hash_bucket_for_object(rd_node, hint, object_number, &bucket_num);
		break;
	case RD_HASH_FN_ID_CEPH_RJENKINS:
		rc = vbdev_redirector_get_ceph_hash_bucket_for_object(rd_node, hint, object_number, &bucket_num);
		break;
	case RD_HASH_FN_ID_NONE:
	default:
		SPDK_ERRLOG("Redirector %s bad hash function ID\n", rd_node->config->redirector_name);
		return -1;
	}

	if (rc) {
		return rc;
	}

	assert(bucket_num < hint->hash.hash_table->num_buckets);
	nqn_num = hint->hash.hash_table->buckets[bucket_num];
	assert(nqn_num < hint->hash.nqn_list->num_nqns);
	if (RD_DEBUG_LOG_TARGET_TRANSLATION) {
		result->name = (char *)g_quark_to_string(hint->hash.nqn_list->nqns[nqn_num].nqn);
	} else {
		result->name = "[not retrieved]";
	}
	result->target_index = hint->hash.nqn_list->nqns[nqn_num].target_index;
	if (spdk_unlikely(rd_target_unavailable(rd_node, result->target_index))) {
		/*
		 * Map any unavailable target to the known good target recorded earlier.
		 *
		 * TODO: Spread the pain by mapping each hash table bucket that points to an
		 * unavailable target to one of the available targets.
		 */
		result->target_index = hint->target_index;
	}
	/* assert(!rd_target_unusable(result->target_index)); */
	/* assert(!rd_target_unavailable(rd_node, result->target_index)); */
	return 0;
}

static inline int
get_location_hint_target_for_lba(struct redirector_bdev *rd_node,
				 const struct location_hint *hint,
				 const uint64_t lba,
				 struct algorithmic_hint_target_for_lba *result)
{
	assert(result);
	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
		/* Simple hints - not algorithmic */
		result->lba = lba;
		result->name = location_hint_target_name(hint);
		result->target_index = hint->target_index;
		result->target_lba =
			(lba - hint->extent.start_lba)			/* Offset into hint LBA range */
			+ location_hint_target_start_lba(hint);		/* Where LBA range starts on target */
		return 0;
		break;
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		return get_hash_hint_target_for_lba(rd_node, hint, lba, result);
		break;
	default:
		return -EINVAL;
	}
}

/*
 * Chooses one of the redirector targets and an offset into that target as the destination for a
 * bdev_io based on the current set of location hints.
 *
 * This is where the rule table is applied to IO in the redirector data plane.
 */
static int
vbdev_redirector_select_target(struct redirector_bdev *rd_node,
			       struct redirector_bdev_io_channel *rd_ch,
			       uint64_t lba, uint64_t *target_lba)
{
	/* Hint describing first LBA of this IO */
	struct location_hint lookup = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN_NS,	/* Hint type ignored in compare fn */
		.extent = {
			.start_lba = lba,
			.blocks = 1
		},
	};
	int rc;
	GSequenceIter *search_iter;
	struct location_hint *hint_data;
	int matching_index = -1;
	struct algorithmic_hint_target_for_lba computed_target;
	struct hint_extent *hint_extent = NULL;

	if (spdk_unlikely(0 == location_list_length(rd_ch->rules))) {
		return -1;
	}

	/*
	 * Find where a hint describing the first LBA of this IO would be inserted. That's the last
	 * rule in the rule table GSequence with a start LBA <= the first LBA of this IO.
	 *
	 * A GSequence behaves like a list but is searchable like a tree. This rule lookup takes log
	 * time, based on the length of the rule table. POR was to use a sorted array for teh rule
	 * table, and binary search on the match here in the data plane. Given that the GSequence
	 * produces the same performance (but perhaps touches more cache lines) there's no apparent
	 * urgency to do that. We duplicate this GSequence for every channel. We actually only need
	 * one immutable copy for all the channels, since they only read. We make separate copies
	 * only because glib2 includes some debug checks for apparently unlocked concurrent access
	 * of GSequences, so unlocked concurrent reads of GSequences trigger a debug warning.
	 */
	search_iter = g_sequence_search(rd_ch->rules, &lookup,
					location_hint_data_compare_fn, NULL);
	if (g_sequence_iter_is_end(search_iter)) {
		search_iter = g_sequence_iter_prev(search_iter);
	}
	hint_data = (struct location_hint *)g_sequence_get(search_iter);
	assert(hint_data);
	hint_extent = location_hint_extent(hint_data);
	assert(hint_extent);
	if (lba < hint_extent->start_lba) {
		search_iter = g_sequence_iter_prev(search_iter);
		hint_data = (struct location_hint *)g_sequence_get(search_iter);
		assert(hint_data);
		hint_extent = location_hint_extent(hint_data);
		assert(hint_extent);
	}
	assert(lba >= hint_extent->start_lba);
	/* Apply hint-specific target selection */
	rc = get_location_hint_target_for_lba(rd_node, hint_data, lba, &computed_target);
	assert(0 == rc);
	matching_index = computed_target.target_index;
	assert(matching_index != -1);
	assert(!rd_node->targets[matching_index].free_index);
	if (spdk_unlikely(!rd_ch->targets[matching_index].ch)) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s (%p)] LBA=%"PRId64" target=%s ch=%p max_qd=%d start_lba=%"PRId64" "
			      "target_start_lba=%"PRId64" target_lba=%"PRId64"\n",
			      rd_th_name(), spdk_get_thread(), lba,
			      computed_target.name,
			      rd_ch->targets[matching_index].ch, rd_ch->targets[matching_index].max_qd,
			      hint_extent->start_lba,
			      location_hint_target_start_lba(hint_data),
			      computed_target.target_lba);
	}
	assert(rd_ch->targets[matching_index].ch || rd_ch->targets[matching_index].max_qd == 0);
	if (target_lba) {
		*target_lba = computed_target.target_lba;
		if (RD_DEBUG_LOG_TARGET_TRANSLATION) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "LBA=%"PRId64" target=%s start_lba=%"PRId64" "
				      "target_start_lba=%"PRId64" target_lba=%"PRId64"\n",
				      lba,
				      computed_target.name,
				      hint_extent->start_lba,
				      location_hint_target_start_lba(hint_data),
				      *target_lba);
		}
	} else {
		if (RD_DEBUG_LOG_TARGET_TRANSLATION) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "LBA=%"PRId64" target=%s start_lba=%"PRId64" "
				      "target_start_lba=%"PRId64" target_lba=NULL\n",
				      lba,
				      computed_target.name,
				      hint_extent->start_lba,
				      location_hint_target_start_lba(hint_data));
		}
	}
	return matching_index;
}

/* Chooses one of the redirector targets as the destination for a
 * bdev_io based on the current set of location hints. */
static inline int
vbdev_redirector_io_select_target(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io,
				  uint64_t *target_lba)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "ch=%p bdev_io=%p\n", ch, bdev_io);
	}

	return vbdev_redirector_select_target(rd_node, spdk_io_channel_get_ctx(ch),
					      bdev_io->u.bdev.offset_blocks,
					      target_lba);
}

/* Callback for getting a buf from the bdev pool in the event that the caller passed
 * in NULL, we need to own the buffer so it doesn't get freed by another vbdev module
 * beneath us before we're done with it. That won't happen in this example but it could
 * if this example were used as a template for something more complex.
 */
static void
rd_read_get_buf_cb(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io, bool success)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);
	struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;
	int rc = 0;

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "ch=%p bdev_io=%p\n", ch, bdev_io);
	}

	if (!success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "FAILED ch=%p bdev_io=%p\n", ch, bdev_io);
		vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	/* target index already computed */
	assert(io_ctx->target_index != -1);
	rc = spdk_bdev_readv_blocks(rd_node->targets[io_ctx->target_index].desc,
				    rd_ch->targets[io_ctx->target_index].ch,
				    bdev_io->u.bdev.iovs,
				    bdev_io->u.bdev.iovcnt, io_ctx->target_offset,
				    bdev_io->u.bdev.num_blocks, _rd_complete_io,
				    bdev_io);
	if (spdk_unlikely(rc != 0)) {
		struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;
		if (rc == -ENOMEM) {
			io_ctx->ch = ch;
			vbdev_redirector_queue_io(bdev_io);
		} else {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "ERROR on bdev_io submission Error=%d "
				      "Redirector %s: LBA=%"PRId64" blocks=%"PRId64" "
				      "target=%d (%s) target_offset=%"PRId64"\n",
				      rc, rd_node->config->redirector_name,
				      bdev_io->u.bdev.offset_blocks,
				      bdev_io->u.bdev.num_blocks,
				      io_ctx->target_index,
				      rd_node->targets[io_ctx->target_index].bdev->name,
				      io_ctx->target_offset);
			vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}

static bool
redirector_bdev_reset_completion(struct redirector_bdev_io *redirector_io,
				 struct spdk_bdev_io *parent_io)
{
	struct redirector_bdev		*redirector_bdev = (struct redirector_bdev *)parent_io->bdev->ctxt;

	assert(redirector_bdev->reset_in_progress);
	/* TODO: locking on request counts */
	redirector_io->target_bdev_io_completed++;
	if (redirector_io->target_bdev_io_completed == redirector_io->target_bdev_io_expected) {
		/* TODO: locking on resetting flag */
		redirector_bdev->reset_in_progress = false;
		vbdev_redirector_io_complete(parent_io, redirector_io->target_bdev_io_status);
		return true;
	}
	return false;
}

static void
redirector_bdev_target_io_completion(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *parent_io = cb_arg;
	struct redirector_bdev_io *redirector_io = (struct redirector_bdev_io *)parent_io->driver_ctx;

	spdk_bdev_free_io(bdev_io);

	if (spdk_unlikely(!success)) {
		redirector_io->target_bdev_io_status = SPDK_BDEV_IO_STATUS_FAILED;
	}

	redirector_bdev_reset_completion(redirector_io, parent_io);
}

static void
redirector_bdev_target_io_submit_fail_process(struct spdk_bdev_io *redirector_bdev_io,
		uint8_t pd_idx,
		spdk_bdev_io_wait_cb cb_fn, int ret)
{
	struct redirector_bdev_io *redirector_io = (struct redirector_bdev_io *)
			redirector_bdev_io->driver_ctx;
	struct redirector_bdev_io_channel *redirector_ch = spdk_io_channel_get_ctx(redirector_io->ch);
	struct redirector_bdev *redirector_bdev = (struct redirector_bdev *)redirector_bdev_io->bdev->ctxt;

	assert(ret != 0);

	if (ret == -ENOMEM) {
		redirector_io->bdev_io_wait.bdev = redirector_bdev->targets[pd_idx].bdev;
		redirector_io->bdev_io_wait.cb_fn = cb_fn;
		redirector_io->bdev_io_wait.cb_arg = redirector_bdev_io;
		spdk_bdev_queue_io_wait(redirector_bdev->targets[pd_idx].bdev,
					redirector_ch->targets[pd_idx].ch,
					&redirector_io->bdev_io_wait);
		return;
	}

	SPDK_ERRLOG("bdev io submit error not due to ENOMEM, it should not happen\n");
	assert(false);
	vbdev_redirector_io_complete(redirector_bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
}

static void
_redirector_bdev_submit_reset_request_next(void *_bdev_io)
{
	struct spdk_bdev_io		*bdev_io = _bdev_io;
	struct redirector_bdev_io	*redirector_io;
	struct redirector_bdev		*redirector_bdev;
	struct redirector_bdev_io_channel	*redirector_ch;
	int				ret;
	uint8_t				i;

	redirector_bdev = (struct redirector_bdev *)bdev_io->bdev->ctxt;
	redirector_io = (struct redirector_bdev_io *)bdev_io->driver_ctx;
	redirector_ch = spdk_io_channel_get_ctx(redirector_io->ch);

	while (redirector_io->target_bdev_io_submitted < redirector_bdev->num_rd_targets) {
		i = redirector_io->target_bdev_io_submitted;
		ret = 0;
		if (redirector_bdev->targets[i].desc) {
			ret = spdk_bdev_reset(redirector_bdev->targets[i].desc,
					      redirector_ch->targets[i].ch,
					      redirector_bdev_target_io_completion, bdev_io);
		}
		if (!redirector_bdev->targets[i].desc || ret == 0) {
			redirector_io->target_bdev_io_submitted++;
			if (!redirector_bdev->targets[i].desc) {
				/* Target indexes with no desc are considered completed */
				redirector_io->target_bdev_io_completed++;
				if (redirector_bdev_reset_completion(redirector_io, bdev_io)) {
					/* completed */
					return;
				}
			}
		} else {
			redirector_bdev_target_io_submit_fail_process(
				bdev_io, i, _redirector_bdev_submit_reset_request_next, ret);
			return;
		}
	}
}

static void
_redirector_bdev_submit_reset_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev_io	*redirector_io;
	struct redirector_bdev		*redirector_bdev;

	redirector_bdev = (struct redirector_bdev *)bdev_io->bdev->ctxt;
	redirector_io = (struct redirector_bdev_io *)bdev_io->driver_ctx;
	if (redirector_bdev->reset_in_progress) {
		/* TODO: Defer completion until previous reset finishes */
		vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	}
	/* TODO: locking on resetting flag */
	redirector_bdev->reset_in_progress = true;
	redirector_io->ch = ch;
	redirector_io->target_bdev_io_submitted = 0;
	redirector_io->target_bdev_io_completed = 0;
	redirector_io->target_bdev_io_expected = redirector_bdev->num_rd_targets;
	redirector_io->target_bdev_io_status = SPDK_BDEV_IO_STATUS_SUCCESS;
	_redirector_bdev_submit_reset_request_next(bdev_io);
}

void
__vbdev_redirector_io_unassign_assigned_target(struct spdk_io_channel *ch,
		struct spdk_bdev_io *bdev_io,
		bool io_completed)
{
	struct redirector_bdev_io	    *rd_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;
	struct redirector_bdev_io_channel   *rd_ch = spdk_io_channel_get_ctx(ch);
	struct redirector_bdev		    *redirector_bdev;
	size_t				    target_index;

	target_index = rd_ctx->target_index;
	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "ch=%p bdev_io=%p rd_ctx=%p target_index=%zu%s%s%s%s\n",
			      ch, bdev_io, rd_ctx, target_index,
			      io_completed ? " [completed]" : "",
			      rd_ctx->in_flight ? " [in-flight]" : "",
			      rd_ctx->is_queued ? " [is-queued]" : "",
			      rd_ctx->was_queued ? " [was-queued]" : "");
	}
	/* Update target in-flight accounting */
	if (rd_ctx->in_flight) {
		assert(rd_ch->targets[target_index].ios_in_flight);
		rd_ch->targets[target_index].ios_in_flight--;
		rd_ctx->in_flight = false;
	}
	if (io_completed) {
		rd_ch->targets[target_index].io_count++;
		if (rd_ctx->was_queued) {
			rd_ch->targets[target_index].queued_io_count++;
		}
	}
	rd_ctx->target_index = -1;
	rd_ctx->target_index_assigned = false;
	rd_ctx->is_queued = false; /* Can't be queued unless target assigned */
	redirector_bdev = (struct redirector_bdev *)bdev_io->bdev->ctxt;
	/* Submit queued IO up to max QD if there is any */
	_ch_target_submit_queued_io(ch, target_index);
	if (rd_ch->targets[target_index].ios_in_flight == 0 &&
	    (rd_ch->targets[target_index].draining || rd_ch->targets[target_index].drained)) {
		_ch_state_target_drain(redirector_bdev, rd_ch, target_index);
	}
}

static void
vbdev_redirector_io_assign_target(struct spdk_io_channel *ch,
				  struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev_io *rd_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);

	assert(is_redirector_io(bdev_io));
	if (!vbdev_redirector_io_requires_target(bdev_io)) {
		return;
	}

	if (spdk_unlikely(rd_ctx->is_queued)) {
		/* Queued IOs are passed to resubmit without repeating target selection. They were not counted
		 * as in-flight. When channel targets or rules are updated, queued IO is resubmitted after
		 * unassigning its target. */
		assert(rd_ctx->target_index != -1);
		assert(rd_ctx->target_index_assigned);
		assert(rd_ch->targets[rd_ctx->target_index].ios_in_flight <=
		       rd_ch->targets[rd_ctx->target_index].max_qd);
		rd_ctx->is_queued = false;
		rd_ctx->in_flight = true;
	} else {
		vbdev_redirector_io_unassign_target(ch, bdev_io);
		rd_ctx->target_index = vbdev_redirector_io_select_target(ch, bdev_io, &rd_ctx->target_offset);
		assert(rd_node->targets[rd_ctx->target_index].target_config);
		if (RD_DEBUG_LOG_CHANNEL_STUFF) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s: io=%p rd_ioctx=%p LBA=%"PRId64" blocks=%"PRId64" "
				      "target=%d (%s) target_offset=%"PRId64"\n",
				      rd_node->config->redirector_name, bdev_io, rd_ctx,
				      bdev_io->u.bdev.offset_blocks,
				      bdev_io->u.bdev.num_blocks,
				      rd_ctx->target_index,
				      rd_node->targets[rd_ctx->target_index].target_config->name,
				      rd_ctx->target_offset);
		}
		assert(rd_ctx->target_index != -1 ||
		       target_index_sticky(rd_node->targets[rd_ctx->target_index].target_config));
		rd_ctx->target_index_assigned = true;
		/* If the selected target is at its QD limit, queue this IO. We will not count it as
		 * in-flight. */
		if (spdk_unlikely((rd_ch->targets[rd_ctx->target_index].ios_in_flight >=
				   rd_ch->targets[rd_ctx->target_index].max_qd) ||
				  !TAILQ_EMPTY(&rd_ch->targets[rd_ctx->target_index].queued_io_tailq))) {
			rd_ctx->is_queued = true;
			rd_ctx->was_queued = true;
			rd_ctx->in_flight = false;
			TAILQ_INSERT_TAIL(&rd_ch->targets[rd_ctx->target_index].queued_io_tailq,
					  bdev_io, module_link);
			rd_ch->targets[rd_ctx->target_index].ios_queued++;
			if (RD_DEBUG_LOG_CHANNEL_STUFF) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s: target=%d (%s) queued io=%p "
					      "ios_queued=%d queued_io_count=%"PRIu64"\n",
					      rd_node->config->redirector_name,
					      rd_ctx->target_index,
					      rd_node->targets[rd_ctx->target_index].target_config->name,
					      bdev_io, rd_ch->targets[rd_ctx->target_index].ios_queued,
					      rd_ch->targets[rd_ctx->target_index].queued_io_count);
			}
		} else {
			rd_ctx->in_flight = true;
		}
	}

	/* Update target in-flight accounting */
	if (spdk_likely(rd_ctx->in_flight)) {
		rd_ch->targets[rd_ctx->target_index].ios_in_flight++;
	}
}

/* Called when someone above submits IO to this rd vbdev. We're simply passing it on here
 * via SPDK IO calls which in turn allocate another bdev IO and call our cpl callback provided
 * below along with the original bdev_io so that we can complete it once this IO completes.
 */
void
vbdev_redirector_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;

	assert(is_redirector_io(bdev_io));
	redirector_bdev_io_init(io_ctx, ch);
	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "[%s] redirector=%s ch=%p bdev_io=%p align=%"PRIu32"\n",
			      rd_th_name(), rd_node->config->redirector_name, ch,
			      bdev_io, rd_node->redirector_bdev.required_alignment);
	}
	vbdev_redirector_resubmit_request(ch, bdev_io);
}

static inline int
vbdev_redirector_translate_target_io_type(struct spdk_bdev *target, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_NVME_ADMIN:
	case SPDK_BDEV_IO_TYPE_RESET:
		/* IO types handled locally */
		io_ctx->type = bdev_io->type;
		return 0;
	default:
		break;
	}

	if (spdk_bdev_io_type_supported(target, bdev_io->type)) {
		/* IO types handled by this target */
		io_ctx->type = bdev_io->type;
		return 0;
	}

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
		/* IOs we can't emulate */
		return -EINVAL;
		break;
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		/* IOs we don't emulate */
		return -EINVAL;
		break;
	case SPDK_BDEV_IO_TYPE_UNMAP:
		/* Turn UNMAP into WRITE_ZEROES */
		if (spdk_bdev_io_type_supported(target, SPDK_BDEV_IO_TYPE_WRITE_ZEROES)) {
			io_ctx->type = SPDK_BDEV_IO_TYPE_WRITE_ZEROES;
			return 0;
		}
		return -EINVAL;
		break;
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_RESET:
		/* IOs we just drop if the target doesn't support them */
		io_ctx->target_noop = true;
		return 0;
		break;
	default:
		SPDK_ERRLOG("unknown I/O type %d (%s)\n",
			    bdev_io->type, spdk_bdev_io_type_enum_name[bdev_io->type]);
		return -EINVAL;
	}
}

/* Called when we submit or resubmit an IO from this module. The driver IO context is already initialized
 * and may contain state we need */
void
vbdev_redirector_resubmit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);
	struct redirector_bdev_io *io_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;
	int rc = 0;

	assert(is_redirector_io(bdev_io));
	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "[%s] ch=%p bdev_io=%p align=%"PRIu32"\n",
			      rd_th_name(), ch, bdev_io, rd_node->redirector_bdev.required_alignment);
	}
	if (RD_IO_ALIGN_ASSERTS && !rd_node->redirector_bdev.required_alignment == 0) {
		assert((bdev_io->u.bdev.offset_blocks * rd_node->redirector_bdev.blocklen)
		       % spdk_bdev_get_buf_align(&rd_node->redirector_bdev) == 0);
		assert(((bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks)
			* rd_node->redirector_bdev.blocklen)
		       % spdk_bdev_get_buf_align(&rd_node->redirector_bdev) == 0);
	}
	/* May queue the IO on the target if the target QD has been reached */
	vbdev_redirector_io_assign_target(ch, bdev_io);
	if (io_ctx->target_index_assigned &&
	    (RD_DEBUG_LOG_TARGET_TRANSLATION || RD_DEBUG_LOG_CHANNEL_STUFF)) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s: type=%s target=%s (index=%d in_flight=%d max_qd=%d) "
			      "LBA=%"PRId64" blocks=%"PRId64" target LBA=%"PRId64" "
			      "io=%p rd_ioctx=%p%s\n",
			      rd_node->config->redirector_name,
			      spdk_bdev_io_type_name[bdev_io->type],
			      rd_node->targets[io_ctx->target_index].target_config->name,
			      io_ctx->target_index,
			      rd_ch->targets[io_ctx->target_index].ios_in_flight,
			      rd_ch->targets[io_ctx->target_index].max_qd,
			      bdev_io->u.bdev.offset_blocks,
			      bdev_io->u.bdev.num_blocks,
			      io_ctx->target_offset, bdev_io, io_ctx,
			      io_ctx->is_queued ? " QUEUED" : "");
	}
	if (spdk_unlikely(io_ctx->is_queued)) {
		return;
	}
	rc = vbdev_redirector_translate_target_io_type(rd_node->targets[io_ctx->target_index].bdev,
			bdev_io);
	if (spdk_unlikely(rc)) {
		SPDK_ERRLOG("redirector %s: I/O type %s not supported by target %s\n",
			    rd_node->config->redirector_name,
			    spdk_bdev_io_type_enum_name[bdev_io->type],
			    rd_node->targets[io_ctx->target_index].bdev->name);
		vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	if (spdk_unlikely(io_ctx->target_noop)) {
		if (RD_DEBUG_LOG_IO_TYPE_TRANSLATION) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "redirector %s: I/O type %s is a no-op on target %s\n",
				      rd_node->config->redirector_name,
				      spdk_bdev_io_type_enum_name[bdev_io->type],
				      rd_node->targets[io_ctx->target_index].bdev->name);
		}
		vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
		return;
	}
	if (bdev_io->type != io_ctx->type) {
		if (RD_DEBUG_LOG_IO_TYPE_TRANSLATION) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s: type %s translated to %s on target %s "
				      "LBA=%"PRId64" blocks=%"PRId64" target LBA=%"PRId64" "
				      "io=%p rd_ioctx=%p\n",
				      rd_node->config->redirector_name,
				      spdk_bdev_io_type_name[bdev_io->type],
				      spdk_bdev_io_type_name[io_ctx->type],
				      rd_node->targets[io_ctx->target_index].bdev->name,
				      bdev_io->u.bdev.offset_blocks,
				      bdev_io->u.bdev.num_blocks,
				      io_ctx->target_offset, bdev_io, io_ctx);
		}
	}
	/* IO type to target may have been translated */
	switch (io_ctx->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		if (bdev_io->u.bdev.iovs[0].iov_base == NULL) {
			if (RD_DEBUG_LOG_TARGET_TRANSLATION) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Getting buffer: Redirector %s: type=%s target=%s "
					      "LBA=%"PRId64" blocks=%"PRId64" target LBA=%"PRId64" "
					      "io=%p rd_ioctx=%p%s\n",
					      rd_node->config->redirector_name,
					      spdk_bdev_io_type_name[io_ctx->type],
					      rd_node->targets[io_ctx->target_index].bdev->name,
					      bdev_io->u.bdev.offset_blocks,
					      bdev_io->u.bdev.num_blocks,
					      io_ctx->target_offset, bdev_io, io_ctx,
					      io_ctx->is_queued ? " QUEUED" : "");
			}
			spdk_bdev_io_get_buf(bdev_io, rd_read_get_buf_cb,
					     bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen);
		} else {
			rd_read_get_buf_cb(ch, bdev_io, true);
		}
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
		rc = spdk_bdev_writev_blocks(rd_node->targets[io_ctx->target_index].desc,
					     rd_ch->targets[io_ctx->target_index].ch, bdev_io->u.bdev.iovs,
					     bdev_io->u.bdev.iovcnt, io_ctx->target_offset,
					     bdev_io->u.bdev.num_blocks, _rd_complete_io,
					     bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		rc = spdk_bdev_write_zeroes_blocks(rd_node->targets[io_ctx->target_index].desc,
						   rd_ch->targets[io_ctx->target_index].ch,
						   io_ctx->target_offset,
						   bdev_io->u.bdev.num_blocks,
						   _rd_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_UNMAP:
		rc = spdk_bdev_unmap_blocks(rd_node->targets[io_ctx->target_index].desc,
					    rd_ch->targets[io_ctx->target_index].ch,
					    io_ctx->target_offset,
					    bdev_io->u.bdev.num_blocks,
					    _rd_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_FLUSH:
		rc = spdk_bdev_flush_blocks(rd_node->targets[io_ctx->target_index].desc,
					    rd_ch->targets[io_ctx->target_index].ch,
					    io_ctx->target_offset,
					    bdev_io->u.bdev.num_blocks,
					    _rd_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_NVME_ADMIN:
		rc = vbdev_redirector_process_nvme_admin_cmd(ch, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_RESET:
		/* Reset has to go to all target bdevs */
		_redirector_bdev_submit_reset_request(ch, bdev_io);
		break;
	default:
		SPDK_ERRLOG("redirector: unknown I/O type %d (%s)\n",
			    io_ctx->type, spdk_bdev_io_type_enum_name[io_ctx->type]);
		vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	if (spdk_unlikely(rc != 0)) {
		vbdev_redirector_io_unassign_target(ch, bdev_io);
		if (rc == -ENOMEM) {
			/* Queue the IO for a buffer. The target QD queue is a different mechanism */
			io_ctx->ch = ch;
			vbdev_redirector_queue_io(bdev_io);
		} else {
			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
			vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}

/* We'll just call the target bdev and let it answer however if we were more
 * restrictive for some reason (or less) we could get the response back
 * and modify according to our purposes.
 */
bool
vbdev_redirector_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;

	switch (io_type) {
	case SPDK_BDEV_IO_TYPE_READ:
	case SPDK_BDEV_IO_TYPE_WRITE:
	case SPDK_BDEV_IO_TYPE_UNMAP:
	case SPDK_BDEV_IO_TYPE_FLUSH:
	case SPDK_BDEV_IO_TYPE_RESET:
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
	case SPDK_BDEV_IO_TYPE_NVME_ADMIN:
		return true;
	case SPDK_BDEV_IO_TYPE_NVME_IO:
	case SPDK_BDEV_IO_TYPE_NVME_IO_MD:
	case SPDK_BDEV_IO_TYPE_ZCOPY:
	default:
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s: type=%s not supported\n",
			      rd_node->config->redirector_name,
			      spdk_bdev_io_type_name[io_type]);
		return false;
	}
}
