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

#ifndef SPDK_VBDEV_REDIRECTOR_INTERNAL_H
#define SPDK_VBDEV_REDIRECTOR_INTERNAL_H

#include "spdk/bdev_module.h"
#include "vbdev_redirector_debug.h"
#include "vbdev_redirector_rpc_types.h"
#include "spdk_internal/log.h"

#define RD_NQN_PREFIX "nqn."

#define RD_ADMIN_CMD_ALIGN SPDK_CACHE_LINE_SIZE

TAILQ_HEAD(redirector_all_config_tailq, redirector_config);
extern struct redirector_all_config_tailq g_redirector_config;

TAILQ_HEAD(redirector_all_tailq, redirector_bdev);
extern struct redirector_all_tailq g_redirector_bdevs;

extern struct spdk_bdev_module redirector_if;

extern bool g_shutdown_started;

const char *rd_th_name(void);

typedef void (*redirector_completion_cb)(void *cb_ctx, int rc);

extern const struct spdk_uuid null_uuid;

static inline bool
uuids_match(const struct spdk_uuid *lhs, const struct spdk_uuid *rhs)
{
	return (0 == spdk_uuid_compare(lhs, rhs));
}

static inline bool
uuid_zero(const struct spdk_uuid *uuid)
{
	return uuids_match(uuid, &null_uuid);
}

static inline bool
uuid_not_zero(const struct spdk_uuid *uuid)
{
	return !uuid_zero(uuid);
}

static inline bool
rd_uuid_known(const struct redirector_config *config)
{
	/* Redirector UUID is known if it's not null */
	return uuid_not_zero(&config->uuid);
}

typedef void (*vbdev_redirector_remove_target_cb)(void *cb_ctx, int rc);

struct location_hint *alloc_location_hint(void);
void free_location_hint(struct location_hint *hint);

void redirector_call_completions(GSList **pcompletions, const int status);

int vbdev_redirector_register(struct redirector_config *config);

/**
 * Create new redirector bdev.
 *
 * \return 0 on success, other on failure.
 */
int create_redirector(const struct rpc_construct_redirector_bdev *req);

/**
 * Delete redirector name and bdev (if it exists yet)
 *
 * \param cb_fn Function to call after deletion.
 * \param cb_arg Argument to pass to cb_fn.
 */
int delete_redirector(const struct rpc_delete_redirector *req, const spdk_bdev_unregister_cb cb_fn,
		      void *cb_arg);

int vbdev_redirector_destruct(void *ctx);

int vbdev_redirector_get_normal_target_qd(void);

struct redirector_config *vbdev_redirector_find_config(const char *redirector_name);

int vbdev_redirector_register_target(const char *target_name, struct spdk_bdev *bdev);

void
vbdev_redirector_update_locations(struct redirector_bdev *bdev);

void
vbdev_redirector_update_channel_state(struct redirector_bdev *bdev,
				      redirector_completion_cb cb_fn, void *cb_ctx);

void
vbdev_redirector_io_complete(struct spdk_bdev_io *orig_bdev_io, int status);

static inline uint64_t
redirector_max_blocks(struct redirector_bdev *bdev)
{
	return bdev->redirector_bdev.blockcnt;
}

void vbdev_redirector_resubmit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io);

void redirector_schedule_completion(GSList **pcompletions, redirector_completion_cb cb_fn,
				    void *cb_ctx);

static inline bool
is_redirector_io(const struct spdk_bdev_io *bdev_io)
{
	return (bdev_io->bdev && bdev_io->bdev->module == &redirector_if);
}

static inline bool
vbdev_redirector_io_requires_target(struct spdk_bdev_io *bdev_io)
{
	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_NVME_ADMIN:
	case SPDK_BDEV_IO_TYPE_RESET:
		return false;
		break;
	default:
		return true;
		break;
	}
}

void
__vbdev_redirector_io_unassign_assigned_target(struct spdk_io_channel *ch,
		struct spdk_bdev_io *bdev_io,
		bool io_completed);

static inline void
_vbdev_redirector_io_unassign_target(struct spdk_io_channel *ch,
				     struct spdk_bdev_io *bdev_io,
				     bool io_completed)
{
	struct redirector_bdev_io	    *rd_ctx = (struct redirector_bdev_io *)bdev_io->driver_ctx;

	if (RD_DEBUG_LOG_CHANNEL_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "ch=%p bdev_io=%p rd_ctx=%p\n", ch, bdev_io, rd_ctx);
	}

	assert(is_redirector_io(bdev_io));
	if (!vbdev_redirector_io_requires_target(bdev_io)) {
		return;
	}

	if (rd_ctx->target_index_assigned) {
		__vbdev_redirector_io_unassign_assigned_target(ch, bdev_io, io_completed);
	}
}

static inline void
vbdev_redirector_io_unassign_target(struct spdk_io_channel *ch,
				    struct spdk_bdev_io *bdev_io)
{
	_vbdev_redirector_io_unassign_target(ch, bdev_io, false);
}

/* During init we'll be asked how much memory we'd like passed to us
 * in bev_io structures as context. Here's where we specify how
 * much context we want per IO.
 */
static inline int
vbdev_redirector_get_ctx_size(void)
{
	return sizeof(struct redirector_bdev_io);
}

#endif /* SPDK_VBDEV_REDIRECTOR_INTERNAL_H */
