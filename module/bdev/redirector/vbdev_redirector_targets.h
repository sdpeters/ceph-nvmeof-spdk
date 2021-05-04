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

#ifndef SPDK_VBDEV_REDIRECTOR_TARGETS_H
#define SPDK_VBDEV_REDIRECTOR_TARGETS_H

#include "spdk/likely.h"
#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"

extern const GDestroyNotify redirector_target_destroy_fn;

static inline bool
rd_target_uuid_known(const struct redirector_target *target)
{
	/* Target UUID is known if it's not null */
	return uuid_not_zero(&target->uuid);
}

static inline bool
target_ns_uuid_matches_rd(const struct redirector_config *config,
			  const struct redirector_target *target)
{
	/* Unknown UUIDs don't match anything */
	return (uuid_not_zero(&config->uuid) &&	uuids_match(&config->uuid, &target->uuid));
}

/* Targets that never get their index unassigned */
static inline bool
target_index_sticky(const struct redirector_target *target)
{
	return target && (target->auth_target ||
			  (target->redirector && target->persistent));
}

static inline bool
target_index_unassigned(const struct redirector_target *target)
{
	return !target || (target->target_index == -1);
}

int
redirector_target_set_nqn(struct redirector_config *config,
			  struct redirector_target *target,
			  char *nqn_buf, size_t nqn_len);

struct redirector_target *
alloc_redirector_target(const char *target_name,
			const int priority,
			const bool persistent,
			const bool required,
			const bool redirector,
			const bool dont_probe);

/* True if target with specified index can't be used at all by a rule */
static inline bool
rd_target_unusable(int target_index)
{
	return (target_index == -1);
}

/* True if target with specified index can't currently complete any IO to this namespace */
static inline bool
rd_target_unavailable(struct redirector_bdev *rd_node, int target_index)
{
	if (spdk_unlikely(rd_target_unusable(target_index))) {
		return true;
	} else {
		struct redirector_bdev_target *rbt = &rd_node->targets[target_index];
		return ((rbt->max_qd == 0) ||
			(rbt->desc == 0) ||
			(rbt->drain) ||
			(rbt->free_index) ||
			(rbt->target_config && rbt->target_config->uuid_mismatch));
	}
}

GSequenceIter *
redirector_config_find_first_target_by_nqn_iter(const struct redirector_config *config,
		const char *nqn);

GSequenceIter *
redirector_config_find_next_target_by_nqn_iter(const struct redirector_config *config,
		GSequenceIter *iter);

struct redirector_target *
vbdev_redirector_default_target(struct redirector_config *config);

void
redirector_config_add_target(struct redirector_config *config, struct redirector_target *target);

int
redirector_config_remove_target(struct redirector_config *config, const char *target_name);

int
redirector_add_target(struct rpc_redirector_add_target *req);

void
redirector_remove_target(struct redirector_config *config,
			 const char *target_name,
			 const bool retain_hints,
			 const bool remain_configured,
			 const bool hotremove,
			 const vbdev_redirector_remove_target_cb cb_fn,
			 void *cb_ctx);

struct redirector_target *
redirector_config_find_target(const struct redirector_config *config, const char *name);

#endif /* SPDK_VBDEV_REDIRECTOR_TARGETS_H */
