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

#ifndef SPDK_VBDEV_REDIRECTOR_HINTS_H
#define SPDK_VBDEV_REDIRECTOR_HINTS_H

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"

extern const GDestroyNotify location_hint_destroy_fn;
extern const GCompareDataFunc location_hint_data_compare_fn;

struct location_hint *
alloc_simple_hint(const uint64_t start_lba,
		  const uint64_t blocks,
		  const char *target_name,
		  const uint64_t target_start_lba,
		  const char *rx_target,
		  const bool persistent,
		  const bool authoritative);

struct location_hint *
alloc_hash_hint(const rd_hash_fn_id_t hash_fn,
		const uint64_t object_bytes,
		const char *object_name_format,
		struct nqn_list *nqn_list,
		struct hash_hint_table *hash_table,
		const char *rx_target,
		const bool persistent,
		const bool authoritative);

struct nqn_list *
alloc_nqn_list(const struct rpc_redirector_hash_hint_nqn_table *rpc_nqn_table);

struct nqn_list *
duplicate_nqn_list(const struct nqn_list *old_nqn_list);

struct hash_hint_table *
alloc_hash_hint_table(const struct rpc_redirector_hash_hint_hash_table *rpc_hash_table,
		      const struct rpc_redirector_hash_hint_nqn_table *rpc_nqn_table);

struct hash_hint_table *
duplicate_hash_hint_table(const struct hash_hint_table *old_table);

void free_hash_hint_table(struct hash_hint_table *hash_table);

void free_nqn_list(struct nqn_list *nqn_list);

void
_rd_debug_log_hint(const char *func, char *description, struct location_hint *hint);

static inline void
rd_debug_log_hint(const bool enable, const char *func, char *description,
		  struct location_hint *hint)
{
	if (enable) {
		_rd_debug_log_hint(func, description, hint);
	}
}

void
redirector_config_remove_hints_to_target(struct redirector_config *config, const char *target_name);

void
redirector_config_remove_hints_from_target(struct redirector_config *config,
		const char *target_name);

int
redirector_add_hint_rpc(struct redirector_config *config,
			const uint64_t start_lba,
			const uint64_t blocks,
			const char *target_name,
			const uint64_t target_start_lba,
			const bool persistent,
			const bool authoritative,
			const bool update_now);

int
redirector_add_hint_learned(struct redirector_config *config,
			    const uint64_t start_lba,
			    const uint64_t blocks,
			    const char *target_name,
			    const uint64_t target_start_lba,
			    const char *rx_target,
			    const bool update_now);

int
redirector_remove_hint(struct redirector_config *config,
		       const uint64_t start_lba,
		       const uint64_t blocks,
		       const char *target_name);

int
redirector_add_hash_hint_rpc(struct rpc_redirector_add_hash_hint *req,
			     struct rpc_redirector_hash_hint_params *hint_params,
			     const bool update_now);

int
redirector_add_hash_hint_learned(struct redirector_config *config,
				 rd_hash_fn_id_t hash_fn,
				 uint64_t object_bytes,
				 const char *object_name_format,
				 struct nqn_list *nqn_list,
				 struct hash_hint_table *hash_table,
				 const char *rx_target,
				 const bool update_now);

int
redirector_remove_hash_hint(struct redirector_config *config);

#endif /* SPDK_VBDEV_REDIRECTOR_HINTS_H */
