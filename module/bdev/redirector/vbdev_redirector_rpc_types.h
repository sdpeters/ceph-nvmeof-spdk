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

#ifndef SPDK_VBDEV_REDIRECTOR_RPC_TYPES_H
#define SPDK_VBDEV_REDIRECTOR_RPC_TYPES_H

/* #include "spdk/bdev_module.h" */
#include "vbdev_redirector_types.h"
#include "vbdev_redirector_enum_names.h"

struct rpc_construct_redirector_default_targets {
	/* Number of default targets */
	size_t           num_default_targets;

	/* List of default target names */
	char             *default_target_names[REDIRECTOR_MAX_TARGET_BDEVS];
};

struct rpc_construct_redirector_size_config {
	uint64_t		blockcnt;		/* Number of blocks */
	uint32_t		blocklen;		/* Bytes per block */
	uint32_t		required_alignment;	/* In bytes. Will be rounded down to a power of two */
	uint32_t		optimal_io_boundary;	/* In bytes. Will be rounded down to the block boundary */
};

struct rpc_construct_redirector_bdev {
	char *name;
	struct spdk_uuid uuid;
	char *nqn;
	struct rpc_construct_redirector_size_config size_config;
	bool size_configured;	/* vs. inherited from another redirector */
	struct rpc_construct_redirector_default_targets default_targets;
};

struct rpc_delete_redirector {
	char *name;
};

struct rpc_redirector_add_target {
	char *redirector_name;
	char *target_name;
	bool persistent;	/* Retain this target in the redirector configuratoin */
	bool required;		/* This target must be present before the redirector can start */
	bool redirector;	/* This target is a redirector */
	bool dont_probe;	/* Don't probe this target to determine if it's a redirector */
};

struct rpc_redirector_remove_target {
	char *redirector_name;
	char *target_name;
	bool retain_hints;	/* Do not delete the hints pointing to this target */
};

struct rpc_redirector_add_hint {
	char *redirector_name;
	char *target_name;
	uint64_t start_lba;
	uint64_t blocks;
	uint64_t target_start_lba;
	bool persistent;
	bool authoritative;
};

struct rpc_redirector_remove_hint {
	char *redirector_name;
	char *target_name;
	uint64_t start_lba;
	uint64_t blocks;
};

struct rpc_redirector_add_hash_hint {
	char *redirector_name;
	char *hash_hint_file;
	bool persistent;
	bool authoritative;
};

struct rpc_redirector_hash_hint_label_params {
	void *unused;
};

struct rpc_redirector_hash_hint_nqn_table {
	size_t           num_nqns;
	char             *nqns[];
};

struct rpc_redirector_hash_hint_nqn_table *alloc_rpc_redirector_hash_hint_nqn_table(
	size_t num_nqns);

void free_rpc_redirector_hash_hint_nqn_table(struct rpc_redirector_hash_hint_nqn_table *nqn_table);

struct rpc_redirector_hash_hint_hash_table {
	size_t           num_buckets;
	uint16_t         buckets[REDIRECTOR_HASH_HINT_MAX_HASH_TABLE_SIZE];
};

static inline void
rpc_redirector_hash_hint_hash_table_destruct(struct rpc_redirector_hash_hint_hash_table *hash_table)
{ /* No-op */ }

struct rpc_redirector_hash_hint_hash_table *alloc_rpc_redirector_hash_hint_hash_table(
	size_t num_nqns);

void free_rpc_redirector_hash_hint_hash_table(struct rpc_redirector_hash_hint_hash_table
		*hash_table);

struct rpc_redirector_hash_hint_params {
	struct rpc_redirector_hash_hint_label_params label;
	struct spdk_uuid ln_nguid;
	char *object_name_format;
	char *hash_fn;
	uint64_t ns_bytes;
	uint64_t object_bytes;
	struct rpc_redirector_hash_hint_nqn_table *nqn_table;
	struct rpc_redirector_hash_hint_hash_table *hash_table;
};

struct rpc_redirector_remove_hash_hint {
	char *redirector_name;
};

#endif /* SPDK_VBDEV_REDIRECTOR_RPC_TYPES_H */
