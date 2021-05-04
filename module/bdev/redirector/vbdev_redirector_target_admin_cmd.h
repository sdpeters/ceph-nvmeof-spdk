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

#ifndef SPDK_VBDEV_REDIRECTOR_TARGET_ADMIN_CMD_H
#define SPDK_VBDEV_REDIRECTOR_TARGET_ADMIN_CMD_H

#include "spdk/likely.h"
#include "spdk/env.h"
#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"

typedef char redirector_admin_cmd_ctx_data[4096];

struct redirector_admin_cmd_ctx {
	redirector_admin_cmd_ctx_data *data;
	struct redirector_bdev *rd_node;
	size_t target_bdev_index;
	struct spdk_io_channel *ch;
	void *cb_ctx;
	struct spdk_bdev_desc *self_desc;
};

static inline void *
rd_alloc_rdmaable(size_t size)
{
	return spdk_zmalloc(size, RD_ADMIN_CMD_ALIGN, NULL,
			    SPDK_ENV_SOCKET_ID_ANY, (SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE));
}

static inline struct spdk_nvme_cmd *
rd_alloc_nvme_cmd(void)
{
	struct spdk_nvme_cmd *cmd;

	cmd = rd_alloc_rdmaable(sizeof(*cmd));
	return cmd;
}

static inline redirector_admin_cmd_ctx_data *
rd_alloc_nvme_admin_cmd_ctx_data(void)
{
	redirector_admin_cmd_ctx_data *data;

	data = rd_alloc_rdmaable(sizeof(*data));
	return data;
}

void free_redirector_admin_cmd_ctx(struct redirector_admin_cmd_ctx *ctx);

void redirector_schedule_tgt_adm_cmd_in_flight_cpl(struct redirector_bdev *rd_node,
		redirector_completion_cb cb_fn, void *cb_ctx);

int
vbdev_redirector_send_admin_cmd(struct redirector_bdev *rd_node,
				size_t target_bdev_index,
				struct spdk_nvme_cmd *cmd,
				spdk_bdev_io_completion_cb cb,
				void *cb_ctx);

#endif /* SPDK_VBDEV_REDIRECTOR_TARGET_ADMIN_CMD_H */
