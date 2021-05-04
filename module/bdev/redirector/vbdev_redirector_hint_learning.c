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
 * Handles learning hints from targets, including periodically polling
 * for additional or replacement hints from each target. When the
 * redirector can send async change notificatoins for the location
 * hint log page, we'll react to those here too (and stop polling).
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector_target_admin_cmd.h"
#include "vbdev_redirector_hint_learning.h"
#include "vbdev_redirector_nvme_hints.h"
#include "vbdev_redirector.h"
#include "spdk/bdev.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

struct redirector_get_hints_ctx {
	size_t target_bdev_index;
	uint64_t page_offset;
	struct spdk_nvme_cmd *get_log_page_cmd_buf;
	struct {
		bool get_log_page_success;
		bool page_read_complete;
		struct rd_hint_log_page_header page_header;
		struct rd_hint_buf_stream bufs;
	} hint_page;
	struct {
		bool get_log_page_success;
		bool page_read_complete;
		bool page_read_success;
		struct rd_nqn_list_log_page page_header;
		struct rd_nqn_list_buf_stream bufs;
		struct nqn_list *nqn_list;
	} nqn_list_page;
	struct {
		bool get_log_page_success;
		bool page_read_complete;
		bool page_read_success;
		struct rd_hash_table_log_page page_header;
		struct rd_hash_table_buf_stream bufs;
		struct hash_hint_table *hash_table;
	} hash_table_page;
	bool table_page_reads_complete;
	struct redirector_admin_cmd_ctx *prev_get_log_page_ctx;
	bool log_pages_valid;
	struct hash_hint_nvme_state log_pages; /* When table reading is necessary */
	bool destroyed;
};

static int
vbdev_redirector_get_hash_table_region(struct redirector_bdev *rd_node,
				       struct redirector_get_hints_ctx *get_hints_ctx, uint64_t offset);

static int
vbdev_redirector_get_nqn_list_region(struct redirector_bdev *rd_node,
				     struct redirector_get_hints_ctx *get_hints_ctx, uint64_t offset);

static int
vbdev_redirector_get_hints_region(struct redirector_bdev *rd_node, size_t target_bdev_index,
				  struct redirector_get_hints_ctx *get_hints_ctx, uint64_t offset);

static void
vbdev_redirector_target_got_hints(struct redirector_target *target, bool success)
{
	if (!target->get_hints_once) {
		/* Only set the redirector detection flags the first time we read hints */
		target->get_hints_once = true;
		target->confirmed_redir = success;
		target->confirmed_not_redir = !success;
	}
}

static void
free_redirector_get_hints_ctx(struct redirector_get_hints_ctx *ctx)
{
	if (!ctx) { return; }
	assert(!ctx->destroyed);
	ctx->destroyed = true;
	if (ctx->get_log_page_cmd_buf) {
		spdk_free(ctx->get_log_page_cmd_buf);
	}
	if (ctx->nqn_list_page.nqn_list) {
		free_nqn_list(ctx->nqn_list_page.nqn_list);
	}
	rd_hint_buf_stream_destruct(&ctx->hint_page.bufs);
	rd_nqn_list_buf_stream_destruct(&ctx->nqn_list_page.bufs);
	free_redirector_admin_cmd_ctx(ctx->prev_get_log_page_ctx);
	free(ctx);
}

/*
 * Applies results of all hint and support log page reading, and applies the
 * learned hints.
 *
 * Takes custody of get_hints_ctx and adm_cmd_ctx. Caller should not
 * dereference rd_node or rd_target on return
 */
static void
vbdev_redirector_apply_learned_hints(struct redirector_bdev *rd_node,
				     struct redirector_bdev_target *rd_target,
				     struct redirector_get_hints_ctx *get_hints_ctx,
				     struct redirector_admin_cmd_ctx *adm_cmd_ctx)
{
	struct redirector_config *config = rd_node->config;
	struct redirector_target *target_config = rd_target->target_config;

	if (RD_DEBUG_LOG_HINT_LEARNING) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s applying learned hints from target %s\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
	}

	assert(get_hints_ctx);
	assert(get_hints_ctx->hint_page.page_read_complete);
	assert(get_hints_ctx->table_page_reads_complete);

	if (get_hints_ctx->hint_page.bufs.stream.success && get_hints_ctx->hint_page.bufs.changed) {
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s all hint log page reads from target %s completed with "
				      "changes. Applying learned hints\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
		}

		rd_target->target_config->hint_stats.hint_update_count++;
		rd_target->target_config->hint_stats.generation = get_hints_ctx->hint_page.page_header.generation;
		if (!get_hints_ctx->hint_page.page_header.retain_prev) {
			rd_target->target_config->hint_stats.hint_replace_count++;

			if (RD_DEBUG_LOG_HINT_LEARNING) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s replacing all hints from target %s (removing)\n",
					      config->redirector_name,
					      spdk_bdev_get_name(rd_target->bdev));
			}
			redirector_config_remove_hints_from_target(config, target_config->name);
			if (target_config->nqn) {
				redirector_config_remove_hints_from_target(config, target_config->nqn);
			}
		}
		/* Apply decoded hints in the order they appeared*/
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s replacing all hints from target %s (adding)\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
		}

		struct location_hint *decoded_hint;
		struct nqn_list *nqn_list;
		struct hash_hint_table *hash_table;

		while (NULL != (decoded_hint = rd_hint_buf_stream_consume_first_hint(
						       &get_hints_ctx->hint_page.bufs))) {
			rd_debug_log_hint(RD_DEBUG_LOG_HINT_LEARNING, __func__, " learning: ", decoded_hint);
			switch (decoded_hint->hint_type) {
			case RD_HINT_TYPE_SIMPLE_NQN:
				redirector_add_hint_learned(rd_node->config, decoded_hint->extent.start_lba,
							    decoded_hint->extent.blocks,
							    location_hint_target_name(decoded_hint),
							    location_hint_target_start_lba(decoded_hint),
							    decoded_hint->rx_target, false);
				break;
			case RD_HINT_TYPE_HASH_NQN_TABLE:
				nqn_list = alloc_nqn_list(get_hints_ctx->nqn_list_page.bufs.rpc_table);
				if (!nqn_list) {
					SPDK_ERRLOG("Redirector %s failed to allocate NQN list\n",
						    config->redirector_name);
					break;
				}

				hash_table = alloc_hash_hint_table(get_hints_ctx->hash_table_page.bufs.rpc_table,
								   get_hints_ctx->nqn_list_page.bufs.rpc_table);
				if (!hash_table) {
					SPDK_ERRLOG("Redirector %s failed to allocate hash table\n",
						    config->redirector_name);
					free(nqn_list);
					break;
				}

				/* TODO: Ignore hint if generated table digests differ from those in the page header */
				redirector_add_hash_hint_learned(rd_node->config,
								 decoded_hint->hash.hash_function_id,
								 decoded_hint->hash.object_bytes,
								 decoded_hint->hash.object_name_format,
								 nqn_list, hash_table,
								 decoded_hint->rx_target, false);
				break;
			case RD_HINT_TYPE_NONE:
			case RD_HINT_TYPE_SIMPLE_NQN_NS:
			case RD_HINT_TYPE_SIMPLE_NQN_ALT:
			case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
			case RD_HINT_TYPE_STRIPE_NQN:
			case RD_HINT_TYPE_STRIPE_NQN_NS:
			case RD_HINT_TYPE_DIFF_NQN_NS:
			case RD_HINT_TYPE_DIFF_HASH_NQN_TABLE:
			default:
				rd_debug_log_hint(RD_DEBUG_LOG_HINT_LEARNING, __func__, " skipping unsupported type: ",
						  decoded_hint);
				break;
			}
			free_location_hint(decoded_hint);
		}

		/* We update the applied rules just once when applying or replacing everything learned from a target */
		vbdev_redirector_update_locations(rd_node);
		vbdev_redirector_update_channel_state(rd_node, NULL, NULL);

		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s hint page from target %s processed all hints\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
	}

	assert(get_hints_ctx->hint_page.page_read_complete);
	assert(get_hints_ctx->table_page_reads_complete);

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s completed reading hints from target %s\n",
		      config->redirector_name,
		      spdk_bdev_get_name(rd_target->bdev));

	rd_target->reading_hints = false;
	free_redirector_get_hints_ctx(get_hints_ctx);
	free_redirector_admin_cmd_ctx(adm_cmd_ctx);
}

/*
 * Completes reading or re-reads the log pages containing tables for the learned hints
 *
 * Takes custody of get_hints_ctx and adm_cmd_ctx. Caller should not
 * dereference rd_node or rd_target on return
 */
static void
vbdev_redirector_read_hint_tables_cpl(struct redirector_bdev *rd_node,
				      struct redirector_bdev_target *rd_target,
				      struct redirector_get_hints_ctx *get_hints_ctx,
				      struct redirector_admin_cmd_ctx *adm_cmd_ctx)
{
	struct redirector_config *config = rd_node->config;

	assert(get_hints_ctx->hint_page.page_read_complete);
	assert(!get_hints_ctx->table_page_reads_complete);

	get_hints_ctx->table_page_reads_complete = true;
	if (RD_DEBUG_LOG_HINT_LEARNING) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s hint support page read from target %s completing\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
	}
	vbdev_redirector_apply_learned_hints(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
	return;
}

/*
 * Completes reading or re-reading the hash table log page
 *
 * Takes custody of get_hints_ctx and adm_cmd_ctx. Caller should not
 * dereference rd_node or rd_target on return
 */
static void
vbdev_redirector_get_hash_table_cpl(struct redirector_bdev *rd_node,
				    struct redirector_bdev_target *rd_target,
				    struct redirector_get_hints_ctx *get_hints_ctx,
				    struct redirector_admin_cmd_ctx *adm_cmd_ctx)
{
	struct redirector_config *config = rd_node->config;

	assert(get_hints_ctx->hint_page.page_read_complete);
	assert(get_hints_ctx->nqn_list_page.page_read_complete);
	assert(!get_hints_ctx->hash_table_page.page_read_complete);

	get_hints_ctx->hash_table_page.page_read_complete = true;
	if (RD_DEBUG_LOG_HINT_LEARNING) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s hash table page read from target %s completing\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
	}
	vbdev_redirector_read_hint_tables_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
	return;
}

static void
vbdev_redirector_get_hash_table_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct redirector_admin_cmd_ctx *adm_cmd_ctx = cb_arg;
	struct redirector_get_hints_ctx *get_hints_ctx = adm_cmd_ctx->cb_ctx;
	struct redirector_bdev *rd_node = adm_cmd_ctx->rd_node;
	struct redirector_config *config = rd_node->config;
	struct redirector_bdev_target *rd_target = &rd_node->targets[adm_cmd_ctx->target_bdev_index];
	struct redirector_target *target_config = rd_target->target_config;
	uint64_t page_offset = get_hints_ctx ? get_hints_ctx->page_offset : 0;
	uint32_t resp_cdw0;
	int resp_sct;
	int resp_sc;
	bool nvme_success;
	bool glp_success;

	spdk_bdev_io_get_nvme_status(bdev_io, &resp_cdw0, &resp_sct, &resp_sc);
	nvme_success = (resp_sct == SPDK_NVME_SCT_GENERIC) && (resp_sc == SPDK_NVME_SC_SUCCESS);
	glp_success = success && nvme_success;
	get_hints_ctx->hash_table_page.get_log_page_success = glp_success;

	if (!success || glp_success) {
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %sread hash table page from target %s\n",
				      config->redirector_name,
				      success ? "" : "FAILED to ",
				      spdk_bdev_get_name(rd_target->bdev));
		}
	} else {
		/* GLP returned an NVMe error from the far end */
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s %sread hash table page from target %s: %s, %s (%0xd)\n",
			      adm_cmd_ctx->rd_node->config->redirector_name,
			      glp_success ? "" : "FAILED to ",
			      spdk_bdev_get_name(rd_target->bdev),
			      get_spdk_nvme_status_code_type_name(resp_sct),
			      get_spdk_nvme_command_status_code_name(resp_sct, resp_sc),
			      resp_sc);
	}

	assert(!get_hints_ctx->hash_table_page.page_read_complete);
	if (!glp_success) {
		/* hash table reading fails */
		get_hints_ctx->hash_table_page.get_log_page_success = false;
		vbdev_redirector_get_hash_table_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	}
	assert(get_hints_ctx);

	/* Consume (parse) the location hints in the region of the hint page we just read. */
	if (page_offset == 0) {
		struct rd_hash_table_log_page *hash_table_page = (void *)adm_cmd_ctx->data;
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hash table page from target %s, gen=%"PRIu64", length=%"PRIu64"\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev),
				      hash_table_page->generation, hash_table_page->length);
		}
		if (hash_table_page->length < sizeof(struct rd_hash_table_log_page)) {
			if (RD_DEBUG_LOG_HINT_LEARNING) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s error processing hash table from target %s: bad page header length\n",
					      config->redirector_name,
					      spdk_bdev_get_name(rd_target->bdev));
			}
			/* hash table reading fails */
			get_hints_ctx->hash_table_page.page_read_success = false;
			vbdev_redirector_get_hash_table_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		}

		/* We consume the hash table page header here */
		get_hints_ctx->hash_table_page.page_header = *hash_table_page;
		get_hints_ctx->hash_table_page.bufs.stream.next.buf = &hash_table_page->nqns[0];
		/* Buf remaining is entire get_log_page_payload minus the header we consume here */
		get_hints_ctx->hash_table_page.bufs.stream.next.remaining = sizeof(adm_cmd_ctx->data) - sizeof(
					*hash_table_page);
		/* Hint list remaining may be greater or less than the payload */
		get_hints_ctx->hash_table_page.bufs.stream.page_remaining = hash_table_page->length - sizeof(
					*hash_table_page);
		assert(!get_hints_ctx->prev_get_log_page_ctx);
		assert(!get_hints_ctx->hash_table_page.bufs.stream.prev.buf);
		assert(get_hints_ctx->hash_table_page.bufs.stream.prev.remaining == 0);
		assert(!get_hints_ctx->hash_table_page.page_read_complete);
		get_hints_ctx->hash_table_page.bufs.rpc_table =
			alloc_rpc_redirector_hash_hint_hash_table(get_hints_ctx->hash_table_page.page_header.bucket_count);
		if (!get_hints_ctx->hash_table_page.bufs.rpc_table) {
			/* hash table reading fails */
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s failed to allocate hash table for target %s\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
			get_hints_ctx->hash_table_page.page_read_success = false;
			vbdev_redirector_get_hash_table_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		}
		vbdev_redirector_consume_hash_table(rd_node, target_config, &get_hints_ctx->hash_table_page.bufs);
	} else {
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hash table page from target %s continues at offset %"PRIu64"\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev),
				      page_offset);
		}
		assert(!get_hints_ctx->hash_table_page.page_read_complete);
		assert(get_hints_ctx->hash_table_page.bufs.rpc_table);
		/* The remaining part of next_buf becomes prev_buf */
		get_hints_ctx->hash_table_page.bufs.stream.prev.buf =
			get_hints_ctx->hash_table_page.bufs.stream.next.buf;
		get_hints_ctx->hash_table_page.bufs.stream.prev.remaining =
			get_hints_ctx->hash_table_page.bufs.stream.next.remaining;
		/* This payload (which has no header) is the next_buf */
		get_hints_ctx->hash_table_page.bufs.stream.next.buf = adm_cmd_ctx->data;
		get_hints_ctx->hash_table_page.bufs.stream.next.remaining = sizeof(adm_cmd_ctx->data);
		/* Consume hints, starting with any fragment remaining in prev_buf */
		assert(!get_hints_ctx->hash_table_page.page_read_complete);
		vbdev_redirector_consume_hash_table(rd_node, target_config, &get_hints_ctx->hash_table_page.bufs);
		/* Whatever was left in prev_buf must be consumed by this point */
		assert(get_hints_ctx->hash_table_page.bufs.stream.prev.remaining == 0);
		get_hints_ctx->hash_table_page.bufs.stream.prev.buf = NULL;
		free_redirector_admin_cmd_ctx(get_hints_ctx->prev_get_log_page_ctx);
		get_hints_ctx->prev_get_log_page_ctx = NULL;
	}

	if (!get_hints_ctx->hash_table_page.bufs.stream.success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s error processing hash table from target %s\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
		/* hash table reading fails */
		get_hints_ctx->hash_table_page.page_read_success = false;
		vbdev_redirector_get_hash_table_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	}

	if (get_hints_ctx->hash_table_page.bufs.stream.end_found) {
		/* hash table page reading ends. */
		get_hints_ctx->hash_table_page.bufs.stream.success = true;
		get_hints_ctx->hash_table_page.bufs.changed = true;
		vbdev_redirector_get_hash_table_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	} else {
		/* hash table page reading continues */
		int rc;
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hash table page from target %s reading page chunk\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
		}
		assert(!get_hints_ctx->prev_get_log_page_ctx);
		/* Admin cmd context retained in get_hints_ctx to preserve any hash bucket fragment remaining in it. */
		get_hints_ctx->prev_get_log_page_ctx = adm_cmd_ctx;
		rc = vbdev_redirector_get_hash_table_region(rd_node, get_hints_ctx,
				get_hints_ctx->page_offset + sizeof(adm_cmd_ctx->data));
		if (rc) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hash table page from target %s reading next page chunk failed\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
			/* hash table reading fails */
			get_hints_ctx->hash_table_page.get_log_page_success = false;
			vbdev_redirector_get_hash_table_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		} else {
			/* ctx and get_hints_ctx now in the custody of the next hint page chunk read, so we must not
			 * free them here */
			get_hints_ctx = NULL;
			adm_cmd_ctx = NULL;
			/* None of the rest of these are safe to use now either */
			rd_node = NULL;
			config = NULL;
			rd_target = NULL;
			target_config = NULL;
		}
	}

out:
	spdk_bdev_free_io(bdev_io);
}

/*
 * Reads the first chunk of a hash table log page
 */
static int
vbdev_redirector_get_hash_table_region(struct redirector_bdev *rd_node,
				       struct redirector_get_hints_ctx *get_hints_ctx, uint64_t offset)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[get_hints_ctx->target_bdev_index];
	struct spdk_nvme_cmd *cmd = NULL;
	int rc;
	uint32_t transfer;
	uint32_t num_dwords;

	assert(get_hints_ctx);
	assert(rd_target->target_config);
	assert(get_hints_ctx->hint_page.page_read_complete);
	transfer = sizeof(((struct redirector_admin_cmd_ctx *)NULL)->data);
	if (get_hints_ctx->get_log_page_cmd_buf) {
		cmd = get_hints_ctx->get_log_page_cmd_buf;
	} else {
		cmd = rd_alloc_nvme_cmd();
		if (!cmd) {
			return -ENOMEM;
		}
		get_hints_ctx->get_log_page_cmd_buf = cmd;
	}
	num_dwords = (transfer >> 2) - 1;
	cmd->opc = SPDK_NVME_OPC_GET_LOG_PAGE;
	/* cmd.nsid will be supplied from the nvme bdev */
	cmd->cdw10 = ((num_dwords & 0xFFFFu) << 16) + get_hints_ctx->log_pages.hash_table_log_page;
	cmd->cdw11 = (num_dwords >> 16) & 0xFFFFu;
	cmd->cdw12 = offset & 0xFFFFFFFFu;
	cmd->cdw13 = (offset >> 32) & 0xFFFFFFFFu;

	get_hints_ctx->page_offset = offset;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s reading hash table page from target %s\n",
		      rd_node->config->redirector_name,
		      spdk_bdev_get_name(rd_target->bdev));

	rc = vbdev_redirector_send_admin_cmd(rd_node, get_hints_ctx->target_bdev_index, cmd,
					     vbdev_redirector_get_hash_table_cb, get_hints_ctx);
	return rc;
}

/*
 * Completes reading or re-reads the nqn list log page
 *
 * Takes custody of get_hints_ctx and adm_cmd_ctx. Caller should not
 * dereference rd_node or rd_target on return
 */
static void
vbdev_redirector_get_nqn_list_cpl(struct redirector_bdev *rd_node,
				  struct redirector_bdev_target *rd_target,
				  struct redirector_get_hints_ctx *get_hints_ctx,
				  struct redirector_admin_cmd_ctx *adm_cmd_ctx)
{
	struct redirector_config *config = rd_node->config;
	int rc;

	assert(get_hints_ctx->hint_page.page_read_complete);
	assert(!get_hints_ctx->nqn_list_page.page_read_complete);

	get_hints_ctx->nqn_list_page.page_read_complete = true;
	if (RD_DEBUG_LOG_HINT_LEARNING) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s nqn list page read from target %s completing\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
	}
	rc = vbdev_redirector_get_hash_table_region(rd_node, get_hints_ctx, 0);
	if (rc) {
		get_hints_ctx->hash_table_page.get_log_page_success = false;
		vbdev_redirector_get_hash_table_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
	}

	free_redirector_admin_cmd_ctx(adm_cmd_ctx);
	return;
}

static void
vbdev_redirector_get_nqn_list_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct redirector_admin_cmd_ctx *adm_cmd_ctx = cb_arg;
	struct redirector_get_hints_ctx *get_hints_ctx = adm_cmd_ctx->cb_ctx;
	struct redirector_bdev *rd_node = adm_cmd_ctx->rd_node;
	struct redirector_config *config = rd_node->config;
	struct redirector_bdev_target *rd_target = &rd_node->targets[adm_cmd_ctx->target_bdev_index];
	struct redirector_target *target_config = rd_target->target_config;
	uint64_t page_offset = get_hints_ctx ? get_hints_ctx->page_offset : 0;
	uint32_t resp_cdw0;
	int resp_sct;
	int resp_sc;
	bool nvme_success;
	bool glp_success;

	spdk_bdev_io_get_nvme_status(bdev_io, &resp_cdw0, &resp_sct, &resp_sc);
	nvme_success = (resp_sct == SPDK_NVME_SCT_GENERIC) && (resp_sc == SPDK_NVME_SC_SUCCESS);
	glp_success = success && nvme_success;
	get_hints_ctx->nqn_list_page.get_log_page_success = glp_success;

	if (!success || glp_success) {
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %sread nqn list page from target %s\n",
				      config->redirector_name,
				      success ? "" : "FAILED to ",
				      spdk_bdev_get_name(rd_target->bdev));
		}
	} else {
		/* GLP returned an NVMe error from the far end */
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s %sread nqn list page from target %s: %s, %s (%0xd)\n",
			      adm_cmd_ctx->rd_node->config->redirector_name,
			      glp_success ? "" : "FAILED to ",
			      spdk_bdev_get_name(rd_target->bdev),
			      get_spdk_nvme_status_code_type_name(resp_sct),
			      get_spdk_nvme_command_status_code_name(resp_sct, resp_sc),
			      resp_sc);
	}

	assert(!get_hints_ctx->nqn_list_page.page_read_complete);
	if (!glp_success) {
		/* NQN list reading fails */
		get_hints_ctx->nqn_list_page.get_log_page_success = false;
		vbdev_redirector_get_nqn_list_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	}
	assert(get_hints_ctx);

	/* Consume (parse) the location hints in the region of the hint page we just read. */
	if (page_offset == 0) {
		struct rd_nqn_list_log_page *nqn_list_page = (void *)adm_cmd_ctx->data;
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn list page from target %s, gen=%"PRIu64", length=%"PRIu64"\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev),
				      nqn_list_page->generation, nqn_list_page->length);
		}
		if (nqn_list_page->length < sizeof(struct rd_nqn_list_log_page)) {
			if (RD_DEBUG_LOG_HINT_LEARNING) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s error processing nqn list from target %s: bad page header length\n",
					      config->redirector_name,
					      spdk_bdev_get_name(rd_target->bdev));
			}
			/* NQN list reading fails */
			get_hints_ctx->nqn_list_page.page_read_success = false;
			vbdev_redirector_get_nqn_list_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		}

		/* We consume the nqn list page header here */
		get_hints_ctx->nqn_list_page.page_header = *nqn_list_page;
		get_hints_ctx->nqn_list_page.bufs.stream.next.buf = &nqn_list_page->nqns[0];
		/* Buf remaining is entire get_log_page_payload minus the header we consume here */
		get_hints_ctx->nqn_list_page.bufs.stream.next.remaining = sizeof(adm_cmd_ctx->data) - sizeof(
					*nqn_list_page);
		/* Hint list remaining may be greater or less than the payload */
		get_hints_ctx->nqn_list_page.bufs.stream.page_remaining = nqn_list_page->length - sizeof(
					*nqn_list_page);
		assert(!get_hints_ctx->prev_get_log_page_ctx);
		assert(!get_hints_ctx->nqn_list_page.bufs.stream.prev.buf);
		assert(get_hints_ctx->nqn_list_page.bufs.stream.prev.remaining == 0);
		assert(!get_hints_ctx->nqn_list_page.page_read_complete);
		get_hints_ctx->nqn_list_page.bufs.rpc_table =
			alloc_rpc_redirector_hash_hint_nqn_table(get_hints_ctx->nqn_list_page.page_header.num_nqns);
		if (!get_hints_ctx->nqn_list_page.bufs.rpc_table) {
			/* NQN list reading fails */
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s failed to allocate nqn list for target %s\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
			get_hints_ctx->nqn_list_page.page_read_success = false;
			vbdev_redirector_get_nqn_list_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		}
		vbdev_redirector_consume_nqn_list(rd_node, target_config, &get_hints_ctx->nqn_list_page.bufs);
	} else {
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn list page from target %s continues at offset %"PRIu64"\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev),
				      page_offset);
		}
		assert(!get_hints_ctx->nqn_list_page.page_read_complete);
		assert(get_hints_ctx->nqn_list_page.bufs.rpc_table);
		/* The remaining part of next_buf becomes prev_buf */
		get_hints_ctx->nqn_list_page.bufs.stream.prev.buf =
			get_hints_ctx->nqn_list_page.bufs.stream.next.buf;
		get_hints_ctx->nqn_list_page.bufs.stream.prev.remaining =
			get_hints_ctx->nqn_list_page.bufs.stream.next.remaining;
		/* This payload (which has no header) is the next_buf */
		get_hints_ctx->nqn_list_page.bufs.stream.next.buf = adm_cmd_ctx->data;
		get_hints_ctx->nqn_list_page.bufs.stream.next.remaining = sizeof(adm_cmd_ctx->data);
		/* Consume hints, starting with any fragment remaining in prev_buf */
		assert(!get_hints_ctx->nqn_list_page.page_read_complete);
		vbdev_redirector_consume_nqn_list(rd_node, target_config, &get_hints_ctx->nqn_list_page.bufs);
		/* Whatever was left in prev_buf must be consumed by this point */
		assert(get_hints_ctx->nqn_list_page.bufs.stream.prev.remaining == 0);
		get_hints_ctx->nqn_list_page.bufs.stream.prev.buf = NULL;
		free_redirector_admin_cmd_ctx(get_hints_ctx->prev_get_log_page_ctx);
		get_hints_ctx->prev_get_log_page_ctx = NULL;
	}

	if (!get_hints_ctx->nqn_list_page.bufs.stream.success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s error processing nqn list from target %s\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
		/* nqn list reading fails */
		get_hints_ctx->nqn_list_page.page_read_success = false;
		vbdev_redirector_get_nqn_list_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	}

	if (get_hints_ctx->nqn_list_page.bufs.stream.end_found) {
		/* NQN list page reading ends. */
		get_hints_ctx->nqn_list_page.bufs.stream.success = true;
		get_hints_ctx->nqn_list_page.bufs.changed = true;
		vbdev_redirector_get_nqn_list_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	} else {
		/* NQN list page reading continues */
		int rc;
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn list page from target %s reading page chunk\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
		}
		assert(!get_hints_ctx->prev_get_log_page_ctx);
		/* Admin cmd context retained in get_hints_ctx to preserve any NQN fragment remaining in it. */
		get_hints_ctx->prev_get_log_page_ctx = adm_cmd_ctx;
		rc = vbdev_redirector_get_nqn_list_region(rd_node, get_hints_ctx,
				get_hints_ctx->page_offset + sizeof(adm_cmd_ctx->data));
		if (rc) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn listpage from target %s reading next page chunk failed\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
			/* NQN list reading fails */
			get_hints_ctx->nqn_list_page.get_log_page_success = false;
			vbdev_redirector_get_nqn_list_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		} else {
			/* ctx and get_hints_ctx now in the custody of the next hint page chunk read, so we must not
			 * free them here */
			get_hints_ctx = NULL;
			adm_cmd_ctx = NULL;
			/* None of the rest of these are safe to use now either */
			rd_node = NULL;
			config = NULL;
			rd_target = NULL;
			target_config = NULL;
		}
	}

out:
	spdk_bdev_free_io(bdev_io);
}

/*
 * Reads the first chunk of an NQN list log page
 */
static int
vbdev_redirector_get_nqn_list_region(struct redirector_bdev *rd_node,
				     struct redirector_get_hints_ctx *get_hints_ctx, uint64_t offset)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[get_hints_ctx->target_bdev_index];
	struct spdk_nvme_cmd *cmd = NULL;
	int rc;
	uint32_t transfer;
	uint32_t num_dwords;

	assert(get_hints_ctx);
	assert(rd_target->target_config);
	assert(get_hints_ctx->hint_page.page_read_complete);
	transfer = sizeof(((struct redirector_admin_cmd_ctx *)NULL)->data);
	if (get_hints_ctx->get_log_page_cmd_buf) {
		cmd = get_hints_ctx->get_log_page_cmd_buf;
	} else {
		cmd = rd_alloc_nvme_cmd();
		if (!cmd) {
			return -ENOMEM;
		}
		get_hints_ctx->get_log_page_cmd_buf = cmd;
	}
	num_dwords = (transfer >> 2) - 1;
	cmd->opc = SPDK_NVME_OPC_GET_LOG_PAGE;
	/* cmd.nsid will be supplied from the nvme bdev */
	cmd->cdw10 = ((num_dwords & 0xFFFFu) << 16) + get_hints_ctx->log_pages.nqn_list_log_page;
	cmd->cdw11 = (num_dwords >> 16) & 0xFFFFu;
	cmd->cdw12 = offset & 0xFFFFFFFFu;
	cmd->cdw13 = (offset >> 32) & 0xFFFFFFFFu;

	get_hints_ctx->page_offset = offset;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s reading nqn list page from target %s\n",
		      rd_node->config->redirector_name,
		      spdk_bdev_get_name(rd_target->bdev));

	rc = vbdev_redirector_send_admin_cmd(rd_node, get_hints_ctx->target_bdev_index, cmd,
					     vbdev_redirector_get_nqn_list_cb, get_hints_ctx);
	return rc;
}

/*
 * Reads or re-reads the log pages containing tables for the learned hints
 *
 * Takes custody of get_hints_ctx and adm_cmd_ctx. Caller should not
 * dereference rd_node or rd_target on return
 */
static void
vbdev_redirector_read_hint_tables(struct redirector_bdev *rd_node,
				  struct redirector_bdev_target *rd_target,
				  struct redirector_get_hints_ctx *get_hints_ctx,
				  struct redirector_admin_cmd_ctx *adm_cmd_ctx)
{
	struct redirector_config *config = rd_node->config;
	int rc;

	assert(get_hints_ctx->hint_page.page_read_complete);
	assert(!get_hints_ctx->table_page_reads_complete);
	assert(get_hints_ctx->log_pages_valid);

	if (RD_DEBUG_LOG_HINT_LEARNING) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s reading hint tables %d and %d from target %s\n",
			      config->redirector_name,
			      get_hints_ctx->log_pages.hash_table_log_page,
			      get_hints_ctx->log_pages.nqn_list_log_page,
			      spdk_bdev_get_name(rd_target->bdev));
	}

	assert(get_hints_ctx->hint_page.page_read_complete);
	rc = vbdev_redirector_get_nqn_list_region(rd_node, get_hints_ctx, 0);
	if (rc) {
		get_hints_ctx->nqn_list_page.get_log_page_success = false;
		vbdev_redirector_get_nqn_list_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
	}

	free_redirector_admin_cmd_ctx(adm_cmd_ctx);
	return;
}

/*
 * Completes the process of reading hints from a target. Called after
 * final region of the location hint log page is consumed (or reading fails).
 *
 * Includes reading tables from other log pages (e.g. hash table) if necessary.
 *
 * Takes custody of get_hints_ctx and adm_cmd_ctx. Caller should not
 * dereference rd_node or rd_target on return
 */
static void
vbdev_redirector_get_hints_cpl(struct redirector_bdev *rd_node,
			       struct redirector_bdev_target *rd_target,
			       struct redirector_get_hints_ctx *get_hints_ctx,
			       struct redirector_admin_cmd_ctx *adm_cmd_ctx)
{
	struct redirector_config *config = rd_node->config;
	struct redirector_target *hash_hint_source_target;

	assert(!get_hints_ctx->hint_page.page_read_complete);

	if (RD_DEBUG_LOG_HINT_LEARNING) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s hint page read from target %s completing\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
	}

	get_hints_ctx->hint_page.page_read_complete = true;

	if (!get_hints_ctx->hint_page.get_log_page_success ||
	    !get_hints_ctx->hint_page.bufs.stream.success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s error processing hints from target %s%s%s%s\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev),
			      get_hints_ctx->hint_page.get_log_page_success ? "" : " [get log page failed]",
			      get_hints_ctx->hint_page.bufs.stream.success ? "" : " [consume hints failed]",
			      get_hints_ctx->hint_page.bufs.stream.end_found ? "" : " [end not found]");
		vbdev_redirector_read_hint_tables_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		return;
	} else {
		/* Hint page read completed, and may or may not have changed */
		if (get_hints_ctx->hint_page.bufs.changed) {
			if (RD_DEBUG_LOG_HINT_LEARNING) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s hints from target %s changed\n",
					      config->redirector_name,
					      spdk_bdev_get_name(rd_target->bdev));
			}
			/* Do we need to read any other log pages to complete reading hints from this
			 * target? */
			if (get_hints_ctx->hint_page.bufs.num_hash_hints) {
				if (RD_DEBUG_LOG_HINT_LEARNING) {
					SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
						      "Redirector %s hints from target %s require loading tables\n",
						      config->redirector_name,
						      spdk_bdev_get_name(rd_target->bdev));
				}
				assert(get_hints_ctx->hint_page.bufs.hash_hint);
				get_hints_ctx->log_pages = get_hints_ctx->hint_page.bufs.hash_hint->hash.nvme_state;
				get_hints_ctx->log_pages_valid = true;
				vbdev_redirector_read_hint_tables(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
				return;
			} else {
				if (RD_DEBUG_LOG_HINT_LEARNING) {
					SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
						      "Redirector %s hints from target %s don't require "
						      "reading any other log pages. Completing now.\n",
						      config->redirector_name,
						      spdk_bdev_get_name(rd_target->bdev));
				}
				vbdev_redirector_read_hint_tables_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
				return;
			}
		} else {
			if (RD_DEBUG_LOG_HINT_LEARNING) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s hints from target %s unchanged\n",
					      config->redirector_name,
					      spdk_bdev_get_name(rd_target->bdev));
			}
			bool read_tables = false;

			/* If there's a hash hint from this target in use, we still need to poll
			 * those support pages for changes */
			if ((NULL == config->hash_hint_tables.hash_table) &&
			    (config->hash_hint_tables.hash_hint_source)) {
				hash_hint_source_target =
					redirector_config_find_target(config,
								      config->hash_hint_tables.hash_hint_source);
				if (hash_hint_source_target == rd_target->target_config) {
					read_tables = true;
				}
			}

			if (RD_DEBUG_LOG_HINT_LEARNING) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s %sre-reading tables for hash hint "
					      "from target %s\n",
					      config->redirector_name,
					      read_tables ? "" : "not ",
					      spdk_bdev_get_name(rd_target->bdev));
			}

			if (read_tables) {
				get_hints_ctx->log_pages = config->hash_hint_tables.hash_hint_pages;
				get_hints_ctx->log_pages_valid = true;
				vbdev_redirector_read_hint_tables(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			} else {
				vbdev_redirector_read_hint_tables_cpl(rd_node, rd_target,
								      get_hints_ctx, adm_cmd_ctx);
			}
			return;
		}
	}
	assert(false);
}

static void
vbdev_redirector_get_hints_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct redirector_admin_cmd_ctx *adm_cmd_ctx = cb_arg;
	struct redirector_get_hints_ctx *get_hints_ctx = adm_cmd_ctx->cb_ctx;
	struct redirector_bdev *rd_node = adm_cmd_ctx->rd_node;
	struct redirector_config *config = rd_node->config;
	struct redirector_bdev_target *rd_target = &rd_node->targets[adm_cmd_ctx->target_bdev_index];
	struct redirector_target *target_config = rd_target->target_config;
	uint64_t page_offset = get_hints_ctx ? get_hints_ctx->page_offset : 0;
	uint32_t resp_cdw0;
	int resp_sct;
	int resp_sc;
	bool nvme_success;
	bool glp_success;

	spdk_bdev_io_get_nvme_status(bdev_io, &resp_cdw0, &resp_sct, &resp_sc);
	nvme_success = (resp_sct == SPDK_NVME_SCT_GENERIC) && (resp_sc == SPDK_NVME_SC_SUCCESS);
	glp_success = success && nvme_success;
	get_hints_ctx->hint_page.get_log_page_success = glp_success;

	if (!success || glp_success) {
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %sread hint page from target %s\n",
				      config->redirector_name,
				      success ? "" : "FAILED to ",
				      spdk_bdev_get_name(rd_target->bdev));
		}
	} else {
		/* GLP returned an NVMe error from the far end */
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s %sread hint page from target %s: %s, %s (%0xd)\n",
			      adm_cmd_ctx->rd_node->config->redirector_name,
			      glp_success ? "" : "FAILED to ",
			      spdk_bdev_get_name(rd_target->bdev),
			      get_spdk_nvme_status_code_type_name(resp_sct),
			      get_spdk_nvme_command_status_code_name(resp_sct, resp_sc),
			      resp_sc);
	}

	assert(!get_hints_ctx->hint_page.page_read_complete);
	if (!glp_success) {
		/* Hint reading fails */
		get_hints_ctx->hint_page.get_log_page_success = false;
		vbdev_redirector_get_hints_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	}
	assert(get_hints_ctx);

	/* Consume (parse) the location hints in the region of the hint page we just read. */
	if (page_offset == 0) {
		struct rd_hint_log_page *hint_page = (void *)adm_cmd_ctx->data;
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hint page from target %s, gen=%"PRIu64", length=%"PRIu64"\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev),
				      hint_page->h.generation, hint_page->h.length);
		}
		if (hint_page->h.length < sizeof(struct rd_hint_log_page_header)) {
			if (RD_DEBUG_LOG_HINT_LEARNING) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s error processing hints from target %s: bad page header length\n",
					      config->redirector_name,
					      spdk_bdev_get_name(rd_target->bdev));
			}
			/* Hint reading fails */
			get_hints_ctx->hint_page.bufs.stream.success = false;
			vbdev_redirector_get_hints_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		}

		vbdev_redirector_target_got_hints(target_config, success);
		/* We consume the hint page header here */
		get_hints_ctx->hint_page.page_header = hint_page->h;
		get_hints_ctx->hint_page.bufs.stream.next.buf = &hint_page->first_hint;
		/* Buf remaining is entire get_log_page_payload minus the header we consume here */
		get_hints_ctx->hint_page.bufs.stream.next.remaining = sizeof(adm_cmd_ctx->data) - sizeof(
					hint_page->h);
		/* Hint list remaining may be greater or less than the payload */
		get_hints_ctx->hint_page.bufs.stream.page_remaining = hint_page->h.length - sizeof(hint_page->h);
		assert(!get_hints_ctx->prev_get_log_page_ctx);
		assert(!get_hints_ctx->hint_page.bufs.stream.prev.buf);
		assert(get_hints_ctx->hint_page.bufs.stream.prev.remaining == 0);
		if (rd_target->target_config->hint_stats.generation ==
		    get_hints_ctx->hint_page.page_header.generation) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hints from target %s unchanged (gen=%"PRIu64")\n",
				      config->redirector_name, spdk_bdev_get_name(rd_target->bdev),
				      get_hints_ctx->hint_page.page_header.generation);
			/* Hint page reading ends (unchanged). Hint specific pages (if any) will be read next. */
			get_hints_ctx->hint_page.bufs.stream.success = true;
			get_hints_ctx->hint_page.bufs.changed = false;
			vbdev_redirector_get_hints_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		} else {
			get_hints_ctx->hint_page.bufs.changed = true;
		}
		assert(!get_hints_ctx->hint_page.page_read_complete);
		vbdev_redirector_consume_hints(rd_node, target_config, &get_hints_ctx->hint_page.bufs);
	} else {
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hint page from target %s continues at offset %"PRIu64"\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev),
				      page_offset);
		}
		/* The remaining part of next_buf becomes prev_buf */
		get_hints_ctx->hint_page.bufs.stream.prev.buf = get_hints_ctx->hint_page.bufs.stream.next.buf;
		get_hints_ctx->hint_page.bufs.stream.prev.remaining =
			get_hints_ctx->hint_page.bufs.stream.next.remaining;
		/* This payload (which has no header) is the next_buf */
		get_hints_ctx->hint_page.bufs.stream.next.buf = adm_cmd_ctx->data;
		get_hints_ctx->hint_page.bufs.stream.next.remaining = sizeof(adm_cmd_ctx->data);
		/* Consume hints, starting with any fragment remaining in prev_buf */
		assert(!get_hints_ctx->hint_page.page_read_complete);
		vbdev_redirector_consume_hints(rd_node, target_config, &get_hints_ctx->hint_page.bufs);
		/* Whatever was left in prev_buf must be consumed by this point */
		assert(get_hints_ctx->hint_page.bufs.stream.prev.remaining == 0);
		get_hints_ctx->hint_page.bufs.stream.prev.buf = NULL;
		/* If there was a prev_buf, it was probably in the context object from the previous get_log_page admin
		 * command, for the previous chunk of the hint page. Release that now. */
		free_redirector_admin_cmd_ctx(get_hints_ctx->prev_get_log_page_ctx);
		get_hints_ctx->prev_get_log_page_ctx = NULL;
	}

	if (!get_hints_ctx->hint_page.bufs.stream.success) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s error processing hints from target %s\n",
			      config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
		/* Hint reading fails */
		vbdev_redirector_get_hints_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	}

	if (get_hints_ctx->hint_page.bufs.stream.end_found) {
		/* Hint page reading ends (changed). Hint specific pages (if any) will be read next. */
		get_hints_ctx->hint_page.bufs.stream.success = true;
		get_hints_ctx->hint_page.bufs.changed = true;
		vbdev_redirector_get_hints_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
		goto out;
	} else {
		/* Hint page reading continues */
		int rc;
		if (RD_DEBUG_LOG_HINT_LEARNING) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hint page from target %s reading next hint page chunk\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
		}
		assert(!get_hints_ctx->prev_get_log_page_ctx);
		/* Admin cmd context retained in get_hints_ctx to preserve any hint fragment remaining in it. */
		get_hints_ctx->prev_get_log_page_ctx = adm_cmd_ctx;
		rc = vbdev_redirector_get_hints_region(rd_node, get_hints_ctx->target_bdev_index, get_hints_ctx,
						       get_hints_ctx->page_offset + sizeof(adm_cmd_ctx->data));
		if (rc) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hint page from target %s reading next hint page chunk failed\n",
				      config->redirector_name,
				      spdk_bdev_get_name(rd_target->bdev));
			/* Hint reading fails */
			get_hints_ctx->hint_page.get_log_page_success = false;
			vbdev_redirector_get_hints_cpl(rd_node, rd_target, get_hints_ctx, adm_cmd_ctx);
			goto out;
		} else {
			/* ctx and get_hints_ctx now in the custody of the next hint page chunk read, so we must not
			 * free them here */
			get_hints_ctx = NULL;
			adm_cmd_ctx = NULL;
			/* None of the rest of these are safe to use now either */
			rd_node = NULL;
			config = NULL;
			rd_target = NULL;
			target_config = NULL;
		}
	}

out:
	spdk_bdev_free_io(bdev_io);
}

static int
vbdev_redirector_get_hints_region(struct redirector_bdev *rd_node, size_t target_bdev_index,
				  struct redirector_get_hints_ctx *get_hints_ctx, uint64_t offset)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[target_bdev_index];
	struct spdk_nvme_cmd *cmd = NULL;
	int rc;
	uint32_t transfer;
	uint32_t num_dwords;

	assert(get_hints_ctx);
	assert(rd_target->target_config);
	assert(!get_hints_ctx->hint_page.page_read_complete);
	if (rd_target->target_config->confirmed_not_redir) {
		return 0;
	}
	if (!spdk_bdev_io_type_supported(rd_target->bdev, SPDK_BDEV_IO_TYPE_NVME_ADMIN)) {
		assert(!rd_target->target_config->confirmed_not_redir);
		rd_target->target_config->confirmed_not_redir = true;
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s target %s can't be a redirector\n",
			      rd_node->config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
		return 0;
	}

	transfer = sizeof(((struct redirector_admin_cmd_ctx *)NULL)->data);
	if (get_hints_ctx->get_log_page_cmd_buf) {
		cmd = get_hints_ctx->get_log_page_cmd_buf;
	} else {
		cmd = rd_alloc_nvme_cmd();
		if (!cmd) {
			return -ENOMEM;
		}
		get_hints_ctx->get_log_page_cmd_buf = cmd;
	}
	num_dwords = (transfer >> 2) - 1;
	cmd->opc = SPDK_NVME_OPC_GET_LOG_PAGE;
	/* cmd.nsid will be supplied from the nvme bdev */
	cmd->cdw10 = ((num_dwords & 0xFFFFu) << 16) + RD_LOCATION_HINT_LOG_PAGE;
	cmd->cdw11 = (num_dwords >> 16) & 0xFFFFu;
	cmd->cdw12 = offset & 0xFFFFFFFFu;
	cmd->cdw13 = (offset >> 32) & 0xFFFFFFFFu;

	get_hints_ctx->page_offset = offset;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s reading hint page from target %s\n",
		      rd_node->config->redirector_name,
		      spdk_bdev_get_name(rd_target->bdev));

	rc = vbdev_redirector_send_admin_cmd(rd_node, get_hints_ctx->target_bdev_index, cmd,
					     vbdev_redirector_get_hints_cb, get_hints_ctx);
	return rc;
}

/*
 * Begin reading or rereading location hints from one target if it isn't already (or still)
 * in progress.
 */
int
vbdev_redirector_get_hints(struct redirector_bdev *rd_node, size_t target_bdev_index)
{
	struct redirector_bdev_target *rd_target = &rd_node->targets[target_bdev_index];
	struct redirector_get_hints_ctx *get_hints_ctx;
	int rc;

	if (rd_target->reading_hints) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s hint read already in progress for target %s\n",
			      rd_node->config->redirector_name,
			      spdk_bdev_get_name(rd_target->bdev));
		return 0;
	}

	get_hints_ctx = calloc(1, sizeof(*get_hints_ctx));
	if (!get_hints_ctx) {
		return -ENOMEM;
	}
	get_hints_ctx->target_bdev_index = target_bdev_index;

	rd_target->reading_hints = true;
	rd_target->target_config->hint_stats.hint_poll_count++;
	rc = vbdev_redirector_get_hints_region(rd_node, target_bdev_index, get_hints_ctx, 0);
	if (rc) {
		rd_target->reading_hints = false;
		free_redirector_get_hints_ctx(get_hints_ctx);
	}

	return rc;
}

int
vbdev_redirector_hint_poll(void *ctx)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;
	size_t target_bdev_index;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "[%s] Redirector %s poll\n",
		      rd_th_name(), rd_node->config->redirector_name);

	for (target_bdev_index = 0;
	     target_bdev_index < rd_node->num_rd_targets;
	     target_bdev_index++) {

		if (rd_node->targets[target_bdev_index].bdev &&
		    rd_node->targets[target_bdev_index].target_config &&
		    !rd_node->targets[target_bdev_index].target_config->dont_probe) {
			vbdev_redirector_get_hints(rd_node, target_bdev_index);
		}

	}

	return 1;
}
