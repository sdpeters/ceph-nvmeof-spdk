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
 * Encodes and decodes location hint log pages. This defines the
 * protocol for passing the hints between redirectors via NVMe log
 * pages.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_nvme_hints.h"
#include "vbdev_redirector.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector_rpc_types.h"
#include "spdk/bdev.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/bdev_module.h"
#include "spdk_internal/log.h"

static bool
rd_pass_hint_to_peers(struct redirector_bdev *rd_node, struct location_hint *hint)
{
	if (hint->authoritative) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s will send authoritative %s hint (%p) "
				      "with target index %d to target (%s)\n",
				      rd_node->config->redirector_name, rd_hint_type_name[location_hint_type(hint)],
				      hint, hint->target_index, location_hint_target_name(hint));
		}
		return true;
	}

	if (location_hint_single_target(hint) && hint->rx_target) {
		if (!rd_node->config->nqn) {
			/* Don't forward a learned hint if we don't know our own NQN */
			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s won't send %s hint (%p) to target (%s) because "
					      "it doesn't know its own NQN\n",
					      rd_node->config->redirector_name, rd_hint_type_name[location_hint_type(hint)],
					      hint, location_hint_target_name(hint));
			}
			return false;
		} else {
			if (0 == strcmp(rd_node->config->nqn, location_hint_target_name(hint))) {
				/* Don't forward a learned hint to ourself. These may have been
				 * learned before our NQN was known, and should be deleted
				 * once we do. */
				if (RD_DEBUG_LOG_NVME_HINTS) {
					SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
						      "Redirector %s won't send %s hint (%p) to self (%s) learned "
						      "(from %s)\n",
						      rd_node->config->redirector_name,
						      rd_hint_type_name[location_hint_type(hint)],
						      hint, location_hint_target_name(hint), hint->rx_target);
				}
				return false;
			}
		}
	}

	if (hint->target_index != -1) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s will send %s hint (%p) with target index %d to target (%s)\n",
				      rd_node->config->redirector_name, rd_hint_type_name[location_hint_type(hint)],
				      hint, hint->target_index, location_hint_target_name(hint));
		}
		return true;
	}

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s won't send %s hint (%p) with target index %d to target (%s)\n",
			      rd_node->config->redirector_name, rd_hint_type_name[location_hint_type(hint)],
			      hint, hint->target_index, location_hint_target_name(hint));
	}
	return false;
}

static bool
rd_hint_translates_lba(struct location_hint *hint)
{
	return (location_hint_single_target(hint) &&
		(hint->extent.start_lba != location_hint_target_start_lba(hint)));
}

static enum rd_hint_type
rd_location_hint_encode_type(struct redirector_bdev *rd_node,
			     struct location_hint *hint) {
	enum rd_hint_type hint_type = location_hint_type(hint);

	switch (hint_type)
	{
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		return (hint_type);
	default:
		return RD_HINT_TYPE_NONE;
	}
}

/*
 * Encode outgoing location hint of type RD_HINT_TYPE_SIMPLE_NQN from an internal location hint
 * struct.
 *
 * Accepts internal hint types RD_HINT_TYPE_SIMPLE_NQN or _SIMPLE_NQN_NS, but always emits
 * _SIMPLE_NQN. Currently _SIMPLE_NQN_NS hints are only used for local egress targets. Egress
 * redirectors must emit location hints tatgeting themselves as the path to egress targets.
 *
 * This will need to change if we decide that passing cross-namespace hints (redirects to bare
 * NVMe-oF SSDs, or other ADNN logical namespaces) is desirable. For now we assume that a DVM will
 * always manage an egress redirector between any storage device and any host, and that passing
 * cross-namespace hints to hosts is not desirable.
 */
static bool
rd_encode_hint_simple_nqn(struct redirector_bdev *rd_node,
			  struct rd_hint_log_page_header *page_header,
			  size_t page_buf_size,
			  struct rd_hint_entry *nvme_hint,
			  struct location_hint *hint)
{
	char *target_nqn = "";
	struct redirector_target *hint_target;
	bool target_is_not_redir = false;
	bool target_has_nqn = false;
	bool target_nqn_known = false;
	bool hint_points_here = false;
	bool hint_can_target_nqn = true;

	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
		break;
	default:
		return false;
	}

	hint_target = redirector_config_find_target(rd_node->config, location_hint_target_name(hint));
	nvme_hint->h.hint_len = sizeof(nvme_hint->h) + sizeof(nvme_hint->simple_nqn);
	nvme_hint->h.hint_type = RD_HINT_TYPE_SIMPLE_NQN;
	nvme_hint->h.read = true;
	nvme_hint->h.write = true;
	nvme_hint->simple_nqn.extent.start_lba = hint->extent.start_lba;
	nvme_hint->simple_nqn.extent.blocks = hint->extent.blocks;

	target_is_not_redir = hint_target && hint_target->confirmed_not_redir;
	target_has_nqn = hint_target && hint_target->nqn;
	target_nqn_known = hint->nqn_target || target_has_nqn;

	/* If the hint we have translates LBAs, we can't refer to its target by the targets NQN in the hint we pass,
	 * because this hint type can't represent LBA translation (SIMPLE_NQN_NS can). Until we support SIMPLE_NQN_NS,
	 * we won't refer to these targets by their NQN in hints. If we generate these hints at all, they'll target
	 * this redirector, which can perform the LBA translation. */
	if (rd_hint_translates_lba(hint)) {
		hint_can_target_nqn = false;
	}

	if (!target_nqn_known) {
		hint_can_target_nqn = false;
	}

	/* We'll only pass hints targeting this redirector for egress targets */
	if (target_is_not_redir && !target_nqn_known) {
		hint_points_here = true;
	}

	/* If the hint can't target an NQN, but we don't want it to point here, we won't gnerate it */
	if (!hint_can_target_nqn && !hint_points_here) {
		return false;
	}

	if (hint_points_here) {
		/* This redirector is the target */
		if (rd_node->config->nqn) {
			/* Use self NQN if known */
			target_nqn = rd_node->config->nqn;
		} else {
			/* Send blank NQN if self NQN unknown. Empty NQN in hint target indicates NQN that sent
			 * hint. */
			target_nqn = "";
		}
	} else {
		assert(hint_can_target_nqn);
		if (hint->nqn_target) {
			target_nqn = location_hint_target_name(hint);
		} else {
			assert(target_has_nqn);
			target_nqn = hint_target->nqn;
		}
	}
	spdk_strcpy_pad(nvme_hint->simple_nqn.dest_nqn, target_nqn,
			sizeof(nvme_hint->simple_nqn.dest_nqn), '\0');
	page_header->length += nvme_hint->h.hint_len;
	rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "encoded", hint);
	return true;
}

/*
 * Encode outgoing location hint of type RD_HINT_TYPE_HASH_NQN_TABLE from an internal location hint
 * struct.
 */
static bool
rd_encode_hint_hash_nqn_table(struct redirector_bdev *rd_node,
			      struct rd_hint_log_page_header *page_header,
			      size_t page_buf_size,
			      struct rd_hint_entry *nvme_hint,
			      struct location_hint *hint)
{
	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		break;
	default:
		return false;
	}

	/* Include null terminator */
	nvme_hint->h.hint_len = sizeof(nvme_hint->h) + sizeof(nvme_hint->hash_nqn_table) +
				strlen(hint->hash.object_name_format) + 1;
	nvme_hint->h.hint_type = RD_HINT_TYPE_HASH_NQN_TABLE;
	nvme_hint->h.read = true;
	nvme_hint->h.write = true;

	nvme_hint->hash_nqn_table.log2_chunk_size = spdk_u64log2(hint->hash.object_bytes);
	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s object_bytes=%"PRIu64", log2_chunk_size=%u\n",
			      rd_node->config->redirector_name,
			      hint->hash.object_bytes, nvme_hint->hash_nqn_table.log2_chunk_size);
	}
	nvme_hint->hash_nqn_table.hash_function_id = hint->hash.hash_function_id;
	/* The contents of the hash table and NQN list log pages is prepared elsewhere */
	nvme_hint->hash_nqn_table.hash_table_log_page = RD_HASH_HINT_HASH_TABLE_LOG_PAGE;
	nvme_hint->hash_nqn_table.nqn_list_log_page = RD_NQN_LIST_LOG_PAGE;
	/* Format string legth excludes NULL, but header length includes it */
	nvme_hint->hash_nqn_table.chunk_format_string_len = strlen(hint->hash.object_name_format);

	strcpy(nvme_hint->hash_nqn_table.chunk_name_format, hint->hash.object_name_format);
	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s object_name_format=\"%s\", len=%d, sent chunk_format_string=\"%s\", hint len=%d\n",
			      rd_node->config->redirector_name,
			      hint->hash.object_name_format, nvme_hint->hash_nqn_table.chunk_format_string_len,
			      nvme_hint->hash_nqn_table.chunk_name_format, nvme_hint->h.hint_len);
	}
	page_header->length += nvme_hint->h.hint_len;
	rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "encoded", hint);
	return true;
}

static bool
rd_encode_nvme_hint(struct redirector_bdev *rd_node,
		    struct rd_hint_log_page_header *page_header,
		    size_t page_buf_size,
		    struct rd_hint_entry *nvme_hint,
		    struct location_hint *hint)
{
	enum rd_hint_type hint_type = rd_location_hint_encode_type(rd_node, hint);

	switch (hint_type) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
		/* May emit RD_HINT_TYPE_SIMPLE_NQN for RD_HINT_TYPE_SIMPLE_NQN_NS */
		return rd_encode_hint_simple_nqn(rd_node, page_header, page_buf_size, nvme_hint, hint);
		break;
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		return rd_encode_hint_hash_nqn_table(rd_node, page_header, page_buf_size, nvme_hint, hint);
		break;
	case RD_HINT_TYPE_NONE:
	case RD_HINT_TYPE_SIMPLE_NQN_ALT:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
	case RD_HINT_TYPE_STRIPE_NQN:
	case RD_HINT_TYPE_STRIPE_NQN_NS:
	case RD_HINT_TYPE_DIFF_NQN_NS:
	case RD_HINT_TYPE_DIFF_HASH_NQN_TABLE:
		rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "skipping, no encoder", hint);
		return false;
		break;
	default:
		if ((hint_type >= RD_HINT_TYPE_VENDOR_SPEC_START) &&
		    (hint_type <= RD_HINT_TYPE_VENDOR_SPEC_END)) {
			rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__,
					  "skipping, no vendor specific encoder", hint);
			return false;
		} else {
			rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "skipping, invalid type", hint);
			return false;
		}
	}
}

static bool
rd_decode_hint_simple_nqn(struct redirector_bdev *rd_node,
			  struct redirector_target *target_config,
			  struct rd_hint_entry *nvme_hint,
			  struct location_hint *decoded)
{
	assert(nvme_hint->h.hint_type == RD_HINT_TYPE_SIMPLE_NQN);

	if (nvme_hint->h.hint_len != sizeof(nvme_hint->h) + sizeof(nvme_hint->simple_nqn)) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s ignoring hint (%p) with bad length %d "
				      "(expected %lu)\n",
				      rd_node->config->redirector_name, nvme_hint,
				      nvme_hint->h.hint_len, sizeof(nvme_hint->h) + sizeof(nvme_hint->simple_nqn));
		}
		return false;
	}

	if (!nvme_hint->h.read || !nvme_hint->h.write) {
		/* vbdev_redirector doesn't support directional hints yet */
		return false;
	}

	decoded->hint_type = nvme_hint->h.hint_type;
	decoded->extent.start_lba = nvme_hint->simple_nqn.extent.start_lba;
	decoded->extent.blocks = nvme_hint->simple_nqn.extent.blocks;
	/* _SIMPLE_NQN doesn't perfrom LBA translation. Internal hint structure is used for both
	 * _SIMPLE_NQN and _SIMPLE_NQN_NS which may perforn LBA translation */
	decoded->simple.target_start_lba = decoded->extent.start_lba;

	if (strnlen(nvme_hint->simple_nqn.dest_nqn, sizeof(nvme_hint->simple_nqn.dest_nqn))) {
		decoded->nqn_target = true;
		decoded->simple.target_name = strndup(nvme_hint->simple_nqn.dest_nqn,
						      sizeof(nvme_hint->simple_nqn.dest_nqn));
	} else {
		/* NULL target string in hint means the target sending the hint is the target of the hint */
		if (target_config->nqn) {
			decoded->nqn_target = true;
			decoded->simple.target_name = strdup(target_config->nqn);
		} else {
			/* Use target bdev name */
			decoded->nqn_target = false;
			decoded->simple.target_name = strdup(target_config->name);
		}
	}

	rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "decoded:", decoded);
	return true;
}

static bool
rd_decode_hint_hash_nqn_table(struct redirector_bdev *rd_node,
			      struct redirector_target *target_config,
			      struct rd_hint_entry *nvme_hint,
			      struct location_hint *decoded)
{
	assert(nvme_hint->h.hint_type == RD_HINT_TYPE_HASH_NQN_TABLE);
	if (nvme_hint->h.hint_len < sizeof(nvme_hint->h) + sizeof(nvme_hint->hash_nqn_table)) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s ignoring hint (%p) with bad length %d "
				      "(expected >= %lu)\n",
				      rd_node->config->redirector_name, nvme_hint,
				      nvme_hint->h.hint_len, sizeof(nvme_hint->h) + sizeof(nvme_hint->hash_nqn_table));
		}
		return false;
	}
	/* Length includes NULL on format string */
	if (nvme_hint->h.hint_len !=
	    (sizeof(nvme_hint->h) + sizeof(nvme_hint->hash_nqn_table) +
	     nvme_hint->hash_nqn_table.chunk_format_string_len + 1)) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s ignoring hint (%p) with bad length %d "
				      "(expected %lu)\n",
				      rd_node->config->redirector_name, nvme_hint,
				      nvme_hint->h.hint_len,
				      sizeof(nvme_hint->h) + sizeof(nvme_hint->hash_nqn_table) +
				      nvme_hint->hash_nqn_table.chunk_format_string_len + 1);
		}
		return false;
	}

	if (!nvme_hint->h.read || !nvme_hint->h.write) {
		/* vbdev_redirector doesn't support directional hints yet */
		return false;
	}

	decoded->hint_type = nvme_hint->h.hint_type;

	/* Hash hints apply to entire LN */
	decoded->extent.start_lba = 0;
	decoded->extent.blocks = -1;

	if (nvme_hint->hash_nqn_table.hash_function_id >= RD_HASH_FN_ID_LAST) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s ignoring hash hint (%p) with unrecognized hash_function_id %d\n",
				      rd_node->config->redirector_name, nvme_hint,
				      (int)nvme_hint->hash_nqn_table.hash_function_id);
		}
		return false;
	}
	decoded->hash.hash_function_id = nvme_hint->hash_nqn_table.hash_function_id;

	if ((nvme_hint->hash_nqn_table.log2_chunk_size < RD_HASH_HINT_MIN_LOG2_CHUNK_SIZE) ||
	    (nvme_hint->hash_nqn_table.log2_chunk_size > RD_HASH_HINT_MAX_LOG2_CHUNK_SIZE)) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s ignoring hash hint (%p) with log2_chunk_size %d "
				      "(not between %d and %d)\n",
				      rd_node->config->redirector_name, nvme_hint,
				      nvme_hint->hash_nqn_table.log2_chunk_size,
				      RD_HASH_HINT_MIN_LOG2_CHUNK_SIZE, RD_HASH_HINT_MAX_LOG2_CHUNK_SIZE);
		}
		return false;
	}
	decoded->hash.object_bytes = 1 << nvme_hint->hash_nqn_table.log2_chunk_size;
	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s object_bytes=%"PRIu64", log2_chunk_size=%u\n",
			      rd_node->config->redirector_name,
			      decoded->hash.object_bytes, nvme_hint->hash_nqn_table.log2_chunk_size);
	}
	if (nvme_hint->hash_nqn_table.chunk_format_string_len) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s received chunk_format_string=\"%s\", length=%d\n",
				      rd_node->config->redirector_name,
				      nvme_hint->hash_nqn_table.chunk_name_format,
				      nvme_hint->hash_nqn_table.chunk_format_string_len);
		}
		assert(nvme_hint->hash_nqn_table.chunk_format_string_len ==
		       strlen(nvme_hint->hash_nqn_table.chunk_name_format));
		decoded->hash.object_name_format =
			strndup(nvme_hint->hash_nqn_table.chunk_name_format,
				nvme_hint->hash_nqn_table.chunk_format_string_len);
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s chunk_format_string=\"%s\", length=%d\n",
				      rd_node->config->redirector_name,
				      decoded->hash.object_name_format, nvme_hint->hash_nqn_table.chunk_format_string_len);
		}
	}

	/* Support table structures constructed later when those log pages are read */
	decoded->hash.hash_table = NULL;
	decoded->hash.nqn_list = NULL;

	/* Log pages on this target containing these tables */
	decoded->hash.nvme_state.hash_table_log_page = nvme_hint->hash_nqn_table.hash_table_log_page;
	decoded->hash.nvme_state.nqn_list_log_page = nvme_hint->hash_nqn_table.nqn_list_log_page;

	rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "decoded:", decoded);
	return true;
}

static bool
rd_decode_nvme_hint(struct redirector_bdev *rd_node,
		    struct redirector_target *target_config,
		    struct rd_hint_entry *nvme_hint,
		    struct location_hint *decoded)
{
	switch (nvme_hint->h.hint_type) {
	case RD_HINT_TYPE_SIMPLE_NQN:
		return rd_decode_hint_simple_nqn(rd_node, target_config, nvme_hint, decoded);
		break;
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		return rd_decode_hint_hash_nqn_table(rd_node, target_config, nvme_hint, decoded);
		break;
	case RD_HINT_TYPE_NONE:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
	case RD_HINT_TYPE_SIMPLE_NQN_ALT:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
	case RD_HINT_TYPE_STRIPE_NQN:
	case RD_HINT_TYPE_STRIPE_NQN_NS:
	case RD_HINT_TYPE_DIFF_NQN_NS:
	case RD_HINT_TYPE_DIFF_HASH_NQN_TABLE:
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s skipping hint (%p) type %d that can't be decoded\n",
				      rd_node->config->redirector_name, nvme_hint, nvme_hint->h.hint_type);
		}
		return false;
		break;
	default:
		if (nvme_hint->h.hint_type >= RD_HINT_TYPE_VENDOR_SPEC_START) {
			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s skipping hint (%p) of vendor specific type %d "
					      "that can't be encoded\n",
					      rd_node->config->redirector_name, nvme_hint, nvme_hint->h.hint_type);
			}
			return false;
		} else {
			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s skipping hint (%p) of invalid type %d\n",
					      rd_node->config->redirector_name, nvme_hint, nvme_hint->h.hint_type);
			}
			return false;
		}
	}
}

/*
 * Generate the contents of the location hint log page for this redirector, and replaces the log page buf
 * if the generated page is different.
 *
 * Return: true if hint page changed.
 *
 * TODO: Operate as a per-host stream of hints, rather than a single complete collection.
 *
 * This function prepares a collection of all the location hints this redirector would forward to any connected
 * initiator (that was a redirector).
 *
 * Ideally a ADNN redirector sends a stream of hints to each of its upstream neighbors. It would use an async
 * notification mechanism to signal when new hints were available. It might do this as part of making an IO forwarding
 * decision, hopefully avoiding more IO from that neighbor that would also need to be forwarded. These neighbors would
 * endeavor to apply these new hints as soon as possible, so subsequent IOs can take a better (shorter) path to the
 * destination.
 *
 * As a bdev, this redirector can't identify which connected host (behind bdev_split, or the NVMF subsystem)
 * corresponds to each submitted IO (or NVME admin command), so can't tailor the hint page to each host. It also cannot
 * send async notifications to specific neighbors, and can't receive an indication that any or all of its connected
 * neighbors have consumed the entire hint page.
 */
static bool
rd_new_hint_log_page(struct redirector_bdev *rd_node)
{
	struct redirector_bdev_hint_page *log_page = &rd_node->hint_page;
	size_t page_size = RD_HINT_PAGE_DEFAULT_SIZE;
	struct rd_hint_log_page *page_buf;
	struct rd_hint_log_page *old_page_buf = log_page->buf;
	struct rd_hint_entry *next_hint;
	void *next_hint_buf;
	GSequenceIter *hint_iter;
	struct location_hint *iter_hint = NULL;
	int hint_count = 0;
	bool changed = false;

	page_buf = calloc(1, page_size);
	if (!page_buf) {
		SPDK_ERRLOG("could not allocate location hint log page buffer\n");
		return false;
	}
	log_page->buffer_size = page_size;
	page_buf->h.generation = log_page->generation;
	/* Zero hints */
	page_buf->h.length = sizeof(page_buf->h);
	/* For now we always replace all our previously sent hints with a complete new set */
	page_buf->h.retain_prev = false;
	next_hint = &page_buf->first_hint;
	next_hint_buf = next_hint;

	/* Add the hints we'll pass to other redirectors. For now they all get the same set */
	hint_iter = g_sequence_get_begin_iter(rd_node->config->hints);
	while (!g_sequence_iter_is_end(hint_iter)) {
		iter_hint = (struct location_hint *)g_sequence_get(hint_iter);
		if ((page_size - page_buf->h.length) < RD_HINT_ENTRY_MAX_LEN) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s log page buffer full\n",
				      rd_node->config->redirector_name);
			break;
		}
		/* Consider adding this hint */
		if (rd_pass_hint_to_peers(rd_node, iter_hint)) {
			if (rd_encode_nvme_hint(rd_node, &page_buf->h, page_size, next_hint, iter_hint)) {
				next_hint_buf += next_hint->h.hint_len;
				next_hint = next_hint_buf;
				hint_count++;
			} else {
				rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__,
						  "skipping, not encoded", iter_hint);
			}
		} else {
			rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__,
					  "skipping, not passed to peers", iter_hint);
		}
		hint_iter = g_sequence_iter_next(hint_iter);
	}

	if ((NULL == old_page_buf) || (0 != memcmp(old_page_buf, page_buf, page_buf->h.length))) {
		changed = true;
		/* Update generation number */
		page_buf->h.generation = ++log_page->generation;
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s hint log page changed gen=%"PRIu64", len=%"PRIu64", hints=%d\n",
				      rd_node->config->redirector_name, page_buf->h.generation, page_buf->h.length, hint_count);
		}

		log_page->buf = page_buf;
		log_page->buffer_size = page_size;
		free(old_page_buf);
	} else {
		/* Nothing changed */
		free(page_buf);
	}

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s hint log page %schanged gen=%"PRIu64", len=%"PRIu64", hints=%d\n",
			      rd_node->config->redirector_name, changed ? "" : "un", log_page->buf->h.generation,
			      log_page->buf->h.length, hint_count);
	}

	return changed;
}

/*
 * Generate the contents of the hash table log page for this redirector, and replaces the log page buf
 * if the generated page is different.
 *
 * Return: true if hint page changed.
 */
static bool
rd_new_hash_table_log_page(struct redirector_bdev *rd_node)
{
	struct redirector_config *config = rd_node->config;
	struct redirector_bdev_hash_table_page *log_page = &rd_node->hint_page.hash_table;
	struct rd_hash_table_log_page *page_buf;
	struct rd_hash_table_log_page *old_page_buf = log_page->buf;
	size_t page_size;
	bool changed = false;
	int bucket_iter;

	/* Compute page size */
	if (config->hash_hint_tables.hash_table) {
		/* There is a hash hint hash table */
		page_size = sizeof(*page_buf);
		page_size += config->hash_hint_tables.hash_table->num_buckets * sizeof(page_buf->nqns[0]);
		page_buf = calloc(1, page_size);
		if (!page_buf) {
			SPDK_ERRLOG("could not allocate hash table log page buffer\n");
			return false;
		}

		page_buf->generation = log_page->generation;
		page_buf->length = page_size;
		page_buf->list_digest = config->hash_hint_tables.hash_table->digest;
		page_buf->bucket_count = config->hash_hint_tables.hash_table->num_buckets;
		for (bucket_iter = 0;
		     bucket_iter < (int) config->hash_hint_tables.hash_table->num_buckets;
		     bucket_iter++) {
			page_buf->nqns[bucket_iter] = config->hash_hint_tables.hash_table->buckets[bucket_iter];
		}
	} else {
		/* There is no hash hint hash table */
		page_size = 0;
		page_buf = NULL;
	}

	if (((NULL == old_page_buf) && (NULL != page_buf)) ||
	    ((NULL != old_page_buf) && (NULL == page_buf)) ||
	    (((NULL != old_page_buf) && (NULL != page_buf)) &&
	     (0 != memcmp(old_page_buf, page_buf, log_page->buffer_size)))) {
		changed = true;
		if (page_buf) {
			/* Update generation number */
			page_buf->generation = ++log_page->generation;

			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s hash table log page changed "
					      "gen=%"PRIu64", len=%"PRIu64", bucket=%d\n",
					      rd_node->config->redirector_name, log_page->generation,
					      page_size, page_buf->bucket_count);
			}
		} else {
			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s hash table log page changed to NULL\n",
					      rd_node->config->redirector_name);
			}
		}

		log_page->buf = page_buf;
		log_page->buffer_size = page_size;
		free(old_page_buf);
	} else {
		/* Nothing changed */
		free(page_buf);
	}

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s hash table log page %schanged gen=%"PRIu64", len=%"PRIu64"\n",
			      rd_node->config->redirector_name, changed ? "" : "un", log_page->generation,
			      log_page->buffer_size);
	}

	return changed;
}

/*
 * Generate the contents of the nqn list log page for this redirector, and replaces the log page buf
 * if the generated page is different.
 *
 * Return: true if hint page changed.
 */
static bool
rd_new_nqn_list_log_page(struct redirector_bdev *rd_node)
{
	struct redirector_config *config = rd_node->config;
	struct redirector_bdev_nqn_list_page *log_page = &rd_node->hint_page.nqn_list;
	struct rd_nqn_list_log_page *page_buf;
	struct rd_nqn_list_log_page *old_page_buf = log_page->buf;
	size_t page_size;
	bool changed = false;
	int nqn_iter;
	char *next_nqn;

	/* Compute page size */
	if (config->hash_hint_tables.nqn_list) {
		/* There is a hash hint hash table */
		page_size = sizeof(*page_buf);
		for (nqn_iter = 0;
		     nqn_iter < (int) config->hash_hint_tables.nqn_list->num_nqns;
		     nqn_iter++) {
			page_size += strlen(g_quark_to_string(config->hash_hint_tables.nqn_list->nqns[nqn_iter].nqn));
			/* Space for NULL terminator */
			page_size++;
		}
		page_buf = calloc(1, page_size);
		if (!page_buf) {
			SPDK_ERRLOG("could not allocate nqn list log page buffer\n");
			return false;
		}

		page_buf->generation = log_page->generation;
		page_buf->length = page_size;
		page_buf->list_digest = config->hash_hint_tables.nqn_list->digest;
		page_buf->num_nqns = config->hash_hint_tables.nqn_list->num_nqns;

		/* Copy NQN strings */
		next_nqn = &page_buf->nqns[0];
		for (nqn_iter = 0;
		     nqn_iter < (int) config->hash_hint_tables.nqn_list->num_nqns;
		     nqn_iter++) {
			strcpy(next_nqn, g_quark_to_string(config->hash_hint_tables.nqn_list->nqns[nqn_iter].nqn));
			/* Next NQN follows NULL terminator */
			next_nqn += strlen(next_nqn) + 1;
		}
	} else {
		/* There is no hash hint nqn list */
		page_size = 0;
		page_buf = NULL;
	}

	if (((NULL == old_page_buf) && (NULL != page_buf)) ||
	    ((NULL != old_page_buf) && (NULL == page_buf)) ||
	    (((NULL != old_page_buf) && (NULL != page_buf)) &&
	     (0 != memcmp(old_page_buf, page_buf, log_page->buffer_size)))) {
		changed = true;
		if (page_buf) {
			/* Update generation number */
			page_buf->generation = ++log_page->generation;

			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s nqn list log page changed "
					      "gen=%"PRIu64", len=%"PRIu64", nqns=%d\n",
					      rd_node->config->redirector_name, log_page->generation,
					      log_page->buffer_size, page_buf->num_nqns);
			}
		} else {
			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s nqn list table log page changed to NULL\n",
					      rd_node->config->redirector_name);
			}
		}

		log_page->buf = page_buf;
		log_page->buffer_size = page_size;
		free(old_page_buf);
	} else {
		/* Nothing changed */
		free(page_buf);
	}

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s nqn list log page %schanged gen=%"PRIu64", len=%"PRIu64"\n",
			      rd_node->config->redirector_name, changed ? "" : "un", log_page->generation,
			      log_page->buffer_size);
	}

	return changed;
}

/*
 * Generate the contents of all the log pages used for senfing hints from this redirector, and
 * replace the log page buf(s) of the generated pages that are different.
 *
 * Return: true if any hint page changed.
 */
bool
rd_new_hint_log_pages(struct redirector_bdev *rd_node)
{
	bool changed = false;

	changed |= rd_new_hint_log_page(rd_node);
	changed |= rd_new_hash_table_log_page(rd_node);
	changed |= rd_new_nqn_list_log_page(rd_node);

	return changed;
}

uint64_t
rd_ch_get_hint_log_page_size(struct redirector_bdev_io_channel *rd_ch)
{
	if (rd_ch->hint_log_page) {
		return rd_ch->hint_log_page->h.length;
	}

	return 0;
}

uint64_t
rd_ch_get_nqn_list_log_page_size(struct redirector_bdev_io_channel *rd_ch)
{
	if (rd_ch->nqn_list_log_page) {
		return rd_ch->nqn_list_log_page->length;
	}

	return 0;
}

uint64_t
rd_ch_get_hash_table_log_page_size(struct redirector_bdev_io_channel *rd_ch)
{
	if (rd_ch->hash_table_log_page) {
		return rd_ch->hash_table_log_page->length;
	}

	return 0;
}

/* Mark bytes consumed from a buf_stream, and one of its internal bufs */
static bool
rd_log_page_buf_stream_consume_bytes(struct rd_log_page_buf_stream *bufs, struct rd_hint_buf *buf,
				     size_t bytes)
{
	assert((buf == &bufs->prev) || (buf == &bufs->next));
	assert(buf->buf);

	if (buf->remaining < bytes) {
		goto fail;
	}
	if (bufs->page_remaining < bytes) {
		goto fail;
	}

	buf->remaining -= bytes;
	buf->buf += bytes;
	bufs->page_remaining -= bytes;
	bufs->end_found = (bufs->page_remaining == 0);
	return true;

fail:
	bufs->success = false;
	return false;
}

/* Copy the rest of bufs.prev to the temp buffer supplied, and do bytes consumed accounting */
static size_t
rd_get_next_hint_copy_head_from_prev(struct rd_log_page_buf_stream *bufs, void *dest)
{
	size_t prev_buf_copied = spdk_min(RD_HINT_ENTRY_MAX_LEN,
					  spdk_min(bufs->page_remaining,
							  bufs->prev.remaining));
	memcpy(dest, bufs->prev.buf, prev_buf_copied);
	bool success = rd_log_page_buf_stream_consume_bytes(bufs, &bufs->prev, prev_buf_copied);
	assert(success);
	assert(bufs->prev.remaining == 0);
	return prev_buf_copied;
}

/* Copy a portion of a hint from bufs.next. The header at *hint_copy may not be complete. This may not be copying the
 * entire hint. */
static struct rd_hint_entry *
rd_get_next_hint_copy_from_next(struct rd_log_page_buf_stream *bufs,
				struct rd_hint_entry *hint_copy,	/* Partially copied hint */
				size_t hint_len,			/* Assumed (partial) hint length */
				size_t hint_bytes_copied)		/* Bytes already copied */
{
	if (bufs->next.remaining < (hint_len - hint_bytes_copied)) {
		/* next.buf is too short */
		bufs->success = false;
		return NULL;
	} else {
		size_t next_buf_copied =
			spdk_min(RD_HINT_ENTRY_MAX_LEN - hint_bytes_copied,
				 spdk_min(hint_len - hint_bytes_copied,
					  spdk_min(bufs->next.remaining,
						   bufs->page_remaining)));
		if ((hint_bytes_copied + next_buf_copied) != hint_len) {
			bufs->success = false;
			return NULL;
		}
		memcpy((void *)hint_copy + hint_bytes_copied, bufs->next.buf, next_buf_copied);
		bool success = rd_log_page_buf_stream_consume_bytes(bufs, &bufs->next, next_buf_copied);
		assert(success);
		bufs->success = true;
		return hint_copy;
	}
}

/* Copy the rest of a hint from bufs.next. The header at *hint_copy is complete. */
static struct rd_hint_entry *
rd_get_next_hint_copy_tail_from_next(struct rd_log_page_buf_stream *bufs,
				     struct rd_hint_entry *hint_copy,	/* Partially copied hint */
				     size_t hint_bytes_copied)		/* Bytes already copied */
{
	return rd_get_next_hint_copy_from_next(bufs, hint_copy, hint_copy->h.hint_len, hint_bytes_copied);
}

/*
 * Return a pointer to the next hint struct, and advance the state of the buf_stream past it.
 *
 * If the next hint spans the prev and next bufs, copy it to the provided temp buf and return a pointer
 * to that. Otherwise skip the copy and return a pointer to the hint in whichever buffer it's in.
 */
static struct rd_hint_entry *
rd_get_next_hint_buf(struct rd_log_page_buf_stream *stream, void *temp)
{
	assert(stream);
	if (!stream->page_remaining) {
		stream->end_found = true;
		stream->success = true;
		return NULL;
	}
	/* There are bytes left in the hint list. We have to find another hint. */
	if (stream->page_remaining < sizeof(struct rd_hint_entry_header)) {
		stream->success = false;
		return NULL;
	}
	if (stream->prev.remaining) {
		assert(stream->prev.buf);
		if (stream->prev.remaining > sizeof(struct rd_hint_entry_header)) {
			/* We can determine hint length without copying */
			struct rd_hint_entry_header *next_header = stream->prev.buf;
			if (next_header->hint_len <= stream->prev.remaining) {
				/* Next hint is entirely contained in prev.buf. Unlikely. */
				if (!rd_log_page_buf_stream_consume_bytes(stream, &stream->prev, next_header->hint_len)) {
					return NULL;
				}
				stream->success = true;
				/* Return pointer to hint in prev_buf */
				return (struct rd_hint_entry *)next_header;
			} else {
				/* Next hint spans buffers. Make a contiguous copy in temp */
				struct rd_hint_entry *next_entry = temp;
				size_t prev_buf_copied =
					rd_get_next_hint_copy_head_from_prev(stream, temp);
				/* The rest of the hint must be in next.buf */
				return rd_get_next_hint_copy_tail_from_next(stream, next_entry, prev_buf_copied);
			}
		} else {
			/* Header is split across bufs */
			struct rd_hint_entry *next_entry = temp;
			size_t prev_buf_copied =
				rd_get_next_hint_copy_head_from_prev(stream, temp);
			/* The rest of the header must be in next.buf */
			next_entry = rd_get_next_hint_copy_from_next(stream, next_entry,
					sizeof(struct rd_hint_entry_header), prev_buf_copied);
			if (!next_entry) {
				/* Couldn't copy header to temp */
				return NULL;
			}
			/* The rest of the hint must be in next_buf */
			return rd_get_next_hint_copy_tail_from_next(stream, next_entry,
					sizeof(struct rd_hint_entry_header));
		}
	} else {
		/* No prev buffer. There has to be a next hint in next.buf. */
		if (stream->next.remaining > sizeof(struct rd_hint_entry_header)) {
			/* At least the header of the next hint is in buf.next */
			struct rd_hint_entry_header *next_header = stream->next.buf;
			if (next_header->hint_len <= stream->next.remaining) {
				/* Next hint is entirely contained in next.buf. */
				if (!rd_log_page_buf_stream_consume_bytes(stream, &stream->next, next_header->hint_len)) {
					return NULL;
				}
				stream->success = true;
				/* Return pointer to hint in next.buf */
				return (struct rd_hint_entry *)next_header;
			} else {
				/* The rest of the next hint hasn't been retrieved yet */
				stream->end_found = false;
				stream->success = true;
				return NULL;
			}
		} else {
			/* The rest of the next hint header hasn't been retrieved yet */
			stream->end_found = false;
			stream->success = true;
			return NULL;
		}
	}
}

/* Adds a decoded location_hint struct to the list in the rd_hint_buf_stream */
static void
rd_hint_buf_stream_append_hint(struct rd_hint_buf_stream *stream,
			       struct location_hint *decoded_hint)
{
	stream->decoded_hints = g_list_append(stream->decoded_hints, (gpointer)decoded_hint);
}

/* Returns first decoded location_hint struct from the list in the rd_hint_buf_stream, and remove it
 * from the list */
struct location_hint *
rd_hint_buf_stream_consume_first_hint(struct rd_hint_buf_stream *bufs)
{
	if ((NULL == bufs) || (NULL == bufs->decoded_hints)) {
		return NULL;
	}
	GList *first_item = g_list_first(bufs->decoded_hints);
	struct location_hint *decoded_hint = (struct location_hint *)first_item->data;
	bufs->decoded_hints = g_list_delete_link(bufs->decoded_hints, first_item);
	return decoded_hint;
}

/* Destroys (but doesn't free) an rd_hint_buf_stream */
void
rd_hint_buf_stream_destruct(struct rd_hint_buf_stream *bufs)
{
	struct location_hint *decoded_hint;

	assert(!bufs->destroyed);
	bufs->destroyed = true;
	while (NULL != (decoded_hint = rd_hint_buf_stream_consume_first_hint(bufs))) {
		free_location_hint(decoded_hint);
	}
}

/*
 * Consumes location hints from chunks of the hint log page.
 *
 * The hint log page may be long, and will be read in chunks. This function will be called once for each chunk, with an
 * rd_hint_buf_stream (bufs) argument. That struct records the state of the process of decoding all the hints. This
 * includes buffers for the last two chunks of the log page read. These are called bufs.prev and bufs.next.
 *
 * Initially called with no bufs.prev.buf, this will consume all the hints in bufs.next it can, and update the bufs
 * struct its passed to indicate how much of the hint list remains to be processed, and how much of bufs.next remains
 * to be processed (e.g. because a hint starts before the end of bufs.next, and extends into the next chunk of the hint
 * page).
 *
 * If there is a bufs.prev, this will consume what must be the last hint that started in that buffer. This will always
 * consume all of bufs.prev unless there is an error in the format of the hint that starts in bufs.prev.
 *
 * If the end of the hint table is found, bufs.end_found is set to true;
 *
 * If a location hint can't be decoded, bufs.success is set false. Otherwise bufs.success is set to true, whether
 * bufs.end_found is also true or not. Location hints of types not supported by this redirector are decoded (enough)
 * and ignored (leaving bufs.success true).
 *
 * Consumed hints are added to the list of learned hints for the specified target.
 *
 * See redirector_add_hint() for the hint retention and conflict resolution policy. Hints added here are all marked as
 * learned (as opposed to configured), and will be treated as such.
 *
 * TODO: clarify if/when this works like a stream of hints from each target rather than like a file containing all the
 * hints. See rd_new_hint_log_page() about generating hint streams vs. complete sets. If we were consuming a hint
 * stream here, we'd indicate to the target in the get_log_page() of the last chunk that we'd completed reading it
 * (e.g. by clearing the async event). Ideally we'd get an async notification when the page changed. We'd expect the
 * page to contain a differet set of hints the next time we read it, but would attempt to retain as many as possible
 * (applying the same basic hint replacement and redundant hint removal as we do now). We'd expect the target to be
 * sending us the hints most relevant to IO we recently sent there, and would apply them as soon as possible (ideally
 * before dispatching any currently queued IO).
 */
void
vbdev_redirector_consume_hints(struct redirector_bdev *rd_node,
			       struct redirector_target *target_config,
			       struct rd_hint_buf_stream *bufs)
{
	struct rd_log_page_buf_stream	*stream = &bufs->stream;
	char				*rx_target;
	char				local[RD_HINT_ENTRY_MAX_LEN];
	struct rd_hint_entry		*next_hint = NULL;
	struct location_hint		*decoded_hint = NULL;
	int decoded = 0;
	int ignored = 0;

	stream->end_found = false;
	stream->success = true;

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s target %s starting stream=%p, page_remaining=%zu, "
			      "prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu\n",
			      rd_node->config->redirector_name, target_config->name, stream,
			      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
			      stream->next.buf, stream->next.remaining);
	}

	if (target_config->nqn) {
		rx_target = target_config->nqn;
	} else {
		rx_target = target_config->name;
	}

	while ((next_hint = rd_get_next_hint_buf(stream, &local))) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s target %s continuing next_hint=%p stream=%p success=%d, end_found=%d, "
				      "page_remaining=%zu, prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu\n",
				      rd_node->config->redirector_name, target_config->name, next_hint, stream,
				      stream->success, stream->end_found,
				      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
				      stream->next.buf, stream->next.remaining);
		}
		decoded_hint = alloc_location_hint();
		if (!decoded_hint) {
			return;
		}
		if (rd_decode_nvme_hint(rd_node, target_config, next_hint, decoded_hint)) {
			rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "decoded:", decoded_hint);
			/* Add hint to config */
			decoded_hint->rx_target = strdup(rx_target);
			decoded++;

			switch (decoded_hint->hint_type) {
			case RD_HINT_TYPE_SIMPLE_NQN:
				rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "appending:", decoded_hint);
				rd_hint_buf_stream_append_hint(bufs, decoded_hint);
				break;
			case RD_HINT_TYPE_HASH_NQN_TABLE:
				rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "appending:", decoded_hint);
				rd_hint_buf_stream_append_hint(bufs, decoded_hint);
				bufs->num_hash_hints++;
				bufs->hash_hint = decoded_hint;
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
				rd_debug_log_hint(RD_DEBUG_LOG_NVME_HINTS, __func__, "NOT appending:", decoded_hint);
				free_location_hint(decoded_hint);
				break;
			}
		} else {
			if (RD_DEBUG_LOG_NVME_HINTS) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s target %s ignored hint %p\n",
					      rd_node->config->redirector_name, target_config->name, next_hint);
			}
			ignored++;
		}
	}

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s target %s done next_hint=%p stream=%p success=%d, end_found=%d, "
			      "page_remaining=%zu, prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu "
			      "decoded=%d, ignored=%d\n",
			      rd_node->config->redirector_name, target_config->name, next_hint, stream,
			      stream->success, stream->end_found,
			      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
			      stream->next.buf, stream->next.remaining, decoded, ignored);
	}
}

/*
 * Return the next hash table bucket (nqn index), and advance the state of the buf_stream past it.
 *
 * Buckets are small (2 bytes) and should not span log page chunks. Fail if it does.
 *
 * TODO: add static assert on header length to ensure these don't span log page chunks.
 *
 * Returns RD_INVALID_NQN_LIST_INDEX_T on fail
 */
static rd_nqn_list_index_t
rd_get_next_hash_table_bucket(struct rd_log_page_buf_stream *stream)
{
	rd_nqn_list_index_t bucket;

	assert(stream);
	if (!stream->page_remaining) {
		stream->end_found = true;
		stream->success = true;
		return RD_INVALID_NQN_LIST_INDEX_T;
	}

	if (stream->prev.remaining) {
		assert(stream->prev.buf);
		/* Next NQN spans buffers. Consume the remainder of prev. */
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Hash bucket spans log page chunk\n");
		assert(0);
		stream->success = false;
		return RD_INVALID_NQN_LIST_INDEX_T;
	} else {
		assert(stream->next.remaining);
		if (stream->next.remaining < sizeof(bucket)) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Hash bucket spans log page chunk\n");
			assert(0);
			stream->success = false;
			return RD_INVALID_NQN_LIST_INDEX_T;
		}
		/* No prev buffer. Next.buf must begin with a hash bucket */
		bucket = *(rd_nqn_list_index_t *)stream->next.buf;

		/* Consume the NQN and its NULL terminator from the buf stream */
		if (!rd_log_page_buf_stream_consume_bytes(stream, &stream->next, sizeof(bucket))) {
			return RD_INVALID_NQN_LIST_INDEX_T;
		}

		stream->success = true;
		return bucket;
	}
}

/* Destroys (but doesn't free) an rd_nqn_list_buf_stream */
void
rd_hash_table_buf_stream_destruct(struct rd_hash_table_buf_stream *bufs)
{
	free_rpc_redirector_hash_hint_hash_table(bufs->rpc_table);
}

/*
 * Consumes chunks of the hash table log page.
 *
 * The hash table log page may be long, and will be read in chunks. This function will be called once for each
 * chunk, with an rd_hash_table_buf_stream (bufs) argument. This works pretty much the same as
 * vbdev_redirector_consume_hints(), but hash buckets are 16-bit ints and can't span log page chunks.
 *
 * The hast table buckets are accumulated into an rpc_redirector_hash_hint_hash_table struct just as they are when
 * the hash hint params are read from a file. This is transformed into the internal hash_hint_table struct the same
 * way as a configured hash hint when the learned hash hint is applied.
 */
void
vbdev_redirector_consume_hash_table(struct redirector_bdev *rd_node,
				    struct redirector_target *target_config,
				    struct rd_hash_table_buf_stream *bufs)
{
	struct rd_log_page_buf_stream	*stream = &bufs->stream;
	rd_nqn_list_index_t		next_bucket;
	int				decoded = 0;

	assert(bufs);
	assert(bufs->rpc_table);
	stream->end_found = false;
	stream->success = true;

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s target %s starting stream=%p, list_remaining=%zu, "
			      "prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu\n",
			      rd_node->config->redirector_name, target_config->name, stream,
			      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
			      stream->next.buf, stream->next.remaining);
	}

	while (RD_INVALID_NQN_LIST_INDEX_T != (next_bucket = rd_get_next_hash_table_bucket(stream))) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s target %s continuing next_bucket=%u stream=%p success=%d, "
				      "end_found=%d, list_remaining=%zu, prev=%p prev.remaining=%zu, next=%p, "
				      "next.remaining=%zu\n",
				      rd_node->config->redirector_name, target_config->name, next_bucket, stream,
				      stream->success, stream->end_found,
				      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
				      stream->next.buf, stream->next.remaining);
		}

		/* Add bucket to config */
		bufs->rpc_table->buckets[bufs->next_bucket++] = next_bucket;

		decoded++;
	}

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s target %s done next_bucket=%u stream=%p success=%d, end_found=%d, "
			      "list_remaining=%zu, prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu "
			      "decoded=%d\n",
			      rd_node->config->redirector_name, target_config->name, next_bucket, stream,
			      stream->success, stream->end_found,
			      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
			      stream->next.buf, stream->next.remaining, decoded);
	}
}

/*
 * Return a pointer to the next nqn string, and advance the state of the buf_stream past it.
 *
 * If the next nqn spans the prev and next bufs, copy it to the provided temp buf and return a pointer
 * to that. Otherwise skip the copy and return a pointer to the nqn in whichever buffer it's in.
 */
static char *
rd_get_next_nqn_buf(struct rd_log_page_buf_stream *stream, void *temp)
{
	size_t				nqn_bytes_remaining = RD_NQN_LEN;
	size_t				next_nqn_len;
	size_t				next_nqn_tail_len;
	char				*next_nqn = NULL;
	char				*next_nqn_tail = NULL;

	assert(stream);
	if (!stream->page_remaining) {
		stream->end_found = true;
		stream->success = true;
		return NULL;
	}

	if (stream->prev.remaining) {
		assert(stream->prev.buf);
		/* Next NQN spans buffers. Consume the remainder of prev. */
		next_nqn = temp;
		next_nqn_len = strnlen(stream->prev.buf, stream->prev.remaining);
		if (next_nqn_len > nqn_bytes_remaining) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Next NQN too long\n");
			stream->success = false;
			return NULL;
		}
		strncpy(next_nqn, stream->prev.buf, next_nqn_len);
		nqn_bytes_remaining -= stream->prev.remaining;
		next_nqn_tail = next_nqn + next_nqn_len;

		/* Consume the (unterminated) NQN head from the prev buffer */
		if (!rd_log_page_buf_stream_consume_bytes(stream, &stream->prev, stream->prev.remaining)) {
			/* fail */
			return NULL;
		}

		/* Find the last part of the NQN */
		assert(!stream->prev.remaining);
		assert(stream->next.remaining);

		/* Confirm there's a NULL terminted string at next buf. Might be zero length. */
		next_nqn_tail_len = strnlen(stream->next.buf, stream->next.remaining);
		if (next_nqn_tail_len > nqn_bytes_remaining) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Next NQN too long\n");
			stream->success = false;
			return NULL;
		}

		strncpy(next_nqn_tail, stream->next.buf, next_nqn_tail_len);

		/* Consume NQN tail and its NULL terminator from the buf stream */
		if (!rd_log_page_buf_stream_consume_bytes(stream, &stream->next, next_nqn_tail_len + 1)) {
			return NULL;
		}

		stream->success = true;
		return next_nqn;
	} else {
		assert(stream->next.remaining);
		/* No prev buffer. Next.buf must begin with an NQN */
		next_nqn = stream->next.buf;

		/* Confirm there's a NULL terminted string at next buf */
		next_nqn_len = strnlen(next_nqn, stream->next.remaining);
		if (next_nqn_len > nqn_bytes_remaining) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Next NQN too long\n");
			stream->success = false;
			return NULL;
		}

		/* If the NQN fills the rest of the buffer, it spills into the next buffer */
		if (next_nqn_len == stream->next.remaining) {
			stream->success = true;
			return NULL;
		}

		/* There's a NULL terminated string <= RD_NQN_LEN at next_nqn. */

		/* Consume the NQN and its NULL terminator from the buf stream */
		if (!rd_log_page_buf_stream_consume_bytes(stream, &stream->next, next_nqn_len + 1)) {
			return NULL;
		}

		stream->success = true;
		return next_nqn;
	}
}

/* Destroys (but doesn't free) an rd_nqn_list_buf_stream */
void
rd_nqn_list_buf_stream_destruct(struct rd_nqn_list_buf_stream *bufs)
{
	free_rpc_redirector_hash_hint_nqn_table(bufs->rpc_table);
}

/*
 * Consumes chunks of the nqn list log page.
 *
 * The nqn list log page may be long, and will be read in chunks. This function will be called once for each chunk,
 * with an rd_nqn_list_buf_stream (bufs) argument. This works pretty much the same as vbdev_redirector_consume_hints().
 *
 * The NQNs are accumulated into an rpc_redirector_hash_hint_nqn_table struct just as they are when the hash hint
 * params are read from a file. This is transformed into the internal nqn_list struct the same way as a configured
 * hash hint when the learned hash hint is applied.
 */
void
vbdev_redirector_consume_nqn_list(struct redirector_bdev *rd_node,
				  struct redirector_target *target_config,
				  struct rd_nqn_list_buf_stream *bufs)
{
	struct rd_log_page_buf_stream	*stream = &bufs->stream;
	char				local[RD_NQN_LEN + 1];
	char				*next_nqn;
	char				*next_nqn_dup;
	int				decoded = 0;

	assert(bufs);
	assert(bufs->rpc_table);
	stream->end_found = false;
	stream->success = true;

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s target %s starting stream=%p, list_remaining=%zu, "
			      "prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu\n",
			      rd_node->config->redirector_name, target_config->name, stream,
			      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
			      stream->next.buf, stream->next.remaining);
	}

	while ((next_nqn  = rd_get_next_nqn_buf(stream, &local))) {
		if (RD_DEBUG_LOG_NVME_HINTS) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s target %s continuing next_nqn=%p stream=%p success=%d, end_found=%d, "
				      "list_remaining=%zu, prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu\n",
				      rd_node->config->redirector_name, target_config->name, next_nqn, stream,
				      stream->success, stream->end_found,
				      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
				      stream->next.buf, stream->next.remaining);
		}

		/* Add NQN to config */
		if (strlen(next_nqn)) {
			next_nqn_dup = strdup(next_nqn);
			if (!next_nqn_dup) {
				stream->success = false;
				return;
			}
			bufs->rpc_table->nqns[bufs->next_nqn++] = next_nqn_dup;
		}

		decoded++;
	}

	if (RD_DEBUG_LOG_NVME_HINTS) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s target %s done next_nqn=%p stream=%p success=%d, end_found=%d, "
			      "list_remaining=%zu, prev=%p prev.remaining=%zu, next=%p, next.remaining=%zu "
			      "decoded=%d\n",
			      rd_node->config->redirector_name, target_config->name, next_nqn, stream,
			      stream->success, stream->end_found,
			      stream->page_remaining, stream->prev.buf, stream->prev.remaining,
			      stream->next.buf, stream->next.remaining, decoded);
	}
}
