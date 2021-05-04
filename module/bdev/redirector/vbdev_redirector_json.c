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
 * Functions for emitting redirector JSON objects for various RPC responses
 * and file output (if any).
 */
#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_json.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector_channel.h"
#include "vbdev_redirector.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

int
vbdev_redirector_dump_targets_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;
	size_t target_bdev_index;
	struct redirector_bdev_target *rbt;
	struct redirector_target *rbt_conf;

	spdk_json_write_name(w, "targets");
	spdk_json_write_array_begin(w);
	for (target_bdev_index = 0;
	     target_bdev_index < rd_node->num_rd_targets;
	     target_bdev_index++) {
		rbt = &rd_node->targets[target_bdev_index];
		spdk_json_write_object_begin(w);
		spdk_json_write_named_uint64(w, "index", (uint64_t)target_bdev_index);
		spdk_json_write_named_bool(w, "configured", rbt->target_config != NULL);
		spdk_json_write_named_bool(w, "allocated", !rbt->free_index);
		spdk_json_write_named_bool(w, "opened", rbt->desc != NULL);
		spdk_json_write_named_bool(w, "drain", rbt->drain);
		spdk_json_write_named_bool(w, "reading_hints", rbt->reading_hints);
		spdk_json_write_named_uint64(w, "max_qd", (uint64_t)rbt->max_qd);
		if (!rbt->free_index) {
			if (rbt->bdev) {
				spdk_json_write_named_string(w, "name", spdk_bdev_get_name(rbt->bdev));
			}
			rbt_conf = rbt->target_config;
			if (rbt_conf) {
				spdk_json_write_named_uint64(w, "config_target_index",
							     (uint64_t)rbt_conf->target_index);
				spdk_json_write_named_bool(w, "persistent", rbt_conf->persistent);
				spdk_json_write_named_bool(w, "required", rbt_conf->required);
				spdk_json_write_named_bool(w, "redirector", rbt_conf->redirector);
				spdk_json_write_named_bool(w, "dont_probe", rbt_conf->dont_probe);
				spdk_json_write_name(w, "state");
				spdk_json_write_object_begin(w);
				if (rbt_conf->nqn) {
					spdk_json_write_named_string(w, "nqn", rbt_conf->nqn);
				}
				if (rd_target_uuid_known(rbt_conf)) {
					char uuid_str[SPDK_UUID_STRING_LEN];
					int rc = spdk_uuid_fmt_lower(uuid_str, sizeof(uuid_str), &rbt_conf->uuid);
					assert(rc == 0);
					spdk_json_write_named_string(w, "uuid", uuid_str);
				}
				if (rbt_conf->ctrlr_data.mn[0]) {
					char buf[SPDK_NVME_CTRLR_MN_LEN + 1] = { '\0' };
					strncat(buf, rbt_conf->ctrlr_data.mn, SPDK_NVME_CTRLR_MN_LEN);
					spdk_json_write_named_string(w, "mn", buf);
				}
				if (rbt_conf->ctrlr_data.sn[0]) {
					char buf[SPDK_NVME_CTRLR_SN_LEN + 1] = { '\0' };
					strncat(buf, rbt_conf->ctrlr_data.sn, SPDK_NVME_CTRLR_SN_LEN);
					spdk_json_write_named_string(w, "sn", buf);
				}
				spdk_json_write_named_bool(w, "registered", rbt_conf->registered);
				spdk_json_write_named_bool(w, "removing", rbt_conf->removing);
				spdk_json_write_named_bool(w, "hotremove", rbt_conf->hotremove);
				spdk_json_write_named_bool(w, "auth_target", rbt_conf->auth_target);
				spdk_json_write_named_bool(w, "confirmed_redir", rbt_conf->confirmed_redir);
				spdk_json_write_named_bool(w, "confirmed_not_redir", rbt_conf->confirmed_not_redir);
				spdk_json_write_named_bool(w, "get_hints_once", rbt_conf->get_hints_once);
				spdk_json_write_named_bool(w, "uuid_mismatch", rbt_conf->uuid_mismatch);
				/* Target stats */
				spdk_json_write_named_uint64(w, "removed_count", rbt_conf->stats.removed_count);
				spdk_json_write_named_uint64(w, "hot_removed_count", rbt_conf->stats.hot_removed_count);
				spdk_json_write_named_uint64(w, "io_count", rbt_conf->stats.io_count);
				spdk_json_write_named_uint64(w, "queued_io_count", rbt_conf->stats.queued_io_count);
				spdk_json_write_named_uint64(w, "ios_in_flight", rbt_conf->stats.ios_in_flight);
				spdk_json_write_named_uint64(w, "ios_queued", rbt_conf->stats.ios_queued);
				/* Target learned hint stats */
				spdk_json_write_name(w, "learned_hints");
				spdk_json_write_object_begin(w);
				spdk_json_write_named_uint64(w, "generation", rbt_conf->hint_stats.generation);
				spdk_json_write_named_uint64(w, "hint_poll_count", rbt_conf->hint_stats.hint_poll_count);
				spdk_json_write_named_uint64(w, "hint_notify_count", rbt_conf->hint_stats.hint_notify_count);
				spdk_json_write_named_uint64(w, "hint_update_count", rbt_conf->hint_stats.hint_update_count);
				spdk_json_write_named_uint64(w, "hint_replace_count", rbt_conf->hint_stats.hint_replace_count);
				/* End of learned_hints: {} */
				spdk_json_write_object_end(w);
				/* End of state: {} */
				spdk_json_write_object_end(w);
			}
		}
		spdk_json_write_object_end(w);
	}
	spdk_json_write_array_end(w);

	return 0;
}

#define RD_LIST_DIGEST_STRING_BUF_BYTES (2*RD_LIST_DIGEST_BYTES + 1)

/*
 * Format an rd_list_digest_t as a string, where each digest byte is a 2-digit hex number.
 * Hash bytes appeaer in the string starting at byte 0 on the left of the string.
 *
 * TODO: Should byte 0 come last? How are hashes normally displayed?
 *
 * Return: 0 = success
 */
static int
rd_list_digest_string(char *digest_string_buf, int digest_string_buf_len,
		      const rd_list_digest_t *digest)
{
	assert(digest_string_buf_len >= RD_LIST_DIGEST_STRING_BUF_BYTES);
	*digest_string_buf = '\0';
	size_t digest_byte;
	char digest_byte_str[8];
	int rc;
	for (digest_byte = 0; digest_byte < RD_LIST_DIGEST_BYTES; digest_byte++) {
		rc = snprintf(digest_byte_str, sizeof(digest_byte_str), "%02x", digest->digest_bytes[digest_byte]);
		if ((rc < 0) || (rc > (int)sizeof(digest_byte_str))) {
			return rc;
		}
		strncat(digest_string_buf, digest_byte_str, digest_string_buf_len);
	}
	return 0;
}

static int
vbdev_redirector_write_rd_list_digest_json(const char *name,
		const rd_list_digest_t *digest,
		struct spdk_json_write_ctx *w)
{
	char digest_string[RD_LIST_DIGEST_STRING_BUF_BYTES];

	if (0 == rd_list_digest_string(digest_string, sizeof(digest_string), digest)) {
		spdk_json_write_named_string(w, name, digest_string);
	}
	return 0;
}

static int
vbdev_redirector_dump_nqn_list_json(struct nqn_list *nqn_list, struct spdk_json_write_ctx *w)
{
	if (!nqn_list) {
		return 0;
	}

	spdk_json_write_named_object_begin(w, "nqn_list");
	if (nqn_list->generation_valid) {
		spdk_json_write_named_uint64(w, "generation", nqn_list->generation);
	}
	if (nqn_list->digest_valid) {
		vbdev_redirector_write_rd_list_digest_json("digest", &nqn_list->digest, w);
	}
	spdk_json_write_name(w, "nqns");
	spdk_json_write_array_begin(w);
	size_t nqn_iter;
	for (nqn_iter = 0; nqn_iter < nqn_list->num_nqns; nqn_iter++) {
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "nqn", g_quark_to_string(nqn_list->nqns[nqn_iter].nqn));
		spdk_json_write_named_int64(w, "target_index", nqn_list->nqns[nqn_iter].target_index);
		spdk_json_write_object_end(w);
	}
	spdk_json_write_array_end(w);
	spdk_json_write_object_end(w);
	return 0;
}

static int
vbdev_redirector_dump_hash_hint_table_json(struct hash_hint_table *hash_table,
		struct spdk_json_write_ctx *w)
{
	if (!hash_table) {
		return 0;
	}

	spdk_json_write_named_object_begin(w, "hash_table");
	spdk_json_write_named_uint64(w, "buckets", (uint64_t)hash_table->num_buckets);
	if (hash_table->generation_valid) {
		spdk_json_write_named_uint64(w, "generation", hash_table->generation);
	}
	if (hash_table->digest_valid) {
		vbdev_redirector_write_rd_list_digest_json("digest", &hash_table->digest, w);
	}
	/* Actual hash table buckets omitted */
	spdk_json_write_object_end(w);

	return 0;
}

/* This is the output for get_bdevs() for this vbdev */
int
vbdev_redirector_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct redirector_bdev *rd_node = (struct redirector_bdev *)ctx;
	GSequenceIter *rule_iter;
	struct location_hint *iter_rule;
	GSequenceIter *hint_iter;
	struct location_hint *iter_hint;

	if (RD_DEBUG_LOG_JSON_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "vbdev_redirector_dump_info_json(%s)\n",
			      spdk_bdev_get_name(&rd_node->redirector_bdev));
	}
	/* Refresh channel stats */
	vbdev_redirector_update_channel_state_sync(rd_node);
	spdk_json_write_name(w, "redirector");
	spdk_json_write_object_begin(w);
	/* Config */
	spdk_json_write_named_string(w, "name", spdk_bdev_get_name(&rd_node->redirector_bdev));
	if (rd_node->config->nqn) {
		spdk_json_write_named_string(w, "nqn", rd_node->config->nqn);
	}
	if (rd_uuid_known(rd_node->config)) {
		char uuid_str[SPDK_UUID_STRING_LEN];
		int rc = spdk_uuid_fmt_lower(uuid_str, sizeof(uuid_str), &rd_node->config->uuid);
		assert(rc == 0);
		spdk_json_write_named_string(w, "uuid", uuid_str);
	}
	spdk_json_write_named_uint64(w, "blockcnt", rd_node->config->blockcnt);
	spdk_json_write_named_uint32(w, "blocklen", rd_node->config->blocklen);
	spdk_json_write_named_uint32(w, "required_alignment", rd_node->config->required_alignment);
	spdk_json_write_named_uint32(w, "optimal_io_boundary", rd_node->config->optimal_io_boundary);
	spdk_json_write_named_bool(w, "uuid_inherited", rd_node->config->uuid_inherited);
	spdk_json_write_named_bool(w, "uuid_generated", rd_node->config->uuid_generated);
	spdk_json_write_named_bool(w, "auth_hints", rd_node->config->auth_hints);
	/* Bdev */
	spdk_json_write_named_int64(w, "tgt_adm_cmd_in_flight", rd_node->tgt_adm_cmd_in_flight);
	spdk_json_write_named_int64(w, "num_self_ref", rd_node->num_self_ref);
	spdk_json_write_named_bool(w, "registered", rd_node->registered);
	spdk_json_write_named_bool(w, "updating_channels", rd_node->updating_channels);
	spdk_json_write_named_bool(w, "updating_channel_rules", rd_node->updating_channel_rules);
	spdk_json_write_named_bool(w, "rule_update_pending", rd_node->rule_update_pending);
	spdk_json_write_named_bool(w, "target_update_pending", rd_node->target_update_pending);
	spdk_json_write_named_bool(w, "other_update_pending", rd_node->other_update_pending);
	spdk_json_write_named_bool(w, "reset_in_progress", rd_node->reset_in_progress);
	spdk_json_write_named_uint64(w, "rule_updates", (uint64_t)rd_node->stats.rule_updates);
	spdk_json_write_named_uint64(w, "target_updates", (uint64_t)rd_node->stats.target_updates);
	spdk_json_write_named_uint64(w, "channel_updates", (uint64_t)rd_node->stats.channel_updates);
	spdk_json_write_named_uint64(w, "hot_removes", (uint64_t)rd_node->stats.hot_removes);
	spdk_json_write_named_uint64(w, "channel_count", (uint64_t)rd_node->stats.channel_count);
	spdk_json_write_named_uint64(w, "channels_drained", (uint64_t)rd_node->stats.channels_drained);
	spdk_json_write_named_uint64(w, "channel_ios_drained",
				     (uint64_t)rd_node->stats.channel_ios_drained);
	spdk_json_write_named_uint64(w, "num_targets", (uint64_t)rd_node->num_rd_targets);
	vbdev_redirector_dump_targets_json(ctx, w);
	/* Dump locations */
	spdk_json_write_named_uint64(w, "hint_page_generation", (uint64_t)rd_node->hint_page.generation);
	spdk_json_write_name(w, "locations");
	spdk_json_write_array_begin(w);
	hint_iter = g_sequence_get_begin_iter(rd_node->config->hints);
	while (!g_sequence_iter_is_end(hint_iter)) {
		iter_hint = (struct location_hint *)g_sequence_get(hint_iter);
		spdk_json_write_object_begin(w);
		spdk_json_write_named_uint64(w, "start_lba", iter_hint->extent.start_lba);
		spdk_json_write_named_uint64(w, "blocks", iter_hint->extent.blocks);
		spdk_json_write_named_string(w, "hint_type", rd_hint_type_name[location_hint_type(iter_hint)]);
		if (iter_hint->rx_target) {
			/* Locations with a source were learned from that named target */
			spdk_json_write_named_string(w, "hint_source", iter_hint->rx_target);
		}
		switch (location_hint_type(iter_hint)) {
		case RD_HINT_TYPE_SIMPLE_NQN:
		case RD_HINT_TYPE_SIMPLE_NQN_NS:
			spdk_json_write_named_string(w, "target", location_hint_target_name(iter_hint));
			spdk_json_write_named_uint64(w, "target_start_lba", location_hint_target_start_lba(iter_hint));
			spdk_json_write_named_int64(w, "target_index", iter_hint->target_index);
			break;
		case RD_HINT_TYPE_HASH_NQN_TABLE:
			if (rd_hash_fn_id_name[iter_hint->hash.hash_function_id]) {
				spdk_json_write_named_string(w, "hash_fn",
							     rd_hash_fn_id_name[iter_hint->hash.hash_function_id]);
			}
			spdk_json_write_named_string(w, "object_name_format", iter_hint->hash.object_name_format);
			spdk_json_write_named_uint64(w, "object_bytes", iter_hint->hash.object_bytes);
			if (iter_hint->hash.persist_state.hint_params_file) {
				spdk_json_write_named_string(w, "hash_hint_file",
							     iter_hint->hash.persist_state.hint_params_file);
			}
			vbdev_redirector_dump_nqn_list_json(iter_hint->hash.nqn_list, w);
			vbdev_redirector_dump_hash_hint_table_json(iter_hint->hash.hash_table, w);
			break;
		default:
			break;
		}
		spdk_json_write_named_bool(w, "authoritative", iter_hint->authoritative);
		spdk_json_write_named_bool(w, "persistent", iter_hint->persistent);
		spdk_json_write_object_end(w);
		hint_iter = g_sequence_iter_next(hint_iter);
	}
	spdk_json_write_array_end(w);
	/* Dump current rule table */
	spdk_json_write_name(w, "applied_rules");
	spdk_json_write_array_begin(w);
	rule_iter = g_sequence_get_begin_iter(rd_node->applied_rules);
	while (!g_sequence_iter_is_end(rule_iter)) {
		iter_rule = (struct location_hint *)g_sequence_get(rule_iter);
		spdk_json_write_object_begin(w);
		spdk_json_write_named_uint64(w, "start_lba", iter_rule->extent.start_lba);
		spdk_json_write_named_string(w, "hint_type", rd_hint_type_name[location_hint_type(iter_rule)]);
		spdk_json_write_named_int64(w, "target_index", iter_rule->target_index);
		/* Block count not relevant for rules */
		switch (location_hint_type(iter_rule)) {
		case RD_HINT_TYPE_SIMPLE_NQN:
			spdk_json_write_named_uint64(w, "target_start_lba",
						     location_hint_target_start_lba(iter_rule));
			spdk_json_write_named_string(w, "target", location_hint_target_name(iter_rule));
			break;
		case RD_HINT_TYPE_HASH_NQN_TABLE:
			if (rd_hash_fn_id_name[iter_rule->hash.hash_function_id]) {
				spdk_json_write_named_string(w, "hash_fn",
							     rd_hash_fn_id_name[iter_rule->hash.hash_function_id]);
			}
			spdk_json_write_named_string(w, "object_name_format", iter_rule->hash.object_name_format);
			spdk_json_write_named_uint64(w, "object_bytes", iter_rule->hash.object_bytes);
			if (iter_rule->hash.persist_state.hint_params_file) {
				spdk_json_write_named_string(w, "hash_hint_file",
							     iter_rule->hash.persist_state.hint_params_file);
			}
			vbdev_redirector_dump_nqn_list_json(iter_rule->hash.nqn_list, w);
			vbdev_redirector_dump_hash_hint_table_json(iter_rule->hash.hash_table, w);
			break;
		default:
			break;
		}
		spdk_json_write_named_bool(w, "authoritative", iter_rule->authoritative);
		spdk_json_write_named_bool(w, "nqn_target", iter_rule->nqn_target);
		spdk_json_write_named_bool(w, "default_rule", iter_rule->default_rule);
		if (iter_rule->rx_target) {
			spdk_json_write_named_string(w, "hint_source", iter_rule->rx_target);
		}
		spdk_json_write_object_end(w);
		rule_iter = g_sequence_iter_next(rule_iter);
	}
	spdk_json_write_array_end(w);
	spdk_json_write_object_end(w);
	if (RD_DEBUG_LOG_JSON_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "vbdev_redirector_dump_info_json(%s) - exit\n",
			      spdk_bdev_get_name(&rd_node->redirector_bdev));
	}

	return 0;
}

/*
 * This is used to generate JSON that can configure this module to its current
 * state.  We include construct RPC calls for any configured redirector,
 * whether the bdev for it has been created yet or not. That includes the
 * targets marked as both persistent (in the configuration) and as
 * redirectors. We include an add_target RPC for any target marked persistent
 * but not marked as a redirector.
 */
int
vbdev_redirector_config_json(struct spdk_json_write_ctx *w)
{
	struct redirector_config *config;
	GSequenceIter *target_iter;
	struct redirector_target *target;
	GSequenceIter *hint_iter;
	struct location_hint *iter_hint;

	if (RD_DEBUG_LOG_JSON_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "vbdev_redirector_config_json()\n");
	}
	TAILQ_FOREACH(config, &g_redirector_config, config_link) {
		/* Emit construct_redirector_bdev RPC */
		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "method", "construct_redirector_bdev");
		spdk_json_write_named_object_begin(w, "params");
		spdk_json_write_named_string(w, "name", config->redirector_name);
		/* Persist non-NULL UUID in config, whether it was configured, inherited, or generated */
		if (rd_uuid_known(config)) {
			char uuid_str[SPDK_UUID_STRING_LEN];
			int rc = spdk_uuid_fmt_lower(uuid_str, sizeof(uuid_str), &config->uuid);
			assert(rc == 0);
			spdk_json_write_named_string(w, "uuid", uuid_str);
		}
		if (config->nqn) {
			spdk_json_write_named_string(w, "nqn", config->nqn);
		}
		spdk_json_write_named_bool(w, "size_configured", config->size_configured);
		if (config->size_configured) {
			spdk_json_write_named_uint64(w, "blockcnt", config->blockcnt);
			spdk_json_write_named_uint32(w, "blocklen", config->blocklen);
			spdk_json_write_named_uint32(w, "required_alignment", config->required_alignment);
			spdk_json_write_named_uint32(w, "optimal_io_boundary", config->optimal_io_boundary);
		}
		spdk_json_write_name(w, "default_target_names");
		spdk_json_write_array_begin(w);
		target_iter = g_sequence_get_begin_iter(config->targets);
		/* Default target list for redirector contains only other redirectors */
		while (!g_sequence_iter_is_end(target_iter)) {
			target = (struct redirector_target *)g_sequence_get(target_iter);
			if (target->persistent && target->redirector && !target->removing) {
				spdk_json_write_string(w, target->name);
			}
			target_iter = g_sequence_iter_next(target_iter);
		}
		spdk_json_write_array_end(w);
		spdk_json_write_object_end(w);
		spdk_json_write_object_end(w);

		/* Emit redirector_add_hint RPCs */
		hint_iter = g_sequence_get_begin_iter(config->hints);
		while (!g_sequence_iter_is_end(hint_iter)) {
			iter_hint = (struct location_hint *)g_sequence_get(hint_iter);
			if (iter_hint->persistent) {
				switch (location_hint_type(iter_hint)) {
				case RD_HINT_TYPE_SIMPLE_NQN:
				case RD_HINT_TYPE_SIMPLE_NQN_NS:
					spdk_json_write_object_begin(w);
					spdk_json_write_named_string(w, "method", "redirector_add_hint");
					spdk_json_write_named_object_begin(w, "params");
					spdk_json_write_named_string(w, "redirector", config->redirector_name);
					spdk_json_write_named_string(w, "target", location_hint_target_name(iter_hint));
					spdk_json_write_named_uint64(w, "start_lba", iter_hint->extent.start_lba);
					spdk_json_write_named_uint64(w, "blocks", iter_hint->extent.blocks);
					spdk_json_write_named_uint64(w, "target_start_lba",
								     location_hint_target_start_lba(iter_hint));
					spdk_json_write_named_bool(w, "persistent_config", iter_hint->persistent);
					spdk_json_write_named_bool(w, "authoritative", iter_hint->authoritative);
					spdk_json_write_object_end(w);
					spdk_json_write_object_end(w);
					break;
				case RD_HINT_TYPE_HASH_NQN_TABLE:
					/* TODO: instead of the file, emit the hash fn, NQN list, and table generation/digests */
					spdk_json_write_object_begin(w);
					spdk_json_write_named_string(w, "method", "redirector_add_hash_hint");
					spdk_json_write_named_object_begin(w, "params");
					spdk_json_write_named_string(w, "redirector", config->redirector_name);
					spdk_json_write_named_string(w, "hash_hint_file",
								     iter_hint->hash.persist_state.hint_params_file);
					spdk_json_write_named_bool(w, "persistent_config", iter_hint->persistent);
					spdk_json_write_named_bool(w, "authoritative", iter_hint->authoritative);
					spdk_json_write_object_end(w);
					spdk_json_write_object_end(w);
					break;
				default:
					break;
				}
			}
			hint_iter = g_sequence_iter_next(hint_iter);
		}

		/* Emit redirector_add_target RPCs */
		target_iter = g_sequence_get_begin_iter(config->targets);
		/* Persistent redirector targets listed above. Add only non-redirectors here. */
		while (!g_sequence_iter_is_end(target_iter)) {
			target = (struct redirector_target *)g_sequence_get(target_iter);
			if (target->persistent && !target->redirector && !target->removing) {
				spdk_json_write_object_begin(w);
				spdk_json_write_named_string(w, "method", "redirector_add_target");
				spdk_json_write_named_object_begin(w, "params");
				spdk_json_write_named_string(w, "redirector", config->redirector_name);
				spdk_json_write_named_string(w, "target", target->name);
				spdk_json_write_named_bool(w, "persistent_config", target->persistent);
				spdk_json_write_named_bool(w, "required", target->required);
				spdk_json_write_named_bool(w, "is_redirector", target->redirector);
				spdk_json_write_named_bool(w, "dont_probe", target->dont_probe);
				spdk_json_write_object_end(w);
				spdk_json_write_object_end(w);
			}
			target_iter = g_sequence_iter_next(target_iter);
		}
	}
	if (RD_DEBUG_LOG_JSON_STUFF) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "vbdev_redirector_config_json() - exit\n");
	}
	return 0;
}
