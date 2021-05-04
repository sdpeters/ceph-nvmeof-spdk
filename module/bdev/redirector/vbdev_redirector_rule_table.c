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
 * Generates the redirector rule table from the current set of configured and learned hints,
 * and the currently available targets.
 *
 * The accumulated set of hints can contain contradictions and ambiguities. A redirector is
 * free to resolve these in whatever way is best for the redirector.  Thia process produces
 * what we call the rule table. The rule table is completely unabmiguous. The redirector data
 * plane only ever sees the rule table, and leaves the resolution of ambiguity in the learned
 * hints to the control plane.
 *
 * This module prepares the rule table the data plane should use. The new rule table is
 * deployed to the data plane by the channel state management module.
 *
 * The rule table is essentially a map of LBAs in the namespace to the target that IO will be
 * routed to. This is conceptually an array of LBA,target pairs sorted by LBA. The data plane
 * can then binary search on the last rule table entry with an LBA<= the starting LBA of the
 * IO, then send the IO to that target.
 *
 * The rule table identifies targets by their target index. This is assigned by the target
 * state managment module. A target's index doesn't change unless it's removed. The data plane
 * maintains per-target state in an array based on the target index.
 *
 * The rule table is tightly coupled with the current target connectivity state. Rule table
 * entries must refer to currently valid target indexes. The channe state module ensures the
 * target state and rule table updates are sequenced to ensure this.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_nvme_hints.h"
#include "vbdev_redirector_rule_table.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector.h"
#include "spdk_internal/log.h"

static inline void
rule_stack_push(GList **rule_stack, struct location_hint *rule)
{
	assert(rule_stack);
	*rule_stack = g_list_prepend(*rule_stack, rule);
}

static inline bool
rule_stack_empty(GList **rule_stack)
{
	assert(rule_stack);
	return (*rule_stack == NULL);
}

static inline struct location_hint *
rule_stack_top(GList **rule_stack)
{
	struct location_hint *hint;

	assert(rule_stack);
	if (rule_stack_empty(rule_stack)) {
		return NULL;
	}
	hint = (struct location_hint *)g_list_first(*rule_stack)->data;
	rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "tos", hint);
	return hint;
}

static inline void
rule_stack_pop(GList **rule_stack, struct location_hint **rule)
{
	assert(rule_stack);
	*rule_stack = g_list_delete_link(*rule_stack, g_list_first(*rule_stack));
}

/* When there's a real rule table structure, these should be part of it */
struct rule_table_hash_params {
	bool rule_table_contains_hash_hint;
	struct hash_hint_table *hash_table;
	struct nqn_list *nqn_list;
};

static int
_rule_table_add(GSequence *rule_table,
		struct rule_table_hash_params *hash_params,
		uint64_t start_lba,
		struct location_hint *hint)
{
	struct location_hint *new_hint = NULL;
	struct nqn_list *nqn_list = NULL;
	struct hash_hint_table *hash_table = NULL;

	/* The location hint structs used as rule table entries must have extent.blocks == 0 */
	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
		new_hint = alloc_simple_hint(start_lba, 0, location_hint_target_name(hint),
					     start_lba - hint->extent.start_lba + location_hint_target_start_lba(hint),
					     hint->rx_target, hint->persistent, hint->authoritative);
		new_hint->hint_type = RD_HINT_TYPE_SIMPLE_NQN_NS;
		break;
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		hash_table = duplicate_hash_hint_table(hint->hash.hash_table);
		nqn_list = duplicate_nqn_list(hint->hash.nqn_list);
		new_hint = alloc_hash_hint(hint->hash.hash_function_id,
					   hint->hash.object_bytes,
					   hint->hash.object_name_format,
					   nqn_list, hash_table,
					   hint->rx_target,
					   hint->persistent,
					   hint->authoritative);
		if (new_hint) {
			new_hint->extent.blocks = 0;
			if (hash_params) {
				hash_params->rule_table_contains_hash_hint = true;
				hash_params->hash_table = hash_table;
				hash_params->nqn_list = nqn_list;
			}
		}
		break;
	default:
		break;
	}
	if (!new_hint) {
		free(hash_table);
		free(nqn_list);
		return -ENOMEM;
	}
	new_hint->rule_table = true;
	rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "adding", new_hint);
	g_sequence_insert_sorted(rule_table,
				 (gpointer)new_hint,
				 location_hint_data_compare_fn,
				 NULL);
	/* Other flags copied for debug. Could be omitted */
	new_hint->target_index = hint->target_index;
	new_hint->default_rule = hint->default_rule;
	return 0;
}

static int
rule_table_add(struct redirector_config *config,
	       GSequence *rule_table,
	       struct rule_table_hash_params *hash_params,
	       uint64_t start_lba,
	       struct location_hint *hint)
{
	int rc = _rule_table_add(rule_table, hash_params, start_lba, hint);

	if (rc) {
		return rc;
	}

	if (spdk_likely(!g_shutdown_started)) {
		assert(hint->target_index != -1);
		if (config->redirector_bdev->targets[hint->target_index].target_config &&
		    !target_index_sticky(config->redirector_bdev->targets[hint->target_index].target_config)) {
			assert(config->redirector_bdev->targets[hint->target_index].bdev);
			assert(config->redirector_bdev->targets[hint->target_index].desc);
		}
	}
	return 0;
}

static void
rule_table_entry_duplicate(gpointer data, gpointer user_data)
{
	struct location_hint *hint = (struct location_hint *)data;

	_rule_table_add((GSequence *)user_data, NULL, hint->extent.start_lba, hint);
}

const GFunc rule_table_entry_duplicate_fn = rule_table_entry_duplicate;

GSequence *
rule_table_duplicate(GSequence *rule_table)
{
	GSequence *duplicate;

	duplicate = g_sequence_new(location_hint_destroy_fn);
	g_sequence_foreach(rule_table, rule_table_entry_duplicate_fn, duplicate);
	return duplicate;
}

/*
 * Get the target index of the specified NQN. If multiple targets with the matching NQN are available and
 * usable, the one with the highest priority will be chosen.
 */
static int
rd_get_nqn_target_index(struct redirector_bdev *rd_node, const char *nqn)
{
	GSequenceIter *nqn_iter;
	struct redirector_target *iter_target;
	struct redirector_target *first_usable = NULL;

	nqn_iter = redirector_config_find_first_target_by_nqn_iter(rd_node->config, nqn);
	do {
		if (nqn_iter && !g_sequence_iter_is_end(nqn_iter)) {
			iter_target = g_sequence_get(nqn_iter);
			if (RD_DEBUG_LOG_NQN_TARGET) {
				SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
					      "Redirector %s hint_target=%s considering=%s\n",
					      rd_node->config->redirector_name, nqn,
					      iter_target->name);
			}
			if (!iter_target->removing && !rd_target_unusable(iter_target->target_index)) {
				if (!first_usable) {
					/* If none of the rest are available, we'll use this */
					first_usable = iter_target;
				}
				if (!rd_target_unavailable(rd_node, iter_target->target_index)) {
					/* Choose this target */
					if (RD_DEBUG_LOG_NQN_TARGET) {
						SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
							      "Redirector %s nqn_target=%s using %s (%d)\n",
							      rd_node->config->redirector_name,
							      nqn,
							      iter_target->name, iter_target->target_index);
					}
					return iter_target->target_index;
				}
			}
			nqn_iter = redirector_config_find_next_target_by_nqn_iter(rd_node->config, nqn_iter);
		}
	} while (nqn_iter && !g_sequence_iter_is_end(nqn_iter));

	if (RD_DEBUG_LOG_NQN_TARGET) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s nqn_target=%s no available target bdevs\n",
			      rd_node->config->redirector_name, nqn);
	}
	if (first_usable) {
		if (RD_DEBUG_LOG_NQN_TARGET) {
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Redirector %s nqn_target=%s using first usable but unavailable target bdev %s\n",
				      rd_node->config->redirector_name, nqn, first_usable->name);
		}
		return first_usable->target_index;
	} else {
		return -1;
	}
}

/*
 * In the hash hint case we update the target index of every target identified in the NQN list. Those that are
 * unavailable remain -1. The target index of the hint struct is set to the index of the first target in the
 * NQN list that was usable. If this is -1, the rule table generator knows this hint is unusable. This hash
 * hint won't be used until at least one of its NQN targets comes up.
 */
static void
update_hash_hint_nqn_target_indexes(struct redirector_bdev *rd_node,
				    struct location_hint *hint)
{
	size_t nqn_iter;
	int single_target_index = -1;

	assert(location_hint_type(hint) == RD_HINT_TYPE_HASH_NQN_TABLE);
	assert(hint->hash.nqn_list);
	for (nqn_iter = 0; nqn_iter < hint->hash.nqn_list->num_nqns; nqn_iter++) {
		hint->hash.nqn_list->nqns[nqn_iter].target_index =
			rd_get_nqn_target_index(rd_node, g_quark_to_string(hint->hash.nqn_list->nqns[nqn_iter].nqn));
		if ((single_target_index == -1) &&
		    !rd_target_unavailable(rd_node, hint->hash.nqn_list->nqns[nqn_iter].target_index)) {
			single_target_index = hint->hash.nqn_list->nqns[nqn_iter].target_index;
			rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "revised single target", hint);
		}
	}
	hint->target_index = single_target_index;
}

/*
 * For each target identified in this hint, replace the target index with the current target index of a target
 * with the nqn specified in this hint.
 */
static void
update_location_hint_nqn_target_index(struct redirector_bdev *rd_node,
				      struct location_hint *hint)
{
	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
		rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "simple", hint);
		hint->target_index = rd_get_nqn_target_index(rd_node, location_hint_target_name(hint));
		break;
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "hash", hint);
		update_hash_hint_nqn_target_indexes(rd_node, hint);
		break;
	default:
		hint->target_index = -1;
		break;
	}
}

/*
 * Replace the target index in the specified hint with the current target index of the target(s) named in the
 * hint.
 */
static void
update_location_hint_target_index(struct redirector_bdev *rd_node,
				  struct location_hint *hint)
{
	struct redirector_target *target;

	if (spdk_likely(hint)) {
		if (hint->nqn_target) {
			/* Hash hint takes this path */
			update_location_hint_nqn_target_index(rd_node, hint);
		} else {
			target = redirector_config_find_target(rd_node->config, location_hint_target_name(hint));
			if (spdk_likely(target && !target->removing)) {
				hint->target_index = target->target_index;
			} else {
				/* Target not currently present */
				hint->target_index = -1;
			}
		}
	}
}

static inline uint64_t
location_hint_last_lba(struct location_hint *hint)
{
	assert(hint);
	return hint->extent.start_lba + hint->extent.blocks - 1;
}

static inline struct location_hint *
update_hint_from_iter(struct redirector_bdev *rd_node,
		      GSequenceIter *hint_iter)
{
	struct location_hint *hint = NULL;

	if (!g_sequence_iter_is_end(hint_iter)) {
		hint = (struct location_hint *)g_sequence_get(hint_iter);
		update_location_hint_target_index(rd_node, hint);
	}
	rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "next", hint);
	return hint;
}

/*
 * Update the rule table in the bdev.
 *
 * A rule table is a sequence of (LBA, target) sorted by LBA. The last item in
 * the sequence with LBA <= the LBA of an IO indicates the target of that IO.
 * (This assumes IOs will not cross extent bounds, which we ensure elsewhere).
 *
 * For now the rule table is stores as a sequence of location_hint objects (because
 * we already have the plumbing for those). Eventually this will be in a form simple
 * enough for a gate array to understand.
 *
 * Given the location hints:
 *
 * (0, MAX): t1
 * (1,1): t2
 * (8,1): t3
 *
 * The rule table produced should look like:
 *
 * 0: t1
 * 1: t2
 * 2: t1
 * 8: t3
 * 9: t1
 *
 * We generate the rule table from the complete hint list. Hints referring to
 * inaccessible targets are ignored. When there are redundant equivalent hints
 * (pointing to different targets), one of them will be selected for the rule table
 * somehow (the others may be used in subsequent updates if target reachability
 * changes).
 *
 * As shown above, the rule table identifies the edges of the best and most specific
 * location hints the redirector has. The rule table has only what the data path
 * needs to choose an egress connection for each IO.
 *
 * The data path only needs to apply the starting LBA of each IO to the rule table,
 * because we require that the redirector's IO size & alignment be smaller than and
 * aligned with the size and alignment of location hints used by all the ADNN
 * redirectors in this system. If IOs are already split on the redirector's size &
 * alignment bounds, no IO will span rule table entries (but we should assert on that
 * anyway in the submit function here, or punt non-aligned IOs to a slow path that can
 * split and resubmit them).
 *
 * The hint list is also kept sorted, by starting LBA (increasing) and hint length
 * (longest first). The transformation of the hint list into the rule table examines
 * each applicable hint in order, and appends rules to the new rule table when the
 * most specific hint for the next LBA the rule table doesn't cover yet is found. It
 * uses a stack for the next candidate rules. As hints from the ordered hint list are
 * considered they are pushed onto the rule stack if they might still apply. The
 * algorithm can then look at the next hint to determine if it or the top of the rule
 * stack should be used for the next LAB range. When the rule table extends to the
 * last LBA of the rule on the top of the stack, that rule is popped. We then
 * consider the new top of stack and the next hint in the list.
 *
 * The transformation process starts by identifying the default target for IOs this
 * redirector has no specific location information for. The rule stack is initialized
 * with a rule matching all LBAs and pointing to this target. If no applicable hints
 * starting at LBA 0 are found in the hint list, the algorithm will add a rule table
 * entry at LBA 0 pointing to the default target. This will happen anywhere else in
 * LBA space when the rule stack gets down to just the initial default rule, and the
 * next hint doesn't start at the next LBA not yet covered by the rule table.
 *
 * This process makes a single pass through the hint list, while laying down the rule
 * table entries in LBA order. The rule table will have no gaps. It will map every
 * LBA to a target.
 *
 * In some circumstances a redirector may have to start before its default target
 * comes online, or all the redirectors it knows about may become unreachable. In
 * those cases the rule table will still map every LBA to a target, but one of those
 * targets may be a queue where submitted IOs wait for targets to (re)appear. As far
 * as rule table generation is concerned, that's just another target.
 *
 * Similarly, of the rule table is consumed by hardware its size may be limited. In
 * that case rule table generation may have to map ranges of infrequently accessed
 * LBAs to a software target that can use the complete rule table (and adjust the
 * hardware rule table in response to current IO access patterns). A hardware rule
 * table like that still maps every LBA to a target, but not all of them are physical
 * egress ports.
 */
void
vbdev_redirector_update_locations(struct redirector_bdev *bdev)
{
	struct redirector_config *config = bdev->config;
	struct location_hint default_location;
	GList *rule_stack = NULL;
	struct redirector_target *default_target = NULL;
	GSequenceIter *hint_iter;
	struct location_hint *next_hint;
	struct location_hint *tos;
	GSequence *old_rule_table;
	GSequence *rule_table;
	uint64_t rule_table_last_lba = 0; /* The first LBA that still needs a rule */
	uint64_t rule_table_last_lba_max = redirector_max_blocks(bdev);
	bool rule_table_last_lba_max_reached = false;
	bool hint_pages_changed = false;
	struct rule_table_hash_params hash_params = {
		.rule_table_contains_hash_hint = false,
		.hash_table = NULL,
		.nqn_list = NULL,
	};
	int rc;

	if (RD_DEBUG_LOG_TARGET_TRANSLATION) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "updating rule table on redirector %s. locations=%p rule_count=%d lba_max=%"PRId64"\n",
			      bdev->config->redirector_name, bdev->locations,
			      location_list_length(bdev->locations), rule_table_last_lba_max);
	}

	bzero(&default_location, sizeof(default_location));
	default_location.hint_type = RD_HINT_TYPE_SIMPLE_NQN_NS;
	default_location.extent.start_lba = 0;
	default_location.extent.blocks = rule_table_last_lba_max;
	default_location.simple.target_name = "NONE";
	default_location.simple.target_start_lba = 0;
	default_location.target_index = -1;
	default_location.default_rule = true;

	if (spdk_unlikely(g_shutdown_started)) {
		default_location.target_index = -1;
		old_rule_table = bdev->locations;
		rule_table = g_sequence_new(location_hint_destroy_fn);
		rc = rule_table_add(config, rule_table, NULL, rule_table_last_lba, &default_location);
		bdev->locations = rule_table;
		assert(!hash_params.rule_table_contains_hash_hint);
		hint_pages_changed = rd_new_hint_log_pages(bdev);
		bdev->rule_update_pending = true;
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Applying NULL rule table for shutdown of redirector %s. "
			      "locations=%p rule_count=%d replaces=%p\n",
			      bdev->config->redirector_name, bdev->locations,
			      location_list_length(bdev->locations), old_rule_table);
		if (old_rule_table) {
			g_sequence_free(old_rule_table);
		}
		return;
	}

	default_target = vbdev_redirector_default_target(bdev->config);
	if (spdk_unlikely(!default_target)) {
		SPDK_ERRLOG("Redirector %s has no default target. Destroying.\n",
			    bdev->config->redirector_name);
		vbdev_redirector_destruct(bdev);
		return;
	}

	if (RD_DEBUG_LOG_RULE_TABLE) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s default target is %s%s%s\n",
			      bdev->config->redirector_name, default_target->name,
			      default_target->auth_target ? " [AUTH]" : "",
			      (default_target->bdev == NULL) ? " [NULL bdev]" : "");
	}

	assert(default_target->redirector);
	default_location.target_index = default_target->target_index;
	default_location.simple.target_name = default_target->name;
	if (!target_index_sticky(default_target)) {
		assert(bdev->targets[default_location.target_index].bdev);
		assert(bdev->targets[default_location.target_index].desc);
	}

	/* This will replace what's in the redirector bdev */
	rule_table = g_sequence_new(location_hint_destroy_fn);
	rule_stack_push(&rule_stack, &default_location);

	rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "default", &default_location);
	hint_iter = g_sequence_get_begin_iter(config->hints);
	next_hint = update_hint_from_iter(bdev, hint_iter);
	while (next_hint || !rule_stack_empty(&rule_stack)) {
		tos = rule_stack_top(&rule_stack);
		if (next_hint) {
			assert(!tos || next_hint->extent.start_lba >= tos->extent.start_lba);
			assert(next_hint->extent.start_lba >= rule_table_last_lba);
			/* Skip hints that refer to unavailable targets unless they're authoritative. */
			if (rd_target_unusable(next_hint->target_index) ||
			    (!next_hint->authoritative &&
			     rd_target_unavailable(bdev, next_hint->target_index))) {
				rd_debug_log_hint(RD_DEBUG_LOG_RULE_TABLE, __func__, "skipping", next_hint);
				hint_iter = g_sequence_iter_next(hint_iter);
				next_hint = update_hint_from_iter(bdev, hint_iter);
				continue;
			}
		}
		if (!next_hint || next_hint->extent.start_lba > rule_table_last_lba) {
			if (next_hint) {
				assert(next_hint->extent.start_lba > rule_stack_top(&rule_stack)->extent.start_lba);
			}
			if (!rule_table_last_lba_max_reached) {
				/* Top of rule stack applies until it ends or the next rule begins */
				rc = rule_table_add(config, rule_table, &hash_params,
						    rule_table_last_lba, rule_stack_top(&rule_stack));
			}
			assert(rc == 0);
			if (next_hint && !rule_table_last_lba_max_reached &&
			    location_hint_last_lba(rule_stack_top(&rule_stack)) >=
			    next_hint->extent.start_lba) {
				/* The top of the rule stack applies until the next hint */
				rule_table_last_lba = next_hint->extent.start_lba;
				continue;
			} else {
				if (!rule_table_last_lba_max_reached) {
					/* The top of the rule stack ends before the next hint */
					rule_table_last_lba =
						spdk_max(rule_table_last_lba,
							 location_hint_last_lba(rule_stack_top(&rule_stack)));
					/* rule_table_last_lba needs to point to the next LBA after the
					 * top of the stack ends, if it hasn't already reached the end of
					 * the bdev */
					if (rule_table_last_lba >= rule_table_last_lba_max) {
						rule_table_last_lba_max_reached = true;
					} else {
						rule_table_last_lba++;
						if (rule_table_last_lba >= rule_table_last_lba_max) {
							rule_table_last_lba_max_reached = true;
						}
					}
				}

				/* Pop all the rules we've passed the end of */
				while (!rule_stack_empty(&rule_stack) &&
				       (rule_table_last_lba_max_reached ||
					(rule_table_last_lba >
					 location_hint_last_lba(rule_stack_top(&rule_stack))))) {

					rule_stack_pop(&rule_stack, NULL);
					tos = rule_stack_top(&rule_stack);
				}
				continue;
			}
		} else {
			assert(next_hint);
			/* A hint not yet on the rule stack applies next */
			if (!rule_table_last_lba_max_reached) {
				assert(next_hint->extent.start_lba == rule_table_last_lba);
			}
			rule_stack_push(&rule_stack, next_hint);
			tos = rule_stack_top(&rule_stack);
			hint_iter = g_sequence_iter_next(hint_iter);
			next_hint = update_hint_from_iter(bdev, hint_iter);
			continue;
		}
	}
	assert(rule_table_last_lba_max_reached);

	old_rule_table = bdev->locations;
	bdev->locations = rule_table;
	hint_pages_changed = rd_new_hint_log_pages(bdev);
	bdev->rule_update_pending = true;
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "rule table updated on redirector %s. locations=%p rule_count=%d "
		      "replaces=%p hint_pages_changed=%s\n",
		      bdev->config->redirector_name, bdev->locations,
		      location_list_length(bdev->locations), old_rule_table,
		      hint_pages_changed ? "yes" : "no");
	if (old_rule_table) {
		g_sequence_free(old_rule_table);
	}
}
