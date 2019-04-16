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
 * Logic for maintaining the set of configured and learned location hints
 * for a redirector.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_rpc_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_null_hash.h"
#include "vbdev_redirector_ceph_hash.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector.h"
#include "spdk/bdev.h"
#include "spdk/util.h"
#include "spdk_internal/log.h"
#include "spdk/likely.h"

static int
redirector_config_remove_hash_hint(struct redirector_config *config);

void
_rd_debug_log_hint(const char *func, char *description, struct location_hint *hint)
{
	if (hint) {
		switch (location_hint_type(hint)) {
		case RD_HINT_TYPE_SIMPLE_NQN:
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "%s %s %s hint start=%"PRId64" blocks=%"PRId64" "
				      "target=%s index=%d%s%s%s%s%s%s%s\n",
				      func ? func : "", description,
				      rd_hint_type_name[location_hint_type(hint)],
				      hint->extent.start_lba, hint->extent.blocks,
				      hint->simple.target_name, hint->target_index,
				      hint->rx_target ? " from=" : "",
				      hint->rx_target ? hint->rx_target : "",
				      hint->persistent ? " persistent" : "",
				      hint->authoritative ? " authoritative" : "",
				      hint->nqn_target ? " nqn_target" : "",
				      hint->default_rule ? " default_rule" : "",
				      hint->rule_table ? " RULE_TABLE" : "");
			break;
		case RD_HINT_TYPE_NONE:
		case RD_HINT_TYPE_SIMPLE_NQN_NS:
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "%s %s %s hint start=%"PRId64" blocks=%"PRId64" target_start_lba=%"PRId64" "
				      "target=%s index=%d%s%s%s%s%s%s%s\n",
				      func ? func : "", description,
				      rd_hint_type_name[location_hint_type(hint)],
				      hint->extent.start_lba, hint->extent.blocks,
				      hint->simple.target_start_lba,
				      hint->simple.target_name, hint->target_index,
				      hint->rx_target ? " from=" : "",
				      hint->rx_target ? hint->rx_target : "",
				      hint->persistent ? " persistent" : "",
				      hint->authoritative ? " authoritative" : "",
				      hint->nqn_target ? " nqn_target" : "",
				      hint->default_rule ? " default_rule" : "",
				      hint->rule_table ? " RULE_TABLE" : "");
			break;
		case RD_HINT_TYPE_HASH_NQN_TABLE:
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "%s %s %s hint start=%"PRId64" blocks=%"PRId64" target_index=%d fn_id=%s object_bytes=0x%"PRIx64" name_format=\"%s\" hash_table_log_page=%d nqn_list_log_page=%d params_file=%s%s%s%s%s%s%s%s\n",
				      func ? func : "", description,
				      rd_hint_type_name[location_hint_type(hint)],
				      hint->extent.start_lba, hint->extent.blocks, hint->target_index,
				      rd_hash_fn_id_name[hint->hash.hash_function_id],
				      hint->hash.object_bytes,
				      hint->hash.object_name_format,
				      hint->hash.nvme_state.hash_table_log_page,
				      hint->hash.nvme_state.nqn_list_log_page,
				      hint->hash.persist_state.hint_params_file,
				      hint->rx_target ? " from=" : "",
				      hint->rx_target ? hint->rx_target : "",
				      hint->persistent ? " persistent" : "",
				      hint->authoritative ? " authoritative" : "",
				      hint->nqn_target ? " nqn_target" : "",
				      hint->default_rule ? " default_rule" : "",
				      hint->rule_table ? " RULE_TABLE" : "");
			break;
		case RD_HINT_TYPE_SIMPLE_NQN_ALT:
		case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
		case RD_HINT_TYPE_STRIPE_NQN:
		case RD_HINT_TYPE_STRIPE_NQN_NS:
		case RD_HINT_TYPE_DIFF_NQN_NS:
		case RD_HINT_TYPE_DIFF_HASH_NQN_TABLE:
		default:
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "%s %s unknown hint type (%d)%s%s%s%s%s%s%s\n",
				      func ? func : "", description,
				      hint->hint_type,
				      hint->rx_target ? " from=" : "",
				      hint->rx_target ? hint->rx_target : "",
				      hint->persistent ? " persistent" : "",
				      hint->authoritative ? " authoritative" : "",
				      hint->nqn_target ? " nqn_target" : "",
				      hint->default_rule ? " default_rule" : "",
				      hint->rule_table ? " RULE_TABLE" : "");
			break;
		}
	} else {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "%s (null)\n", description);
	}
}

static bool
name_is_nqn(const char *name)
{
	return (0 == strncmp(name, RD_NQN_PREFIX, strlen(RD_NQN_PREFIX)));
}

void
free_hash_hint_table(struct hash_hint_table *hash_table)
{
	free(hash_table);
}

void
free_nqn_list(struct nqn_list *nqn_list)
{
	free(nqn_list);
}

void
free_location_hint(struct location_hint *hint)
{
	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
		free(hint->simple.target_name);
		break;
	case RD_HINT_TYPE_DIFF_HASH_NQN_TABLE:
		free(hint->hash.object_name_format);
		free_nqn_list(hint->hash.nqn_list);
		free_hash_hint_table(hint->hash.hash_table);
		free(hint->hash.persist_state.hint_params_file);
		break;
	case RD_HINT_TYPE_NONE:
	default:
		break;
	}
	free(hint->rx_target);
	free(hint);
}

struct location_hint *
alloc_location_hint(void)
{
	struct location_hint *hint;

	hint = calloc(1, sizeof(struct location_hint));
	if (!hint) {
		SPDK_ERRLOG("could not allocate location hint\n");
		return NULL;
	}

	hint->target_index = -1; /* hint target doesn't exist */
	return hint;
}

static struct location_hint *
_alloc_generic_hint(const uint64_t start_lba,
		    const uint64_t blocks,
		    const char *rx_target,
		    const bool persistent,
		    const bool authoritative)
{
	struct location_hint *hint;

	hint = alloc_location_hint();
	if (!hint) {
		SPDK_ERRLOG("could not allocate location hint\n");
		return NULL;
	}

	hint->hint_type = RD_HINT_TYPE_NONE;

	if (rx_target) {
		assert(!authoritative);
		assert(!persistent);
		hint->rx_target = strdup(rx_target);
		if (!hint->rx_target) {
			SPDK_ERRLOG("could not allocate location hint source target name\n");
			free_location_hint(hint);
			return NULL;
		}
	}

	hint->extent.start_lba = start_lba;
	hint->extent.blocks = blocks;
	hint->persistent = persistent;
	hint->authoritative = authoritative;
	return hint;
}

struct location_hint *
alloc_simple_hint(const uint64_t start_lba,
		  const uint64_t blocks,
		  const char *target_name,
		  const uint64_t target_start_lba,
		  const char *rx_target,
		  const bool persistent,
		  const bool authoritative)
{
	struct location_hint *hint;

	hint = _alloc_generic_hint(start_lba, blocks, rx_target, persistent, authoritative);
	if (!hint) {
		SPDK_ERRLOG("could not allocate location hint\n");
		return NULL;
	}

	hint->hint_type = RD_HINT_TYPE_SIMPLE_NQN;
	hint->simple.target_name = strdup(target_name);
	if (!hint->simple.target_name) {
		SPDK_ERRLOG("could not allocate location hint target name\n");
		free_location_hint(hint);
		return NULL;
	}

	/* Flag hints that refer to targets by NQN */
	hint->nqn_target = name_is_nqn(target_name);
	hint->simple.target_start_lba = target_start_lba;
	return hint;
}

/* On success, the location hint takes ownership of nqn_list, and hash_table. These will be freed with the hint */
struct location_hint *
alloc_hash_hint(const rd_hash_fn_id_t hash_fn,
		const uint64_t object_bytes,
		const char *object_name_format,
		struct nqn_list *nqn_list,
		struct hash_hint_table *hash_table,
		const char *rx_target,
		const bool persistent,
		const bool authoritative)
{
	struct location_hint *hint;

	hint = _alloc_generic_hint(0, UINT64_MAX, rx_target, persistent, authoritative);
	if (!hint) {
		SPDK_ERRLOG("could not allocate location hint\n");
		return NULL;
	}

	hint->hint_type = RD_HINT_TYPE_HASH_NQN_TABLE;
	hint->hash.object_name_format = strdup(object_name_format);
	if (!hint->hash.object_name_format) {
		SPDK_ERRLOG("could not allocate location hint object name format\n");
		free_location_hint(hint);
		return NULL;
	}
	hint->hash.hash_function_id = hash_fn;
	hint->hash.object_bytes = object_bytes;
	hint->hash.hash_table = hash_table;
	hint->hash.nqn_list = nqn_list;
	/* Flag hints that refer to targets by NQN (all hash hints use an NQN table) */
	hint->nqn_target = true;
	return hint;
}

static void
location_hint_destroy(gpointer data)
{
	free_location_hint((struct location_hint *)data);
}

/* Mostly to assert that location_hint_destroy has the right prototype */
const GDestroyNotify location_hint_destroy_fn = location_hint_destroy;

/*
 * Compare affected hint region for sorting in map
 *
 * Sorts first by LBA (increasing), then specificity (increasing)
 *
 * When sorted this way, the last hint in order that doesn't start after the
 * LBA searched for is the most specific hint that applies to that (starting)
 * LBA.
 */
static int
location_hint_extent_compare(const struct location_hint *lhs, const struct location_hint *rhs)
{
	if (lhs->extent.start_lba != rhs->extent.start_lba) {
		if (lhs->extent.start_lba < rhs->extent.start_lba) {
			/* lower start LBA sorts first */
			return -1;
		} else {
			return 1;
		}
	} else if (lhs->extent.blocks != rhs->extent.blocks) {
		if (lhs->extent.blocks > rhs->extent.blocks) {
			/* more general hint sorts first */
			return -1;
		} else {
			return 1;
		}
	} else {
		/* hints are equivalent */
		return 0;
	}
}


static gint
location_hint_data_compare(gconstpointer lhs, gconstpointer rhs, gpointer ignored)
{
	return location_hint_extent_compare((const struct location_hint *)lhs,
					    (const struct location_hint *)rhs);
}

const GCompareDataFunc location_hint_data_compare_fn = location_hint_data_compare;

struct redirector_location_hint_data_and_target_compare_opts {
	bool	ignore_target;
	bool	ignore_flags;
	bool	ignore_target_start_lba;
	bool	ignore_hint_type;
	bool	compare_general_hint_type;   /* If !ignore_hint_type, use rd_general_hint_type */
	bool	ignore_hint_source;
};

/*
 * Compare hints by more than just the extent. Can compare entire hint for duplicate detection and display
 *
 * Hint types that have single targets (e.g. simple hints) sort before those that don't (e.g. hash) if the
 * target name needs to be compared (hash hints have no target name to compare).
 */
static int
location_hint_equal(struct location_hint *lhs, struct location_hint *rhs,
		    struct redirector_location_hint_data_and_target_compare_opts *opts)
{
	int result = location_hint_extent_compare(lhs, rhs);
	bool lhs_has_target = rd_hint_type_single_target(lhs->hint_type);
	bool rhs_has_target = rd_hint_type_single_target(rhs->hint_type);
	bool both_have_targets = (lhs_has_target && rhs_has_target);
	bool lhs_learned = lhs->rx_target;
	bool rhs_learned = rhs->rx_target;
	bool both_learned = (lhs_learned && rhs_learned);

	if (result) {
		return result;
	}

	if (!opts->ignore_hint_type) {
		enum rd_hint_type lhs_cmp_type;
		enum rd_hint_type rhs_cmp_type;

		if (opts->compare_general_hint_type) {
			lhs_cmp_type = location_hint_general_type(lhs);
			rhs_cmp_type = location_hint_general_type(rhs);
		} else {
			lhs_cmp_type = location_hint_type(lhs);
			rhs_cmp_type = location_hint_type(rhs);
		}

		if (lhs_cmp_type != rhs_cmp_type) {
			if (lhs_cmp_type < rhs_cmp_type) {
				return -1;
			} else {
				return 1;
			}
		}
	}

	if (!opts->ignore_target) {
		if (both_have_targets) {
			result = strcmp(location_hint_target_name(lhs),
					location_hint_target_name(rhs));
			if (result) {
				return result;
			}
		} else if (lhs_has_target) {
			return -1;
		} else if (rhs_has_target) {
			return 1;
		} else {
			/* equal so far */
		}
	}

	if (!opts->ignore_flags) {
		if (lhs->authoritative != rhs->authoritative) {
			if (lhs->authoritative) {
				return -1;
			} else {
				return 1;
			}
		}

		if (lhs->persistent != rhs->persistent) {
			if (lhs->persistent) {
				return -1;
			} else {
				return 1;
			}
		}
	}

	if (!opts->ignore_target_start_lba) {
		if (both_have_targets) {
			if (location_hint_target_start_lba(lhs) != location_hint_target_start_lba(rhs)) {
				if (location_hint_target_start_lba(lhs) < location_hint_target_start_lba(rhs)) {
					return -1;
				} else {
					return 1;
				}
			}
		} else if (lhs_has_target) {
			return -1;
		} else if (rhs_has_target) {
			return 1;
		} else {
			/* equal so far */
		}
	}

	if (!opts->ignore_hint_source) {
		if (both_learned) {
			result = strcmp(lhs->rx_target, rhs->rx_target);
			if (result) {
				return result;
			}
		} else if (lhs_learned) {
			return -1;
		} else if (rhs_learned) {
			return 1;
		} else {
			/* equal so far */
		}
	}

	/* equal */
	return 0;
}

/* Compare options defaults are chosen for redirector_config_add_hint() */
static struct redirector_location_hint_data_and_target_compare_opts default_compare_opts = {
	.ignore_target = false,               /* Consider target */
	.ignore_flags = true,                 /* Ignore flags */
	.ignore_target_start_lba = true,      /* Ignore target_start_lba */
	.ignore_hint_type = false,            /* Consider hint type */
	.compare_general_hint_type = true,    /* Use general hint types for matching */
	.ignore_hint_source = true,           /* Ignore hint source */
};

/*
 * Compare location hints for sorting in the redirector's configured hint list.
 *
 * Sorts first by LBA (increasing), then specificity (increasing), then hint
 * type, then target name.
 *
 * When sorted this way, the last hint in order that doesn't start after the LBA
 * searched for is the most specific hint that applies to that (starting)
 * LBA. So the order is useful for applying hints.
 *
 * This order also enables lookup of hints by extent, extent and hint type,
 * extent and hint type and target name, or (because single target hints sort
 * before multi-target hints that don't name a single specific target) just
 * extent and target name.
 *
 * Searches for other combinations of hint properties will require an exhaustive
 * search of the hint list. Specifically any search that ignores the extent will
 * fail. Searching for and removing hints by only their target name or the name
 * of the target we learned them from both require an exhaustive search.
 */
static gint
location_hint_data_and_target_compare(gconstpointer lhs, gconstpointer rhs, gpointer opts)
{
	struct redirector_location_hint_data_and_target_compare_opts *l_opts =
		(struct redirector_location_hint_data_and_target_compare_opts *) opts;

	if (l_opts == NULL) {
		l_opts = &default_compare_opts;
	}

	return location_hint_equal((struct location_hint *)lhs, (struct location_hint *)rhs, l_opts);
}

const GCompareDataFunc location_hint_data_and_target_compare_fn =
	location_hint_data_and_target_compare;


/* Match by extent and target name, or by specified criteria if opts is not NULL */
static GSequenceIter *
redirector_config_find_first_hint_iter(const struct redirector_config *config,
				       struct location_hint *lookup,
				       struct redirector_location_hint_data_and_target_compare_opts *opts)
{
	GSequenceIter *search_iter;
	static GSequenceIter *prev_iter;
	struct location_hint *prev_hint;
	int comp_result;

	rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " searching for: ", lookup);
	search_iter = g_sequence_lookup(config->hints, lookup, location_hint_data_and_target_compare_fn,
					opts);

	if (!search_iter) {
		/* No hints match this extent & target */
		return NULL;
	}
	do {
		if (g_sequence_iter_is_begin(search_iter)) {
			prev_iter = NULL;
		} else {
			prev_iter = g_sequence_iter_prev(search_iter);
		}
		if (prev_iter) {
			prev_hint = g_sequence_get(prev_iter);
			comp_result = location_hint_data_and_target_compare(lookup, prev_hint, opts);
			if (0 == comp_result) {
				/* Previous hint also has this extent & target */
				search_iter = prev_iter;
			} else {
				/* Previous target has different extent & target. This is the first match. */
				return search_iter;
			}
		}
	} while (prev_iter);

	/* No prev, so search_iter is the first match */
	return search_iter;
}

/* Match by extent and target name, or by specified criteria if opts is not NULL */
static GSequenceIter *
redirector_config_find_next_hint_iter(const struct redirector_config *config, GSequenceIter *iter,
				      struct redirector_location_hint_data_and_target_compare_opts *opts)
{
	struct location_hint *iter_hint;
	static GSequenceIter *next_iter;
	struct location_hint *next_hint;
	int comp_result;

	assert(iter);
	if (g_sequence_iter_is_end(iter)) {
		return NULL;
	}
	iter_hint = g_sequence_get(iter);
	next_iter = g_sequence_iter_next(iter);
	if (g_sequence_iter_is_end(next_iter)) {
		/* No next */
		return next_iter;
	}

	next_hint = g_sequence_get(next_iter);
	comp_result = location_hint_data_and_target_compare(iter_hint, next_hint, opts);
	if (0 == comp_result) {
		/* Next hint has same extent & target */
		return next_iter;
	} else {
		/* The last hint with this extent & target was at iter. No Next */
		return NULL;
	}
}

static void
redirector_config_add_hint(struct redirector_config *config, struct location_hint *hint)
{
	assert(config);
	assert(hint);
	/* Keep list sorted by extent, then hint type, then target. Allows simple hints to be looked up by
	 * both when removing, or just by extent when looking for any/all that apply. */
	g_sequence_insert_sorted(config->hints, (gpointer)hint, location_hint_data_and_target_compare_fn,
				 NULL);
}

/*
 * Remove all the location hints with the same extent and target name as the lookup hint.
 *
 * If opts is not NULL, it can exclude the target name from the match. The opts argument here
 * can only differ from default_compare_opts in the ignore_target field. Other combinations of
 * opts will fail to find all matchng items in the hint list when used here.
 *
 * The learned_only flag causes configured hints (not learned from another redirector) to be
 * excluded.
 */
static int
_redirector_config_remove_hint(struct redirector_config *config, struct location_hint *lookup,
			       struct redirector_location_hint_data_and_target_compare_opts *opts, bool learned_only)
{
	GSequenceIter *hint_iter;
	GSequenceIter *next_iter;
	struct location_hint *iter_hint;
	int num_removed = 0;

	rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " removing all: ", lookup);
	hint_iter = redirector_config_find_first_hint_iter(config, lookup, opts);
	while (hint_iter && !g_sequence_iter_is_end(hint_iter)) {
		next_iter = redirector_config_find_next_hint_iter(config, hint_iter, opts);
		iter_hint = g_sequence_get(hint_iter);
		if (!learned_only || iter_hint->rx_target) {
			rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " removing: ", iter_hint);
			g_sequence_remove(hint_iter);
			num_removed++;
		} else {
			rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " not removing: ", lookup);
		}
		hint_iter = next_iter;
	}

	if (0 == num_removed) {
		rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " removed zero of: ", lookup);
		return -ENODEV;
	}
	return 0;
}

/*
 * Remove a configured or learned hint. Usually used to remove configured hints, where we
 * expect only one will match.
 */
static int
redirector_config_remove_hint(struct redirector_config *config, struct location_hint *lookup)
{
	return _redirector_config_remove_hint(config, lookup, NULL, false);
}

/* True if any LBA is included by both hints */
static bool
redirector_hints_overlap(struct location_hint *lhs, struct location_hint *rhs)
{
	int extent_cmp = location_hint_extent_compare(lhs, rhs);

	if (0 == extent_cmp) {
		return true;	/* Equal extents overlap */
	}

	if (extent_cmp > 0) {
		/* Perform tests below with lowest starting LBA on the left */
		return redirector_hints_overlap(rhs, lhs);
	}

	assert(extent_cmp < 0);

	/* If we get here the extents are not equal, and the highest or shortest is on the right */
	assert(lhs->extent.start_lba <= rhs->extent.start_lba);
	if (lhs->extent.start_lba < rhs->extent.start_lba) {
		/* If left ends after right starts, they overlap */
		return ((lhs->extent.start_lba + lhs->extent.blocks - 1) >= rhs->extent.start_lba);
	} else {
		/* If they start at the same LBA, they overlap */
		return (lhs->extent.start_lba == rhs->extent.start_lba);
	}
}

static bool
redirector_hint_conflicts_with_auth(struct redirector_config *config, struct location_hint *hint)
{
	GSequenceIter *hint_iter;
	GSequenceIter *next_iter;
	struct location_hint *iter_hint;

	hint_iter = g_sequence_get_begin_iter(config->hints);
	while (!g_sequence_iter_is_end(hint_iter)) {
		next_iter = g_sequence_iter_next(hint_iter);
		iter_hint = g_sequence_get(hint_iter);
		if (iter_hint->authoritative) {
			if (redirector_hints_overlap(iter_hint, hint)) {
				return true;
			}
		}
		hint_iter = next_iter;
	}
	return false;
}

/* True if this hint has the same extent as an existing learned hint. */
static bool
redirector_hint_duplicates_existing_learned(struct redirector_config *config,
		struct location_hint *lookup)
{
	struct redirector_location_hint_data_and_target_compare_opts l_opts = {
		.ignore_target = true,
		.ignore_flags = true,
		.ignore_target_start_lba = true,
	};
	GSequenceIter *hint_iter;
	GSequenceIter *next_iter;
	struct location_hint *iter_hint;

	rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " testing for dup: ", lookup);
	hint_iter = redirector_config_find_first_hint_iter(config, lookup, &l_opts);
	while (hint_iter && !g_sequence_iter_is_end(hint_iter)) {
		next_iter = redirector_config_find_next_hint_iter(config, hint_iter, &l_opts);
		iter_hint = g_sequence_get(hint_iter);
		if (iter_hint->rx_target) {
			rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " dup: ", iter_hint);
			return true;
		}
		hint_iter = next_iter;
	}

	return false;
}

/*
 * Add a location hint either from the control interface (JSON RPC) or by learning it from another
 * redirector.
 *
 * Learned hints are identified by rd_target, which specifies the target redirector that sent the hint
 * (which is not necessarily the IO destination target identified in the hint).
 */
static int
redirector_add_hint(struct redirector_config *config,
		    const uint64_t start_lba,
		    const uint64_t blocks,
		    const char *target_name,
		    const uint64_t target_start_lba,
		    const char *rx_target,
		    const bool persistent,
		    const bool authoritative,
		    const bool update_now)
{
	struct redirector_location_hint_data_and_target_compare_opts l_opts = default_compare_opts;
	l_opts.ignore_target = true;
	struct location_hint *new_hint;
	int ret = 0;

	new_hint = alloc_simple_hint(start_lba, blocks, target_name, target_start_lba, rx_target,
				     persistent, authoritative);
	if (!new_hint) {
		SPDK_ERRLOG("Failed to allocate new hint\n");
		return -ENOMEM;
	}

	/* If this hint does LBA translation, change its type to indicate that */
	if (start_lba != target_start_lba) {
		new_hint->hint_type = RD_HINT_TYPE_SIMPLE_NQN_NS;
	}

	/* TODO: (#51) if this hint is learned and refers to this redirector's NQN, reject it */

	/* If this hint conflicts with any auth hints, reject it */
	if (redirector_hint_conflicts_with_auth(config, new_hint)) {
		_rd_debug_log_hint(__func__,
				   "Rejecting hint that conflicts with existing authoritative hint: ", new_hint);
		free_location_hint(new_hint);
		return -EINVAL;
	}

	/* If this exactly matches an existing hint, remove the old hint */
	if (redirector_hint_duplicates_existing_learned(config, new_hint)) {
		_rd_debug_log_hint(__func__, "New hint replaces existing learned hint: ", new_hint);
		/* Remove all learned hints with this extent */
		_redirector_config_remove_hint(config, new_hint, &l_opts, true);
	}

	/* TODO: (#9) If the new hint agrees with an existing larger (enclosing) hint, drop it. If we removed an
	 * existing hint that matched it above, this hint is effectively removing an exception to the larger hint. */

	redirector_config_add_hint(config, new_hint);

	if (authoritative) {
		/* Redirector has (or had) auth hints */
		config->auth_hints |= authoritative;
		struct redirector_target *auth_target =
			redirector_config_find_target(config, target_name);
		if (auth_target) {
			/* Target has (or had) auth hints */
			auth_target->auth_target |= true;
			SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
				      "Marking target %s as the destination of authoritative "
				      "location hints\n", auth_target->name);
		}
	}

	/* Update locations in redirector bdev if it exists */
	if (update_now && config->redirector_bdev) {
		vbdev_redirector_update_locations(config->redirector_bdev);
		/* Update the rule tables in the channels */
		vbdev_redirector_update_channel_state(config->redirector_bdev, NULL, NULL);
	}

	return ret;
}

/* Add a simple location hint via the JSON RPC interface
 *
 * TODO: Remove config from args, and look it up here from the name.
 */
int
redirector_add_hint_rpc(struct redirector_config *config,
			const uint64_t start_lba,
			const uint64_t blocks,
			const char *target_name,
			const uint64_t target_start_lba,
			const bool persistent,
			const bool authoritative,
			const bool update_now)
{
	return redirector_add_hint(config, start_lba, blocks, target_name, target_start_lba,
				   NULL, persistent, authoritative, update_now);
}

/* Add a simple location hint by learning it from a peer */
int
redirector_add_hint_learned(struct redirector_config *config,
			    const uint64_t start_lba,
			    const uint64_t blocks,
			    const char *target_name,
			    const uint64_t target_start_lba,
			    const char *rx_target,
			    const bool update_now)
{
	return redirector_add_hint(config, start_lba, blocks, target_name, target_start_lba,
				   rx_target, false, false, update_now);
}

/*
 * Remove all hints targeting the named target.
 *
 * This requires iterating through all hint list entries because the hint list
 * is sorted by extent, type and target.
 */
void
redirector_config_remove_hints_to_target(struct redirector_config *config, const char *target_name)
{
	GSequenceIter *hint_iter;
	GSequenceIter *next_iter;
	struct location_hint *iter_hint;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Removing location hints referring to target %s on redirector %s\n",
		      target_name, config->redirector_name);

	hint_iter = g_sequence_get_begin_iter(config->hints);
	while (!g_sequence_iter_is_end(hint_iter)) {
		next_iter = g_sequence_iter_next(hint_iter);
		iter_hint = g_sequence_get(hint_iter);
		if (location_hint_single_target(iter_hint) &&
		    (0 == strcmp(target_name, location_hint_target_name(iter_hint)))) {
			if (iter_hint->authoritative) {
				SPDK_WARNLOG("Removing auithoritative location hint for LBA %"PRId64" "
					     "referring to target %s on redirector %s\n",
					     iter_hint->extent.start_lba,
					     target_name, config->redirector_name);
			}
			rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " removing: ", iter_hint);
			g_sequence_remove(hint_iter);
		} else {
			rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " not removing: ", iter_hint);
		}
		hint_iter = next_iter;
	}
}

/*
 * Remove all hints learned from the named target.
 *
 * This requires iterating through all hint list entries because the hint list
 * is sorted by extent, type and target.
 */
void
redirector_config_remove_hints_from_target(struct redirector_config *config,
		const char *target_name)
{
	GSequenceIter *hint_iter;
	GSequenceIter *next_iter;
	struct location_hint *iter_hint;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Removing location hints learned from target %s on redirector %s\n",
		      target_name, config->redirector_name);

	hint_iter = g_sequence_get_begin_iter(config->hints);
	while (!g_sequence_iter_is_end(hint_iter)) {
		next_iter = g_sequence_iter_next(hint_iter);
		iter_hint = g_sequence_get(hint_iter);
		if ((NULL != iter_hint->rx_target) &&
		    (0 == strcmp(target_name, iter_hint->rx_target))) {
			rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " removing: ", iter_hint);
			g_sequence_remove(hint_iter);
		} else {
			rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, " not removing: ", iter_hint);
		}
		hint_iter = next_iter;
	}
}

int
redirector_remove_hint(struct redirector_config *config,
		       const uint64_t start_lba,
		       const uint64_t blocks,
		       const char *target_name)
{
	struct location_hint lookup = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = start_lba,
			.blocks = blocks
		},
		.simple = {
			.target_name = (char *)target_name,
			.target_start_lba = 0
		},
		.rx_target = NULL,
		.persistent = false,
		.authoritative = false,
		.nqn_target = false,
		.default_rule = false,
		.rule_table = false,
		.target_index = 0
	};
	int rc;

	rc = redirector_config_remove_hint(config, &lookup);
	if (rc) {
		return rc;
	}

	/* Update locations in redirector bdev if it exists */
	if ((rc == 0) && config->redirector_bdev) {
		vbdev_redirector_update_locations(config->redirector_bdev);
		/* Update target and rule tables in channels */
		vbdev_redirector_update_channel_state(config->redirector_bdev, NULL, NULL);
	}

	return rc;
}

static bool
hash_hint_format_string_valid(const char *s)
{
	/* TODO: String must contain exactly one format argument for a uint64_t, and be a valid
	 * snprintf() format string */
	return (s != NULL);
}

static rd_hash_fn_id_t
hash_fn_name_to_id(const char *hash_fn_name)
{
	int id_iter;

	for (id_iter = 0; id_iter < RD_HASH_FN_ID_LAST; id_iter++) {
		if (!rd_hash_fn_id_name[id_iter]) {
			continue;
		}
		if (0 == strcasecmp(rd_hash_fn_id_name[id_iter], hash_fn_name)) {
			return id_iter;
		}
	}
	return RD_HASH_FN_ID_NONE;
}

static size_t
_nqn_list_size(const size_t num_nqns)
{
	struct nqn_list *nqn_list;

	return sizeof(struct nqn_list) +
	       (sizeof(nqn_list->nqns[0]) * num_nqns);
}

static struct nqn_list *
_alloc_nqn_list(const size_t num_nqns)
{
	struct nqn_list *nqn_list = NULL;

	nqn_list = calloc(1, _nqn_list_size(num_nqns));
	return nqn_list;
}

struct nqn_list *
duplicate_nqn_list(const struct nqn_list *old_nqn_list)
{
	struct nqn_list *nqn_list = NULL;

	nqn_list = _alloc_nqn_list(old_nqn_list->num_nqns);
	if (nqn_list) {
		memcpy(nqn_list, old_nqn_list, _nqn_list_size(old_nqn_list->num_nqns));
	}
	return nqn_list;
}

/*
 * Construct internal NQN list from the JSON-RPC struct
 *
 * Internally we use glib2 quarks (deduplicated strings) for the NQNs
 */
struct nqn_list *
alloc_nqn_list(const struct rpc_redirector_hash_hint_nqn_table *rpc_nqn_table)
{
	struct nqn_list *nqn_list = NULL;
	size_t nqn_iter;
	struct spdk_md5ctx md5ctx;

	nqn_list = _alloc_nqn_list(rpc_nqn_table->num_nqns);
	if (!nqn_list) {
		SPDK_ERRLOG("could not allocate NQN list\n");
		return NULL;
	}

	nqn_list->num_nqns = rpc_nqn_table->num_nqns;
	spdk_md5init(&md5ctx);
	for (nqn_iter = 0; nqn_iter < nqn_list->num_nqns; nqn_iter++) {
		nqn_list->nqns[nqn_iter].nqn = g_quark_from_string(rpc_nqn_table->nqns[nqn_iter]);
		/* The characters of the NQN are hashed, but not the terminating NULL */
		spdk_md5update(&md5ctx, rpc_nqn_table->nqns[nqn_iter], strlen(rpc_nqn_table->nqns[nqn_iter]));
	}
	spdk_md5final(&nqn_list->digest, &md5ctx);
	nqn_list->digest_valid = true;
	return nqn_list;
}

static size_t
_hash_hint_table_size(const size_t num_buckets)
{
	struct hash_hint_table *hash_table;

	return sizeof(struct hash_hint_table) +
	       (sizeof(hash_table->buckets[0]) * num_buckets);
}

static struct hash_hint_table *
_alloc_hash_hint_table(const size_t num_buckets)
{
	struct hash_hint_table *hash_table = NULL;

	hash_table = calloc(1, _hash_hint_table_size(num_buckets));
	return hash_table;
}

struct hash_hint_table *
duplicate_hash_hint_table(const struct hash_hint_table *old_table)
{
	struct hash_hint_table *hash_table = NULL;

	hash_table = _alloc_hash_hint_table(old_table->num_buckets);
	if (hash_table) {
		memcpy(hash_table, old_table, _hash_hint_table_size(old_table->num_buckets));
	}
	return hash_table;
}

/*
 * Construct internal hash table from the JSON RPC struct
 *
 * This hash table refers to the NQNs in some specific NQN table.  If
 * that NQN table is supplied, the hash table digest will be computed
 * using the NQN strings from that NQN table.
 */
struct hash_hint_table *
alloc_hash_hint_table(const struct rpc_redirector_hash_hint_hash_table *rpc_hash_table,
		      const struct rpc_redirector_hash_hint_nqn_table *rpc_nqn_table)
{
	struct hash_hint_table *hash_table = NULL;
	size_t bucket_iter;
	struct spdk_md5ctx md5ctx;

	hash_table = _alloc_hash_hint_table(rpc_hash_table->num_buckets);
	if (!hash_table) {
		SPDK_ERRLOG("could not allocate hash table\n");
		return NULL;
	}

	/*
	 * We leave the hash table buckets pointing to entries in an NQN list specific to this hint.  In the
	 * rule table we'll want these to point to target indexes. At some point between here and there, we'll
	 * translate these buckets to refer to connected targets. That's where we'll rewrite buckets that
	 * refer to unconnected targets so they point to one of the targets in the NQN list for this hint (and
	 * try to scatter those around so all the buckets for disconnected targets don't point to the same
	 * working target)
	 */
	hash_table->num_buckets = rpc_hash_table->num_buckets;
	spdk_md5init(&md5ctx);
	for (bucket_iter = 0; bucket_iter < hash_table->num_buckets; bucket_iter++) {
		hash_table->buckets[bucket_iter] = rpc_hash_table->buckets[bucket_iter];
		if (rpc_nqn_table) {
			assert(rpc_hash_table->buckets[bucket_iter] <= rpc_nqn_table->num_nqns);
			/* The characters of the NQN are hashed (not the index into the NQN table), but not
			 * the terminating NULL */
			spdk_md5update(&md5ctx,
				       rpc_nqn_table->nqns[rpc_hash_table->buckets[bucket_iter]],
				       strlen(rpc_nqn_table->nqns[rpc_hash_table->buckets[bucket_iter]]));
		}
	}

	if (rpc_nqn_table) {
		spdk_md5final(&hash_table->digest, &md5ctx);
		hash_table->digest_valid = true;
	}

	return hash_table;
}

/*
 * Add a consistent hash location hint either from the control interface (JSON RPC) or by learning it from another
 * redirector.
 *
 * Learned hints are identified by rd_target, which specifies the target redirector that sent the hint
 * (which is not necessarily the IO destination target identified in the hint).
 *
 * Always takes ownership of nqn_list and hash_table.
 */
static int
redirector_add_hash_hint(struct redirector_config *config,
			 rd_hash_fn_id_t hash_fn,
			 uint64_t object_bytes,
			 const char *object_name_format,
			 struct nqn_list *nqn_list,
			 struct hash_hint_table *hash_table,
			 const char *rx_target,
			 const bool persistent,
			 const bool authoritative,
			 const bool update_now,
			 struct location_hint **new_hint_out)
{
	/* struct redirector_location_hint_data_and_target_compare_opts l_opts = { */
	/* 	.ignore_target = true, */
	/* 	.ignore_flags = true, */
	/* 	.ignore_target_start_lba = true, */
	/* }; */
	struct location_hint *new_hint;
	int ret = 0;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Adding/replacing hash hint on redirector %s\n",
		      config->redirector_name);

	/* Alloc a new hash hint */
	new_hint = alloc_hash_hint(hash_fn, object_bytes, object_name_format, nqn_list, hash_table,
				   rx_target, persistent, authoritative);
	if (!new_hint) {
		SPDK_ERRLOG("Failed to allocate new hash hint\n");
		/* We own these on alloc fail */
		free(nqn_list);
		free(hash_table);
		if (new_hint_out) {
			*new_hint_out = NULL;
		}
		return -ENOMEM;
	}

	/* TODO: (#50) if this hint is learned and refers to this redirector's NQN, reject it */
	/* TODO: It doesn't really make sense for the hash hint NQN table to incluude this redirector */

	/* If this hint conflicts with any auth hints, reject it. */
	/* TODO: implies the hash hint will be ignored if any auth hints are present */
	/* TODO: Implies that a learned non-auth hash hint will not replace a auth hash hint */
	/* if (redirector_hint_conflicts_with_auth(config, new_hint)) { */
	/* 	_rd_debug_log_hint(RD_DEBUG_LOG_HINTS, __func__, "Rejecting hint that conflicts with existing authoritative hint: ", */
	/* 			   new_hint); */
	/* 	free_location_hint(new_hint); */
	/* 	return -EINVAL; */
	/* } */

	/* Only one hash hint at a time can apply to a LN. Remove any existing hash hint before adding. */
	redirector_config_remove_hash_hint(config);

	redirector_config_add_hint(config, new_hint);

	/* Update hash hint tables in config struct (old ones removed above with the hint) */
	config->hash_hint_tables.hash_table = new_hint->hash.hash_table;
	config->hash_hint_tables.nqn_list = new_hint->hash.nqn_list;
	config->hash_hint_tables.hash_hint_source = new_hint->rx_target;
	config->hash_hint_tables.hash_hint_pages = new_hint->hash.nvme_state;

	if (authoritative) {
		/* Redirector has (or had) auth hints */
		config->auth_hints |= authoritative;
		/* TODO: We will *not* mark hash hint targets as auth, because the set of OSD nodes is dynamic */
	}

	/* Update locations in redirector bdev if it exists */
	if (update_now && config->redirector_bdev) {
		vbdev_redirector_update_locations(config->redirector_bdev);
		/* Update the rule tables in the channels */
		vbdev_redirector_update_channel_state(config->redirector_bdev, NULL, NULL);
	}

	if (new_hint_out) {
		*new_hint_out = new_hint;
	}

	return ret;
}

/*
 * Add a consistent hash location hint from the control interface (JSON RPC)
 */
int
redirector_add_hash_hint_rpc(struct rpc_redirector_add_hash_hint *req,
			     struct rpc_redirector_hash_hint_params *hint_params,
			     const bool update_now)
{
	struct redirector_config *config;
	struct location_hint *new_hint;
	struct nqn_list *nqn_list = NULL;
	struct hash_hint_table *hash_table = NULL;
	char *hash_hint_file;
	int ret = 0;

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Adding/replacing hash hint on redirector %s\n",
		      req->redirector_name);

	/* SPDK_NOTICELOG("Looking for redirector %s\n", req.redirector_name); */
	config = vbdev_redirector_find_config(req->redirector_name);
	if (!config) {
		SPDK_NOTICELOG("Redirector %s not found\n", req->redirector_name);
		return -ENODEV;
	}

	/* Object/chunk length in bytes must be 2^n (TODO: it is for Ceph, does it have to be?) */
	if (spdk_align64pow2(hint_params->object_bytes) != hint_params->object_bytes) {
		SPDK_NOTICELOG("Redirector %s hash hint object/chunk size invalid (must be2^n)\n",
			       req->redirector_name);
		return -EINVAL;
	}

	/* Hash fn name must correspond to a supported rd_hash_fn_id */
	if (hash_fn_name_to_id(hint_params->hash_fn) == RD_HASH_FN_ID_NONE) {
		SPDK_NOTICELOG("Redirector %s hash hint hash function name (%s) invalid\n",
			       req->redirector_name, hint_params->hash_fn);
		return -EINVAL;
	}
	/* Object name format string must be valid */
	if (!hash_hint_format_string_valid(hint_params->object_name_format)) {
		SPDK_NOTICELOG("Redirector %s hash hint format string invalid\n", req->redirector_name);
		return -EINVAL;
	}

	/* LN length should match hint length */
	if ((config->blocklen * config->blockcnt) != hint_params->ns_bytes) {
		SPDK_NOTICELOG("Redirector %s hash hint ns length (%"PRIu64") differs from "
			       "the redirector's namespace sise (%"PRIu64")\n", req->redirector_name,
			       hint_params->ns_bytes, (config->blocklen * config->blockcnt));
	}

	/* Hint LN NGUID must match LN NGUID */
	if (rd_uuid_known(config) && !uuids_match(&config->uuid, &hint_params->ln_nguid)) {
		char rd_uuid_str[SPDK_UUID_STRING_LEN];
		int rc = spdk_uuid_fmt_lower(rd_uuid_str, sizeof(rd_uuid_str), &config->uuid);
		assert(rc == 0);
		char ln_uuid_str[SPDK_UUID_STRING_LEN];
		rc = spdk_uuid_fmt_lower(ln_uuid_str, sizeof(ln_uuid_str), &hint_params->ln_nguid);
		assert(rc == 0);
		SPDK_NOTICELOG("Redirector %s hash hint NGUID (%s) must be the same as "
			       "the redirector's NGUID (%s)\n", req->redirector_name,
			       ln_uuid_str, rd_uuid_str);
		return -EINVAL;
	}

	/* TODO: Configure redirector LN NGUID & length from hash hint */

	nqn_list = alloc_nqn_list(hint_params->nqn_table);
	if (!nqn_list) {
		SPDK_ERRLOG("Redirector %s failed to allocate NQN list\n", req->redirector_name);
		return -ENOMEM;
	}

	hash_table = alloc_hash_hint_table(hint_params->hash_table, hint_params->nqn_table);
	if (!hash_table) {
		SPDK_ERRLOG("Redirector %s failed to allocate hash table\n", req->redirector_name);
		free(nqn_list);
		return -ENOMEM;
	}

	hash_hint_file = strdup(req->hash_hint_file);
	if (!hash_hint_file) {
		SPDK_ERRLOG("Redirector %s failed to allocate hash hint file name\n", req->redirector_name);
		free(nqn_list);
		free(hash_table);
		return -ENOMEM;
	}

	ret = redirector_add_hash_hint(config, hash_fn_name_to_id(hint_params->hash_fn),
				       hint_params->object_bytes, hint_params->object_name_format,
				       nqn_list, hash_table, NULL,
				       req->persistent, req->authoritative, update_now, &new_hint);
	/* We no longer own these */
	nqn_list = NULL;
	hash_table = NULL;
	if (ret < 0) {
		SPDK_ERRLOG("Failed to add new hash hint\n");
		return ret;
	}

	new_hint->hash.persist_state.hint_params_file = hash_hint_file;
	return ret;
}

/*
 * Add a consistent hash location hint by learning it from another redirector.
 *
 * Learned hints are identified by rd_target, which specifies the target redirector that sent the hint
 * (which is not necessarily the IO destination target identified in the hint).
 */
int
redirector_add_hash_hint_learned(struct redirector_config *config,
				 rd_hash_fn_id_t hash_fn,
				 uint64_t object_bytes,
				 const char *object_name_format,
				 struct nqn_list *nqn_list,
				 struct hash_hint_table *hash_table,
				 const char *rx_target,
				 const bool update_now)
{
	return redirector_add_hash_hint(config, hash_fn, object_bytes, object_name_format,
					nqn_list, hash_table, rx_target, false, false, update_now, NULL);
}

static int
redirector_config_remove_hash_hint(struct redirector_config *config)
{
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Removing hash hint on redirector %s\n",
		      config->redirector_name);
	struct location_hint lookup = {
		.hint_type = RD_HINT_TYPE_HASH_NQN_TABLE,
		.extent = {
			.start_lba = 0,
			.blocks = UINT64_MAX
		}
	};

	/* These point to the tables in the (lone) hash hint in the config, and are freed with the
	 * hint */
	config->hash_hint_tables.hash_table = NULL;
	config->hash_hint_tables.nqn_list = NULL;
	config->hash_hint_tables.hash_hint_source = NULL;

	return redirector_config_remove_hint(config, &lookup);
}

int
redirector_remove_hash_hint(struct redirector_config *config)
{
	int rc;

	rc = redirector_config_remove_hash_hint(config);

	/* Update locations in redirector bdev if it exists and the hash hint was removed */
	if ((rc == 0) && config->redirector_bdev) {
		vbdev_redirector_update_locations(config->redirector_bdev);
		/* Update target and rule tables in channels */
		vbdev_redirector_update_channel_state(config->redirector_bdev, NULL, NULL);
	}

	return rc;
}
