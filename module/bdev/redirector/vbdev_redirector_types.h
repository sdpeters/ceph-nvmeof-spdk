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

#ifndef SPDK_VBDEV_REDIRECTOR_TYPES_H
#define SPDK_VBDEV_REDIRECTOR_TYPES_H

#include "spdk/bdev_module.h"
#include "vbdev_redirector.h"
#include "vbdev_redirector_enum_names.h"
#include "md5.h"

#include <gmodule.h>

enum rd_hint_type {
	RD_HINT_TYPE_NONE			= 0,	/* Empty hint / end of list */

	/* Simple hints (LBA range to target, target + NS, target + NS + offset, alt target list */
	RD_HINT_TYPE_SIMPLE_NQN			= 1,	/* Simple hint (NQN, same NS) */
	RD_HINT_TYPE_SIMPLE_NQN_NS		= 2,	/* Simple hint (NQN, NS NGUID + offset) */
	RD_HINT_TYPE_SIMPLE_NQN_ALT		= 3,	/* Simple hint, multiple alternatives (NQNs only) */
	RD_HINT_TYPE_SIMPLE_NQN_TABLE		= 4,	/* Simple hint, NQN only, NQN string table */

	/* Algorithmic (computed target) hints */

	/* Striping */
	RD_HINT_TYPE_STRIPE_NQN			= 0x10,	/* Stripe across multiple targets (by NQN) */
	RD_HINT_TYPE_STRIPE_NQN_NS		= 0x11,	/* Stripe across multiple targets (by NQN + NS) */

	/* Hashing */
	RD_HINT_TYPE_HASH_NQN_TABLE		= 0x20,	/* Hash LBA into NQN table */

	/* Snapshots & clones */
	RD_HINT_TYPE_DIFF_NQN_NS		= 0xb0,	/* Layered snapshot, clone, or differencing LN */
	RD_HINT_TYPE_DIFF_HASH_NQN_TABLE	= 0xb1,	/* Layered hash hints (Ceph clones) */

	/* Hint types unique to a specific make/model */
	RD_HINT_TYPE_VENDOR_SPEC_START		= 0xc0,	/* Redirector vendor specific hint types */
	RD_HINT_TYPE_VENDOR_SPEC_END		= 0xff
};

/* True for hint types that refer to a single target */
static inline bool rd_hint_type_single_target(enum rd_hint_type type)
{
	switch (type) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
		return true;
	default:
		return false;
	}
}

#define RD_NQN_LEN sizeof(((struct spdk_nvme_ctrlr_data*)NULL)->subnqn)

typedef uint8_t	rd_nguid[16];		/* Namespace NGUID */
typedef uint8_t	rd_nqn[RD_NQN_LEN];	/* NQN string. NULL padded. Not necessarily NULL terminated. */

typedef uint8_t rd_log_page_id_t;

/* Index into lists of strings in log pages */
typedef uint16_t rd_nqn_list_index_t;
#define RD_INVALID_NQN_LIST_INDEX_T ((rd_nqn_list_index_t)0xffff)

/*
 * Hash functions defined for the consistent hash hint.
 *
 * Redirectors ignore hash hints specifying unknown or unimplemented hash functions.
 */
typedef enum rd_hash_fn_id {
	RD_HASH_FN_ID_NONE			= 0,	/* Hash hint not applied. Effectively deletes the
							 * previously sent hash hint from this redirector. */
	RD_HASH_FN_ID_CEPH_RJENKINS		= 1,	/* Ceph rjenkins hash and "stable mod" mapping */
	RD_HASH_FN_ID_NULL,				/* NULL hash function for testing. Maps unaltered object
							 * number to hash table (integer mod) without generating
							 * a name string */
	RD_HASH_FN_ID_LAST				/* Must be last */
} rd_hash_fn_id_t;

/*
 * Digest of a list of strings. Used by RD_HINT_TYPE_HASH_NQN_TABLE
 *
 * TBD. Probably MD5 or SHA256. Something already available in SPDK, with negligible collision probability.
 * MD5 is already used in iscsi.
 */
#define RD_LIST_DIGEST_BYTES 16
SPDK_STATIC_ASSERT(RD_LIST_DIGEST_BYTES == SPDK_MD5DIGEST_LEN,
		   "MD5 digest length differs from protocol");
typedef struct __attribute__((packed)) rd_list_digest {
	uint8_t			digest_bytes[RD_LIST_DIGEST_BYTES];
} rd_list_digest_t;

struct nqn_list {
	size_t			num_nqns;
	uint64_t		generation;		/* Incremented by producer */
	rd_list_digest_t	digest;			/* Digest of NQN strings in order */
	struct {
		uint32_t	generation_valid : 1;	/* True if generation known */
		uint32_t	digest_valid : 1;	/* True if digest set & valid */
	};
	struct {
		GQuark		nqn;
		int		target_index;
	} nqns[];
};

struct hash_hint_table {
	uint64_t		generation;		/* Incremented by producer */
	rd_list_digest_t	digest;			/* See rd_hash_table_log_page */
	uint32_t		num_buckets;
	struct {
		uint32_t	generation_valid : 1;	/* True if generation known */
		uint32_t	digest_valid : 1;	/* True if digest set & valid */
	};
	uint16_t		buckets[];		/* An index into a struct nqn_list->nqns[] */
};

struct hash_hint_nvme_state {
	rd_log_page_id_t	hash_table_log_page;	/* A log page generated by this
							 * redirector with contents defined by
							 * rd_hash_table_log_page. */
	rd_log_page_id_t	nqn_list_log_page;	/* A log page generated by this
							 * redirector with contents defined by
							 * rd_nqn_list_log_page. */
};

struct hash_hint_params {
	rd_hash_fn_id_t		hash_function_id;	/* rd_hash_fn_id */
	uint64_t		object_bytes;
	char			*object_name_format;	/* A format string for snprintf() taking the object number
							 * as its only format argument. */
	struct hash_hint_table	*hash_table;
	struct nqn_list		*nqn_list;
	/* State for passing this hint to/from peers */
	struct hash_hint_nvme_state nvme_state;
	/* Info for persisting this hash hint in the config. Normally a real
	 * system wouldn't do this, but instead get this bint state from an agent
	 * on a Ceph node. */
	struct {
		char			*hint_params_file;
	} persist_state;
};

struct simple_hint_params {
	char			*target_name;
	uint64_t		target_start_lba;	/* Starting LBA on target. The blocks affected by this
							 * hint start here on the target.  When the target is
							 * another redirector, this will be the same as
							 * start_lba. If the target is an actual storage
							 * device, this will probably indicate the start of an
							 * extent of this logical namespace. */
};

/* Internally all hints have an extent, even if they always apply to the entire LN */
struct hint_extent {
	uint64_t		start_lba;		/* First affected LBA */
	uint64_t		blocks;			/* Affected LBA count */
};

struct location_hint {
	enum rd_hint_type	hint_type;
	struct hint_extent	extent;
	union {
		struct simple_hint_params   simple;	/* hint_type = RD_HINT_TYPE_SIMPLE_NQN */
		struct hash_hint_params	    hash;	/* hint_type = RD_HINT_TYPE_HASH_NQN_TABLE */
	};
	char			*rx_target;		/* Target (NQN, or bdev name if none) this was learned from
							 * (NULL if configured) */
	struct {
		uint32_t	persistent : 1;		/* Saved in redirector config file */
		uint32_t	authoritative : 1;	/* Not overridden by non-authoritative hints */
		uint32_t	nqn_target : 1;		/* Target names an NQN */
	};
	/* Things related to hints used as routing rules go below here. Rule
	 * table entries don't need lengths. Maybe these will become separate
	 * structures, but for now we'll use this hint structure for hints and
	 * forwarding rules. */
	struct {
		uint32_t	default_rule : 1;	/* This redirector's default target */
		uint32_t	rule_table : 1;		/* This hint structure is in the rule table */
	};
	int			target_index;		/* Index of target in bdev / channel target table */
};

static inline enum rd_hint_type rd_general_hint_type(const enum rd_hint_type specific_hint_type)
{
	switch (specific_hint_type) {

	/* Simple hint variations all become RD_HINT_TYPE_SIMPLE_NQN */
	case RD_HINT_TYPE_SIMPLE_NQN:
			case RD_HINT_TYPE_SIMPLE_NQN_NS:
				case RD_HINT_TYPE_SIMPLE_NQN_ALT:
					case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
							return RD_HINT_TYPE_SIMPLE_NQN;

	/* Striping hint variations all become RD_HINT_TYPE_STRIPE_NQN */
	case RD_HINT_TYPE_STRIPE_NQN:
	case RD_HINT_TYPE_STRIPE_NQN_NS:
		return RD_HINT_TYPE_STRIPE_NQN;

	/* The others have no general type */
	case RD_HINT_TYPE_NONE:
	case RD_HINT_TYPE_HASH_NQN_TABLE:
	case RD_HINT_TYPE_DIFF_NQN_NS:
	case RD_HINT_TYPE_DIFF_HASH_NQN_TABLE:
	default:
		return specific_hint_type;
	}
}

static inline enum rd_hint_type location_hint_type(const struct location_hint *hint)
{
	return (hint ? hint->hint_type : RD_HINT_TYPE_NONE);
}

static inline enum rd_hint_type location_hint_general_type(const struct location_hint *hint)
{
	return rd_general_hint_type(location_hint_type(hint));
}

static inline bool location_hint_single_target(const struct location_hint *hint)
{
	return (rd_hint_type_single_target(location_hint_type(hint)));
}

static inline char *location_hint_target_name(const struct location_hint *hint)
{
	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
		return hint->simple.target_name;
	default:
		return NULL;
	}
}

static inline uint64_t location_hint_target_start_lba(const struct location_hint *hint)
{
	switch (location_hint_type(hint)) {
	/* Only _NQN_NS explicitly performs LBA translation */
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
		return hint->simple.target_start_lba;
	/* All other hint types map to one or more alternative targets at the same LBA */
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
	case RD_HINT_TYPE_SIMPLE_NQN:
	default:
		return hint->extent.start_lba;
	}
}

static inline struct hint_extent *location_hint_extent(struct location_hint *hint)
{
	switch (location_hint_type(hint)) {
	case RD_HINT_TYPE_SIMPLE_NQN:
	case RD_HINT_TYPE_SIMPLE_NQN_NS:
	case RD_HINT_TYPE_SIMPLE_NQN_TABLE:
	case RD_HINT_TYPE_HASH_NQN_TABLE:
		return &hint->extent;
	default:
		return NULL;
	}
}

#define RD_DEFAULT_TARGET_PRIORITY 0

struct redirector_target {
	char			*name;
	struct spdk_bdev	*bdev;
	int			target_index;		/* Index of target in bdev / channel target table */
	int			priority;		/* Order targets with same NQN are chosen (0 first) */
	struct {
		uint32_t	persistent : 1;		/* Saved in redirector config file */
		uint32_t	required : 1;		/* Required for redirector start */
		uint32_t	redirector : 1;		/* Configuration indicates target is another redirector */
		uint32_t	dont_probe : 1;		/* Do not probe target to determine if it's a redirector */
		/* Configuration flags above here */
		/* Runtime state flags below here */
		uint32_t	registered : 1;		/* Target registered to redirector with or without a bdev */
		uint32_t	removing : 1;		/* Target being removed from channel tables */
		uint32_t	hotremove : 1;		/* Special removing behavior for hotremove */
		uint32_t	auth_target : 1;	/* Target was or is named by one or more authoritative
							 * location hints */
		/* TODO: Should the following two bits be in the redirector_bdev_target struct? */
		uint32_t	confirmed_redir : 1;	/* Target provides location hint log page */
		uint32_t	confirmed_not_redir : 1;/* Target does not provide location hint log page */
		uint32_t	get_hints_once : 1;	/* Get hints has been completed once on this target */
		uint32_t	uuid_mismatch : 1;	/* Target UUID differs from redirector's (if known) */
	};
	/* Target configuration above here */
	/* Target runtime state below here */
	char			*nqn;			/* Target NQN from identify controller (if any).
							 * If present, target nqn is immutable, and target will
							 * appear in targets_by_nqn sequence. */
	struct spdk_uuid	uuid;			/* UUID of target (zero if unknown). If it doesn't match
							 * the redirector UUID, this is not a default target (We'll
							 * only use it when hints name this bdev, or this namespace
							 * UUID) */
	uint8_t			nguid[16];		/* NGUID of target, or zero if unknown */
	uint64_t		eui64;			/* EUI64 of target, or zero if unknown */
	struct spdk_nvme_ctrlr_data ctrlr_data;		/* From IDENTIFY_CONTROLLER */
	struct redirector_target_stats {
		uint64_t	removed_count;
		uint64_t	hot_removed_count;
		uint64_t	io_count;		/* Cumulative */
		uint64_t	queued_io_count;	/* Cumulative */
		uint64_t	ios_in_flight;		/* At last channel update */
		uint64_t	ios_queued;		/* At last channel update */
	} stats;
	struct redirector_target_hint_stats {
		uint64_t	generation;		/* Generation number of last hints log page consumed from
							 * this target */
		uint64_t	hint_poll_count;	/* Target hint log page examined for changes */
		uint64_t	hint_notify_count;	/* Async hint change notificationds from target */
		uint64_t	hint_update_count;	/* Changes detected and consumed from target hint page */
		uint64_t	hint_replace_count;	/* Consumed hint page changes replaced hints from target */
	} hint_stats;
	struct redirector_target_stats_coll {		/* Written to by for_each_channel function */
		uint64_t	ch_io_count;
		uint64_t	ch_queued_io_count;
		uint64_t	ch_ios_in_flight;
		uint64_t	ch_ios_queued;
	} ch_stats_coll;
	/* TODO: Source: static config, or DS */
};

/* Everything needed to configure a redirector when it can be created
 */
struct redirector_config {
	char			*redirector_name;
	uint64_t		blockcnt;
	uint32_t		blocklen;
	uint32_t		required_alignment;
	uint32_t		optimal_io_boundary;
	char			*nqn;			/* NQN of redirector (if known) */
	struct spdk_uuid	uuid;			/* UUID of redirector logical namespace */
	struct {
		uint32_t	size_configured : 1;	/* Size specified in config (not inherited from another
							 * redirector) */
		uint32_t	uuid_inherited : 1;	/* Namespace UUID was inherited from a redirector target */
		uint32_t	uuid_generated : 1;	/* Namespace UUID was generated */
		uint32_t	auth_hints : 1;		/* We have or had authoritative hints */
	};
	struct redirector_bdev	*redirector_bdev;
	GSequence		*targets;		/* All targets by bdev */
	GSequence		*targets_by_nqn;	/* Targets by NQN (for targets with known NQNs) */
	/* Location hints configured on or learned by this redirector. Ordered according
	   to location_hint_data_and_target_compare() and default_compare_opts */
	GSequence		*hints;
	struct {
		/* If the hints list above contains a hash hint, the supporting tables are here.
		 * These point to the tables in the hint struct, which are freed with the hint struct. */
		struct hash_hint_table	*hash_table;
		struct nqn_list		*nqn_list;
		char			*hash_hint_source;
		struct hash_hint_nvme_state hash_hint_pages;
	} hash_hint_tables;
	TAILQ_ENTRY(redirector_config)	config_link;
};

/* List of virtual bdevs and associated info for each. */
struct redirector_bdev {
	struct redirector_config	*config;
	size_t				num_rd_targets;
	struct redirector_bdev_target {
		struct spdk_bdev	    *bdev;
		struct spdk_bdev_desc	    *desc;
		struct redirector_target    *target_config;
		int			    max_qd;
		struct {
			uint32_t	    drain : 1;
			uint32_t	    free_index : 1;
			uint32_t	    reading_hints : 1;
		};
	} targets[REDIRECTOR_MAX_TARGET_BDEVS];
	/* Complete location map (rule table) for this bdev. Derived from config->hints, with overlaps
	 * and ambiguity resolved. Refers only to targets that are present now. */
	GSequence			*locations;	   /* Rules prepared and ready to apply
							    *(or NULL if applied) */
	GSequence			*applied_rules;	   /* Rules in use or being replaced */
	GSequence			*replaced_rules;   /* Replaced rules (or NULL once replacement complete) */
	/* Location hint log page contents for all redirector initiators. This is replaced whenever the rule table is
	 * replaced, and uses the same mechanism.
	 *
	 * For now all initiators see the same hints. This is not ideal, but as a bdev this redirector can't
	 * distinguish IO or log page reads from different connected NVMF hosts, nor local redirector bdev
	 * initiators. */
	struct redirector_bdev_hint_page {
		uint64_t		buffer_size;	   /* Size of hint page buffer allocation. Reported size
							    * is <= this */
		uint64_t		generation;
		struct rd_hint_log_page	*buf;		   /* Hint page ready to be applied to channels */
		struct rd_hint_log_page	*applied_buf;	   /* Hint page in use or being replaced */
		struct rd_hint_log_page	*replaced_buf;	   /* Replaced hint page (or NULL once replacement
							    * completes) */
		/* Other log pages used to pass hints to hosts. All are replaced the same way the hint
		 * page is.*/
		struct redirector_bdev_hash_table_page {
			uint64_t buffer_size;		   /* Size of hash table page buffer allocation. */
			uint64_t generation;
			struct rd_hash_table_log_page *buf;
			struct rd_hash_table_log_page *applied_buf;
			struct rd_hash_table_log_page *replaced_buf;
		} hash_table;
		struct redirector_bdev_nqn_list_page {
			uint64_t buffer_size;		   /* Size of nqn list page buffer allocation. */
			uint64_t generation;
			struct rd_nqn_list_log_page *buf;
			struct rd_nqn_list_log_page *applied_buf;
			struct rd_nqn_list_log_page *replaced_buf;
		} nqn_list;
	} hint_page;
	struct {
		GSList			*starting;	   /* Completions for next channel update */
		GSList			*in_progress;	   /* Completions for current channel update */
	}				ch_update_cpl;
	int				tgt_adm_cmd_in_flight; /* NVME admin commands to targets */
	int				num_self_ref;	       /* number of self-ref descs */
	GSList				*tgt_adm_cmd_cpl;      /* Completions when 0 commands in flight */
	struct {
		uint32_t		registered : 1;
		uint32_t		updating_channels : 1;
		uint32_t		updating_channel_rules : 1;
		uint32_t		rule_update_pending : 1;
		uint32_t		target_update_pending : 1;
		uint32_t		other_update_pending : 1;
		uint32_t		reset_in_progress : 1;
	};
	struct spdk_poller		*hint_poller;
	struct redirector_bdev_stats {
		uint64_t		rule_updates;
		uint64_t		target_updates;
		uint64_t		channel_updates;
		uint64_t		hot_removes;
		uint64_t		channel_count;		/* Latest ch count */
		uint64_t		channels_drained;	/* Cumulative */
		uint64_t		channel_ios_drained;	/* Cumulative */
	} stats;
	struct redirector_bdev_ch_stats_coll {		   /* Written to by for_each_channel function */
		uint64_t		ch_count;
		uint64_t		ch_drain_count;	   /* CHs with >0 IOs to drain */
		uint64_t		ch_ios_drained;    /* IOs waited for during drain */
	} ch_stats_coll;
	struct spdk_bdev		redirector_bdev;   /* the redirector virtual bdev */
	TAILQ_ENTRY(redirector_bdev)	bdev_link;
};

/*
 * The redirector vbdev channel struct.
 *
 * See vbdev_redirector_update_channel_state() for how these channel structs are updated when rules and the targets
 * they refer to are updated.
 */
struct redirector_bdev_io_channel {
	GSequence			*rules;		/* A version of bdev->locations */
	struct rd_hint_log_page		*hint_log_page;	/* A version of bdev->hint_page.buf */
	struct rd_hash_table_log_page	*hash_table_log_page;
	struct rd_nqn_list_log_page	*nqn_list_log_page;
	size_t				num_ch_targets;
	size_t				num_draining;
	struct spdk_io_channel_iter	*state_update_iter;
	struct redirector_bdev_io_channel_target {
		int			ios_in_flight;
		int			ios_queued;
		int			max_qd;
		uint64_t		io_count;	/* Completed IOs */
		uint64_t		queued_io_count;/* Completed IOs that were queued */
		struct spdk_io_channel	*ch;		/* IO channels of target devices */
		bdev_io_tailq_t		queued_io_tailq;
		struct {
			uint32_t	draining : 1;
			uint32_t	drained : 1;
		};
	} targets[REDIRECTOR_MAX_TARGET_BDEVS];
};

struct redirector_bdev_io {
	enum spdk_bdev_io_type		type;			/* Possibly translated */
	struct spdk_io_channel		*ch;
	int				target_index;		/* If assigned, this IO is counted as in-flight for
								 * this target */
	uint64_t			target_offset;		/* Valid if target_index_assigned */
	struct {
		uint32_t		target_index_assigned : 1;
		uint32_t		in_flight : 1;
		uint32_t		is_queued : 1;
		uint32_t		was_queued : 1;
		uint32_t		target_noop : 1;	/* IO is no-op for target */
	};

	/* for bdev_io_wait */
	struct spdk_bdev_io_wait_entry bdev_io_wait;

	/* Used for tracking progress of reset requests sent to target devs */
	uint8_t				target_bdev_io_submitted;
	uint8_t				target_bdev_io_completed;
	uint8_t				target_bdev_io_expected;
	uint8_t				target_bdev_io_status;
};

#endif /* SPDK_VBDEV_REDIRECTOR_TYPES_H */
