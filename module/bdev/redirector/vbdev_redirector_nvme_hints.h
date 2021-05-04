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
 * Location hint log page structures. These define the protocol used to pass location hints from ADNN target
 * redirectors to ADNN initiator redirectors.
 */

#ifndef SPDK_VBDEV_REDIRECTOR_NVME_HINTS_H
#define SPDK_VBDEV_REDIRECTOR_NVME_HINTS_H

#include "vbdev_redirector_types.h"

#define RD_HINT_ENTRY_MAX_LEN	1024
#define RD_HINT_PAGE_DEFAULT_SIZE (1024 * 128)

#define RD_NQN_LEN sizeof(((struct spdk_nvme_ctrlr_data*)NULL)->subnqn)

/*
 * Common description of LN extent that a hint applies to. Most hints use this.
 *
 * In general the bounds of a location hint must align with the required IO boundary of the redirector bdev, which must
 * agree with the NVMF transport(s) used to reach them. A DVM must select these bounds, and the configuration for all
 * NVMF transports used between redirectors to ensure this.
 *
 * No IO submitted to a redirector should cross the boundary of any location hint. Fast IO paths (and HW offloads) will
 * probably only examine the IO start LBA when selecting a target, and only validate that the last LBA doesn't cross
 * the required IO boundary. These fast paths will pass all unaligned IOs to a general (and slower) SW IO path that can
 * handle fragmentation and reassembly.
 */
struct __attribute__((packed)) rd_hint_extent {
	uint64_t		start_lba;		/* First affected LBA */
	uint64_t		blocks;			/* Affected LBA count */
};

/*
 * RD_HINT_TYPE_SIMPLE_NQN
 *
 * LBA range to target NQN
 *
 * Different target, same NS & offset
 *
 * Ignored until subsystem with dest_nqn becomes reachable. A redirector may forward this hint verbatim. That's not
 * true for all hint types.
 */
struct __attribute__((packed)) rd_hint_simple_nqn {
	struct rd_hint_extent	extent;
	rd_nqn			dest_nqn;
};

/*
 * RD_HINT_TYPE_SIMPLE_NQN_NS
 *
 * LBA range to target NQN, target NGUID, and offset into NGUID
 *
 * Can redirect to a different namespace at a different offset in a different target
 *
 * Ignored until subsystem with dest_nqn containing a namespace with dest_nguid becomes reachable.
 */
struct __attribute__((packed)) rd_hint_simple_nqn_ns {
	struct rd_hint_extent	extent;
	uint64_t		dest_offset;	/* Offset of extent.start_lba in destination.  Normally the same as
						 * extent.start_lba. */
	rd_nqn			dest_nqn;	/* Destination (target) NQN, or zero for this redirector */
	rd_nguid		dest_nguid;	/* If nonzero, redirect IO to this namespace. TODO: Needs to be an
						 * nvme_ns_id_desc, so EUI64 and UUID can also be used here. */
};

/*
 * Alternate target selection policy used in RD_HINT_TYPE_SIMPLE_NQN_ALT
 */
enum rd_alt_policy {
	RD_ALT_POLICY_NONE	    = 0,    /* Client chooses anyhow it likes */
	RD_ALT_POLICY_ORDER	    = 1,    /* Ordered most to least preferred */
	RD_ALT_POLICY_RR	    = 2,    /* Client RR among alternatives */
	RD_ALT_POLICY_LAST		    /* Leave last */
};

/*
 * RD_HINT_TYPE_SIMPLE_NQN_ALT
 *
 * LBA range to one of several alternate target NQNs
 *
 * Different target (one of several), same NS & offset
 */
struct __attribute__((packed)) rd_hint_simple_nqn_alt {
	struct rd_hint_extent	extent;
	uint8_t			alt_policy; /* rd_alt_policy */
	struct {
		rd_nqn		dest_nqn;
	} alternatives[];		    /* Count indicated by hint length */
};

/*
 * RD_HINT_TYPE_SIMPLE_NQN_TABLE
 *
 * LBA range to target NQN
 *
 * Different target (via lookup table), same NS & offset
 *
 * Redirectors receiving this hint will ignore it if they can't read nqn_list_log_page, don't find an NQN in that table
 * at index nqn_list_entry, or if they don't have a connection to the NQN found there.
 *
 * This hint can't be forwarded verbatim. The nqn_list_entry field is only usable in the nqn_list_log_page on the
 * redirector that sent the hint. The nqn_list_log_page is also only valid on the redirector that sent the hint. Other
 * redirectors may use a different log page, and may list the NQNs they contain in different orders.
 *
 * To forward this hint, a redirector must either translate it into an RD_HINT_TYPE_SIMPLE_NQN (supplying the entire
 * NQN), or translate the nqn_list_entry field to the index of the matching NQN in its own nqn_list_log_page (and of
 * course supply the log page ID of that in nqn_list_log_page).
 */
struct __attribute__((packed)) rd_hint_simple_nqn_table {
	struct rd_hint_extent	extent;
	rd_nqn_list_index_t	nqn_list_index;
	rd_log_page_id_t	nqn_list_log_page;	/* A log page generated by this redirector with contents
							 * defined by rd_nqn_list_log_page. */
};

/*
 * NQN list log page for RD_HINT_TYPE_SIMPLE_NQN_TABLE and RD_HINT_TYPE_HASH_NQN_TABLE, etc.
 *
 * NQNs should only be added to this table, never removed or reordered. This prevents the NQN list indexes
 * used in other hints (e.g. the hash table) from being invalidated. (Stable NQN table is currently unimplemented)
 *
 * A redirector may produce a single rd_nqn_list_log_page, and refer to it in multiple location hints for multiple
 * logical namespaces.
 *
 * Different redirectors (even on the same host) may provide this log page, and may list the NQNs it contains in
 * different orders.
 */
struct __attribute__((packed)) rd_nqn_list_log_page {
	uint64_t		generation;		/* Incremented when changed */
	uint64_t		length;			/* Length in bytes of entire log page */
	rd_list_digest_t	list_digest;		/* Digest (hash) of this NQN list. The digest includes
							 * only the NQN strings (not the NULL terminators) in
							 * the order they appear here. This allows host
							 * redirectors to quickly identify identical NQN
							 * tables, even for different namespaces. */
	uint16_t		num_nqns;		/* Number of null terminated strings in nqns[] */
	char			nqns[];			/* Count indicated by log page length */
};

/*
 * Striping hint extent, used in RD_HINT_TYPE_STRIPE_NQN
 *
 * The idea here is to describe a group of several stripes (potentially the entire LN) with a single location hint.
 *
 * We divide LN LBAs into power of two sized groups called strips. These are stored in a number of target extents
 * called stripe extents. The set of stripe extents is called the stripe group. Adjacent strips are mapped sequentially
 * across the stripe extents (LN strip 0 to strip 0 of stripe extent 0, etc.). Each set of strips mapped to each of the
 * stripe extents is called a stripe.
 *
 * The stripe hint specifies the log(2) of the stripe size in bytes, and the the stripe extent count. The strip size
 * will be the stripe size in bytes / the stripe extent count. The hint length should be an integer multiple of the
 * strip size (but may be less if the LN must be smaller than that). The stripe extent length is stripe count * strip
 * size.
 *
 * It's up to the volume manager to ensure the stripe extents are the right size. If the LN is resized (larger), and
 * the stripe extents cannot be resized (larger), the DVM should extend the LN by allocating additional stripe extents
 * and using an additional striping hint for the added region of the LN.
 *
 * The DVM must choose a strip size that aligns with the global location hint alignment and redirector required IO
 * boundary settings.  User IO should never cross a location hint or strip boundary (else incur fragmentation
 * overhead).
 */
struct __attribute__((packed)) rd_stripe_params {
	uint8_t			log2_stripe_size;	/* log(2) of bytes per stripe */
	uint8_t			stripe_extents;		/* Target stripe extent count */
};

/*
 * RD_HINT_TYPE_STRIPE_NQN
 *
 * Stripe LBA range over regions of several target NQNs
 *
 * Different target per strip, same NS & offset
 *
 * This can be used by redirectors in hosts to send the strips to the correct remote target. These hosts don't have
 * direct access to the PN's containing the stripe extents, and don't need the ability to translate each strip's
 * location in the LN to its corresponding stripe extent NGUID and offset. The DVM may find it desirable to hide the
 * actual NGUIDs and PN device names / NQNs from these redirectors. These NQN-only striping hints are also smaller.
 */
struct __attribute__((packed)) rd_hint_stripe_nqn {
	struct rd_hint_extent	extent;
	struct rd_stripe_params	stripe;
	rd_nqn			stripe_extent_nqns[]; /* 1 << stripe.log2_stripe_extents-1 */
};

/*
 * RD_HINT_TYPE_STRIPE_NQN_NS
 *
 * Stripe LBA range over several target NQNs
 *
 * Different target, NS & offset
 *
 * Egress redirectors need this to map the LN strips into the stripe extents they contain. In these cases the
 * stripe_extents entries in the hint corresponding to physical namespaces connected to this redirector will identify
 * that target (probably by a local device name rather than an NQN), the NGUID on that target (the DVM may omit that
 * for local NVMe devices), and the offset of the stripe extent on that target. The other stripe_extents entries in
 * these egress redirectors will contain the NQN of another egress redirector, all zeros in the NGUID (no namespace
 * translation for that LBA range on this redirector), and a dest_offset equal to extent.start_lba (no LBA translation
 * for that LBA range on this redirector).
 *
 * Hints naming egress targets will be given to egress redirectors by the DVM via the control interface. Before passing
 * hints with egress targets to other redirectors, egress redirectors will replace that target NQN, NGUID, and offset
 * with its own NQN, and omit the destination NS and offset (using the NQN-only form of the hint, or by adjusting them
 * to indicate no NS or offset translation).
 */
struct __attribute__((packed)) rd_hint_stripe_nqn_ns {
	struct rd_hint_extent	extent;
	struct rd_stripe_params	stripe;
	struct {
		uint64_t	dest_offset;	/* Offset in NQN.NGUID of this stripe extent. */
		rd_nqn		dest_nqn;	/* Destination (target) NQN, or zero for this redirector */
		rd_nguid	dest_nguid;	/* If nonzero, redirect IO to this namespace. TODO: Needs to be an
						 * nvme_ns_id_desc, so EUI64 and UUID can also be used here. */
	} stripe_extents[];			/* Count: 1 << stripe.log2_stripe_extents-1 */
};

/*
 * RD_HINT_TYPE_HASH_NQN_TABLE
 *
 * The idea here is to enable NVMF to be used to access namespaces stored in distributed storage systems like Ceph and
 * Gluster. These both segment namespaces and place the segments in available storage deices based on a hash of the
 * name of the segment. This hint enables ADNN to direct IO to a region of a namespace to the Ceph or Gluster storage
 * node that contains it (or to the specific NUMA node if the storage node is configured with ADNN redirector targets
 * in each of them). This removes the requirement to run storage system specific clients in the host, and the need for
 * separate gateway machines. This comes at the cost of handling a fraction of the NVMF gateway overhead in each
 * storage node. The cluster specific network traffic between hosts and cluster nodes is replaced with NVMe-oF.
 *
 * We divide a LN into fixed size objects, and choose the target for them using a hash function to produce an index
 * into a table of targets.
 *
 * Different target per object, same NS & offset
 *
 * When used with LN's that are stored in Ceph RBD images the host redirector uses this type of location hint to send
 * IO for each RADOS object in an RBD image to the NVMF target in the Ceph OSD node that should (according to the hash
 * function) contain that object. In real Ceph clusters some objects will not be where the hash function would put
 * them. As these are discovered (and the first IO is completed to them from the wrong OSD node via RADOS), the ADNN
 * NVMf targets in the OSD nodes will emit simple location hints to the source of that IO targeting the NVMf target in
 * the Ceph OSD node where the object is actually located. Simple hint retention by redirectors is best effort, so when
 * a large number of objects are out of place performance may suffer. Ceph will eventually remedy this with its
 * background rebalancing activity.
 *
 * For every IO the redirector determines which LN chunk it falls into. It generates the chunk name by supplying the
 * chunk number to snprintf as the argument to the format string in this hint. Valid format strings may only take one
 * format arg of type uint64_t, and of one of a few format specifiers (TBD, but valid numeric formatters with field
 * width modifiers). The has function specified in the hint is then applied to the chunk name. The resulting hash value
 * is then truncated (mod hash_bucket_count), and the truncated result used to look up a target in
 * hash_table_log_page. That gives an nqn_list index, which (logically) is applied to the contents of the
 * nqn_list_log_page to obtain the destination NQN. Actual redirectors probably combine those tables into a copy of the
 * hash table that directly yields an output device or QP.
 *
 * When the redirector doesn't have a connection to the NQN returned from the hash function, the redirector may choose
 * any other target for this LN, and rely on it being forwarded (or completed) by that redirector. A redirector could
 * forward all these IOs to its default target (relying on the DVM to configure each redirector with a default target
 * that's nearby or low overhead), or it could use the first hash table entry following the one the hash function
 * indicated that it has a working connection to (which may spread the forwarding load due to target reachability
 * across several redirectors).
 *
 * The IO must fit in a single chunk. The redirector IO size & alignment should ensure that, but the redirector will
 * have to verify that it did. IOs that span chunks must be split at the chunk boundary and resubmitted.
 *
 * Hash hints always apply to the entire LN.
 *
 * The log page ids in this hint are only valid on the redirector that sent the hint, and the nqn_list_entry_t's in the
 * hash table are only valid in the nqn_list_log_page on the same redirector. Redirectors forwarding a
 * RD_HINT_TYPE_HASH_NQN_TABLE must construct their own equivalent nqn_list and hash_table log pages.
 *
 * There is no RD_HINT_TYPE_HASH_NQN form of this hint (listing NQNs directly in the hash table), because NQNs are
 * fairly large, and there will probably be far more hash table buckets than there are unique NVMF target NQNs in the
 * cluster.
 *
 * A RD_HINT_TYPE_HASH_NQN_TABLE with any or all all the fields set to zero still replaces any previously sent
 * hash hint and effectively deletes it.
 */
#define RD_HASH_HINT_MIN_LOG2_CHUNK_SIZE 12
#define RD_HASH_HINT_MAX_LOG2_CHUNK_SIZE 63
struct __attribute__((packed)) rd_hint_hash_nqn_table {
	uint8_t			log2_chunk_size;	/* LN divided into regions of 2^this bytes */
	uint8_t			hash_function_id;	/* rd_hash_fn_id */
	rd_log_page_id_t	hash_table_log_page;	/* A log page generated by this redirector with contents
							 * defined by rd_hash_table_log_page. */
	rd_log_page_id_t	nqn_list_log_page;	/* A log page generated by this redirector with contents
							 * defined by rd_nqn_list_log_page. */
	uint8_t			chunk_format_string_len;/* If zero, hint is not applied */
	uint8_t			chunk_name_format[];	/* A format string for snprintf() taking the object number
							 * as its only format argument. */
};

/*
 * Hash table log page for RD_HINT_TYPE_HASH_NQN_TABLE
 *
 * The contents of this log page are generated by the redirector(s) that construct the rd_hint_hash_nqn hint, and only
 * make sense when used with the nqn_list log page from the same redirector. Each bucket is an index of an NQN in the
 * nqn_list_log_page specified in the rd_hint_hash_nqn_table.
 *
 * Consumers of the hash hint must check this log page for changes when consuming hints from the redirector
 * they've received a hash hint from, even if they don't receive an updated hash hint. If the generation field
 * has not changed since the last time the hash table page was read, consumers can assume the contents have not
 * changed.
 *
 * Redirectors that receive hash hints for multiple namespaces and/or from multiple targets may use the
 * list_digest field to identify identical hash table contents.
 */
struct __attribute__((packed)) rd_hash_table_log_page {
	uint64_t		generation;		/* Incremented when changed */
	uint64_t		length;			/* Length in bytes of entire log page */
	rd_list_digest_t	list_digest;		/* Digest (hash) of the expanded form of this hash
							 * table. The expanded form uses the actual NQN
							 * strings in each bucket. Only the NQN strings are
							 * hashed (not the NULL terminator), in the order they
							 * appear in this hash table. All Ceph egress
							 * redirectors should generate the same hash table for
							 * any image, which will have the same digest. This
							 * allows host redirectors to quickly identify
							 * identical hash tables, even for different
							 * namespaces. */
	uint32_t		bucket_count;		/* Number of hash buckets */
	rd_nqn_list_index_t	nqns[];			/* Array of hash buckets pointing to NQNs */
};

/*
 * RD_HINT_TYPE_DIFF_NQN_NS
 *
 * Divide LN into fixed-size chunks, and redirect IO for any chunk to one of several different namespaces (probably in
 * separate redirectors).
 *
 * This is indented to be used by a DVM supporting snapshots or differencing volumes. In this use case a (child) LN
 * corresponds to the contents of a parent LN, except where the application has written to the child. Reads of the
 * modified regions must come from the child, and reads from regions unchanged from the parent should go to the
 * parent. There can be several layers of differencing here, with the child on top of the stack, and the series of
 * parents below. A DVM may locate extents of the parent and child regions in different devices or different
 * nodes. Immutable parents may have multiple readable copies, and the host may be able to choose a nearer/faster
 * replica for reads from that parent.
 *
 * The DVM exposes the LN corresponding to the first parent (lowest in the stack, with no parents, just children),
 * called LN-P0. The DVM exposes all the parent layers as separate (R/O) namespaces (LN-P0 through LN-Pn), and one
 * writable namespace (LN-C) corresponding to the child (top of the stack, no children, only a parent).
 *
 * A RD_HINT_TYPE_DIFF_NQN_NS is constructed by this DVM directing all writes to LN-C, and reads for each chunk tho the
 * topmost layer in which that object differs from the layer below. Storage backends may encode that in a variety of
 * ways, but in the RD_HINT_TYPE_DIFF_NQN_NS the DVM translates the storage backend's representation into the
 * rd_diff_map_log_page struct, and passes that in the diff_map_log_page. One version of that is an array of bytes, one
 * byte for each chunk of the image indicates which layer in the stack gets reads for that chunk.
 *
 * We assume here that parent LNs are immutable, and that writes only go to the topmost child LN. A parent LN may have
 * multiple child LNs, but no parent LN is writable.
 *
 * When a chunk of the LN which was previously inherited from a parent is written to for the first time, the DVM will
 * update the diff_map log page. Redirectors that pass these writes can assume that subsequent reads of that chunk will
 * be redirected to the child layer.
 *
 * Redirectors that can support >1 namespace should repeat the target selection for every IO that has its namespace
 * transformed by the DIFF hint. This bdev redirector cannot accept IO for >1 namespace, but could apply hints for one
 * of the target namespaces to IO after it was redirected to one of them. When this bdev redirector passes the hash
 * hint to other redirectors, the target NQN for the alternate NGUIDs must refer to a redirector that can accept IO for
 * that NS. The DVM will probably have to construct one redirector bdev and NVMF subsystem NS on every node for every
 * differencing layer.
 */
struct __attribute__((packed)) rd_hint_diff_nqn_ns {
	uint8_t			log2_chunk_size;	/* LN divided into regions of 2^this bytes */
	uint8_t			layer_count;		/* Number of differencing layers */
	rd_log_page_id_t	diff_map_log_page;	/* A log page generated by this redirector with contents
							 * defined by rd_diff_map_log_page. */
	struct {
		rd_nqn		dest_nqn;	/* Destination (target) NQN, or zero for this redirector */
		rd_nguid	dest_nguid;	/* If nonzero, redirect IO to this namespace */
	} diff_layers[];			/* layer_count entries */
};

/*
 * RD_HINT_TYPE_DIFF_HASH_NQN_TABLE
 *
 * Apply different hash based target selection to the layers of a differencing LN (e.g. Ceph RBD image clones).  This
 * is a stack of RD_HINT_TYPE_HASH_NQN_TABLE hints, sharing the same hash function and block size, where the hash
 * function is selected by the diff_map log page. The RD_HINT_TYPE_DIFF_HASH_NQN_TABLE hint does not translate the
 * namespace of IO applied to it, so a single redirector bdev should be able to process any IO to any layer.
 *
 * As with the simpler DIFF hint, all writes go to the child (top) layer, and all lower layers are R/O and immutable.
 * A redirector applying this hint to a write can assume that all subsequent IO (R or W) to that chunk / object should
 * go to the top layer.
 */
struct __attribute__((packed)) rd_hint_diff_hash_nqn_table {
	uint8_t			log2_chunk_size;	/* LN divided into regions of 2^this bytes */
	uint8_t			hash_function_id;	/* rd_hash_fn_id */
	uint8_t			layer_count;		/* Number of differencing layers */
	rd_log_page_id_t	diff_map_log_page;	/* A log page generated by this redirector with contents
							 * defined by rd_diff_map_log_page. */
	rd_log_page_id_t	nqn_list_log_page;	/* A log page generated by this redirector with contents
							 * defined by rd_nqn_list_log_page. */
	struct {
		uint16_t		hash_bucket_count;
		rd_log_page_id_t	hash_table_log_page;	/* A log page generated by this redirector with contents
								 * defined by rd_hash_table_log_page. */
		uint16_t		chunk_format_string_len;
		uint8_t			chunk_name_format;	/* A format string for snprintf() taking the object number
								 * as its only format argument. */
	} diff_layers[];				/* layer_count entries */
};

/* A single hint entry in the location hint log page */
struct __attribute__((packed)) rd_hint_entry {
	struct rd_hint_entry_header {
		uint16_t		hint_len;	/* Includes the size of rd_hint_entry_header, and the
							 * (possibly variable length) size of the specific
							 * hint struct in the union below */
		uint8_t			hint_type;	/* rd_hint_type */
		struct {
			/* A hint specifying just read or just write should be treated
			 * as more specific than one specifying both. */
			uint8_t		read : 1;	/* Hint applies to reads */
			uint8_t		write : 1;	/* Hint applies to writes */
			uint8_t		reserved : 6;
		};
	} h;
	union {
		/* Simple */
		struct rd_hint_simple_nqn		simple_nqn;
		struct rd_hint_simple_nqn_ns		simple_nqn_ns;
		struct rd_hint_simple_nqn_alt		simple_nqn_alt;
		struct rd_hint_simple_nqn_table		simple_nqn_table;
		/* Striping */
		struct rd_hint_stripe_nqn		stripe_nqn;
		struct rd_hint_stripe_nqn_ns		stripe_nqn_ns;
		/* Hashing */
		struct rd_hint_hash_nqn_table		hash_nqn_table;
		/* Differencing */
		struct rd_hint_diff_nqn_ns		diff_nqn_ns;
		struct rd_hint_diff_hash_nqn_table	diff_hash_nqn_table;
	};
};

struct __attribute__((packed)) rd_hint_log_page {
	struct rd_hint_log_page_header {
		uint64_t	    generation;		/* Incremented when changed */
		uint64_t	    length;		/* Length in bytes of entire log page */
		struct {
			uint64_t    retain_prev : 1;	/* True if client should retain hints from previous
							   versions of this hint log page */
		};
	} h;
	struct rd_hint_entry	first_hint;	/* Count indicated by log page length */
};

bool rd_new_hint_log_pages(struct redirector_bdev *rd_node);

uint64_t rd_ch_get_hint_log_page_size(struct redirector_bdev_io_channel *rd_ch);
uint64_t rd_ch_get_nqn_list_log_page_size(struct redirector_bdev_io_channel *rd_ch);
uint64_t rd_ch_get_hash_table_log_page_size(struct redirector_bdev_io_channel *rd_ch);

struct rd_hint_buf {
	void *buf;
	size_t remaining; /* bytes */
};

/* For all log page consume functions */
struct rd_log_page_buf_stream {
	size_t page_remaining;
	struct rd_hint_buf prev;    /* next and prev point to the payload parts of separate
				     * admin command structs */
	struct rd_hint_buf next;
	bool end_found;
	bool success;
};

/* For vbdev_redirector_consume_hints */
struct rd_hint_buf_stream {
	struct rd_log_page_buf_stream stream;
	bool changed; /* hint log page changed since last read */
	GList *decoded_hints; /* struct location_hint* */
	size_t num_hash_hints; /* number of hash hints in the list. We'll ignore all but the last one */
	struct location_hint *hash_hint; /* If not NULL, points to the last hash hint in the list above */
	bool destroyed;
};

struct location_hint *
rd_hint_buf_stream_consume_first_hint(struct rd_hint_buf_stream *bufs);

void
rd_hint_buf_stream_destruct(struct rd_hint_buf_stream *bufs);

void
vbdev_redirector_consume_hints(struct redirector_bdev *rd_node,
			       struct redirector_target *target_config,
			       struct rd_hint_buf_stream *bufs);

/* For vbdev_redirector_consume_hash_table */
struct rd_hash_table_buf_stream {
	struct rd_log_page_buf_stream stream;
	bool changed; /* nqn_list log page changed since last read */
	struct rpc_redirector_hash_hint_hash_table *rpc_table;
	size_t next_bucket;
	bool destroyed;
};

void
rd_hash_table_buf_stream_destruct(struct rd_hash_table_buf_stream *bufs);

void
vbdev_redirector_consume_hash_table(struct redirector_bdev *rd_node,
				    struct redirector_target *target_config,
				    struct rd_hash_table_buf_stream *bufs);

/* For vbdev_redirector_consume_nqn_list */
struct rd_nqn_list_buf_stream {
	struct rd_log_page_buf_stream stream;
	bool changed; /* nqn_list log page changed since last read */
	struct rpc_redirector_hash_hint_nqn_table *rpc_table;
	size_t next_nqn;
	bool destroyed;
};

void
rd_nqn_list_buf_stream_destruct(struct rd_nqn_list_buf_stream *bufs);

void
vbdev_redirector_consume_nqn_list(struct redirector_bdev *rd_node,
				  struct redirector_target *target_config,
				  struct rd_nqn_list_buf_stream *bufs);

#endif /* SPDK_VBDEV_REDIRECTOR_NVME_HINTS_H */
