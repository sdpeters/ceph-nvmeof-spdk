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

#define spdk_for_each_channel _ut_spdk_for_each_channel
#define spdk_for_each_thread _ut_spdk_for_each_thread
#define spdk_get_thread _ut_spdk_get_thread
#define spdk_poller_register _ut_spdk_poller_register
#define spdk_poller_unregister _ut_spdk_poller_unregister
#define spdk_io_device_register _ut_spdk_io_device_register
#define spdk_io_device_unregister _ut_spdk_io_device_unregister
#define spdk_get_io_channel _ut_spdk_get_io_channel
#define spdk_put_io_channel _ut_spdk_put_io_channel
#define spdk_thread_lib_init _ut_spdk_thread_lib_init
#define spdk_thread_send_msg _ut_spdk_thread_send_msg

#include "spdk/stdinc.h"
#include "spdk_cunit.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "spdk/event.h"
#include "spdk_internal/mock.h"
#include "spdk_internal/event.h"
#include "bdev/redirector/vbdev_redirector_enum_names.c"
#include "bdev/redirector/vbdev_redirector_null_hash.c"
#include "bdev/redirector/vbdev_redirector_ceph_hash.c"
#include "bdev/redirector/vbdev_redirector_process_nvme_admin.c"
#include "bdev/redirector/vbdev_redirector_nvme_hints.c"
#include "bdev/redirector/vbdev_redirector_hints.c"
#include "bdev/redirector/vbdev_redirector_targets.c"
#include "bdev/redirector/vbdev_redirector_target_state.c"
#include "bdev/redirector/vbdev_redirector_target_admin_cmd.c"
#include "bdev/redirector/vbdev_redirector_hint_learning.c"
#include "bdev/redirector/vbdev_redirector_rule_table.c"
#include "bdev/redirector/vbdev_redirector_channel.c"
#include "bdev/redirector/vbdev_redirector_data_plane.c"
#include "bdev/redirector/vbdev_redirector_json.c"
#include "bdev/redirector/vbdev_redirector.c"
#include "bdev/redirector/vbdev_redirector_rpc.c"
#include "md5.h"

/* #define MAX_BASE_DRIVES 255 */
#define MAX_BASE_DRIVES 8
/* #define MAX_REDIRECTORS 31 */
#define MAX_REDIRECTORS 3
#define INVALID_IO_SUBMIT 0xFFFF
#define MAX_TEST_IO_RANGE (3 * 3 * 3 * (MAX_BASE_DRIVES + 5))

/* Data structure to capture the output of IO for verification */
struct io_output {
	struct spdk_bdev_desc       *desc;
	struct spdk_io_channel      *ch;
	uint64_t                    offset_blocks;
	uint64_t                    num_blocks;
	spdk_bdev_io_completion_cb  cb;
	void                        *cb_arg;
	enum spdk_bdev_io_type      iotype;
};

struct redirector_io_ranges {
	uint64_t lba;
	uint64_t nblocks;
};

/* Different test options, more options to test can be added here */
uint32_t g_blklen_opts[] = {512, 4096};
uint32_t g_strip_opts[] = {64, 128, 256, 512, 1024, 2048};
uint32_t g_iosize_opts[] = {256, 512, 1024};
uint32_t g_max_qd_opts[] = {64, 128, 256, 512, 1024, 2048};

/* Globals */
int g_bdev_io_submit_status;
struct io_output *g_io_output = NULL;
uint32_t g_io_output_index;
uint32_t g_io_comp_status;
bool g_child_io_status_flag;
void *rpc_req;
uint32_t rpc_req_size;
TAILQ_HEAD(bdev, spdk_bdev);
struct bdev g_bdev_list;
TAILQ_HEAD(waitq, spdk_bdev_io_wait_entry);
struct waitq g_io_waitq;
uint32_t g_block_len;
uint32_t g_strip_size;
uint32_t g_max_io_size;
uint32_t g_max_qd;
uint8_t g_max_base_drives;
uint8_t g_max_redirectors;
uint8_t g_ignore_io_output;
uint8_t g_rpc_err;
char *g_get_redirectors_output[MAX_REDIRECTORS];
uint32_t g_get_redirectors_count;
uint8_t g_json_beg_res_ret_err;
uint8_t g_json_decode_obj_err;
uint8_t g_json_decode_obj_construct;
uint8_t g_config_level_create = 0;
uint8_t g_test_multi_redirectors;
struct redirector_io_ranges g_io_ranges[MAX_TEST_IO_RANGE];
uint32_t g_io_range_idx;
uint64_t g_lba_offset;
bool g_verbose = false;
bool g_debug_print = false;
bool g_seed_specified = false;
uint32_t g_seed;
bool g_block_len_specified = false;
bool g_strip_size_specified = false;
bool g_max_io_size_specified = false;
bool g_max_qd_specified = false;
bool g_max_base_drives_specified = false;
bool g_max_redirectors_specified = false;
struct spdk_io_channel *g_io_channel = NULL;

/* Set randomly test options, in every run it is different */
static void
set_test_opts(void)
{
	uint32_t seed = time(0);

	/* Generate random test options */
	if (g_seed_specified) {
		seed = g_seed;
	}
	srand(seed);
	if (!g_max_base_drives_specified) {
		g_max_base_drives = (rand() % MAX_BASE_DRIVES) + 1;
	}
	if (!g_max_redirectors_specified) {
		g_max_redirectors = (rand() % MAX_REDIRECTORS) + 1;
	}
	if (!g_block_len_specified) {
		g_block_len = g_blklen_opts[rand() % SPDK_COUNTOF(g_blklen_opts)];
	}
	if (!g_strip_size_specified) {
		g_strip_size = g_strip_opts[rand() % SPDK_COUNTOF(g_strip_opts)];
	}
	if (!g_max_io_size_specified) {
		g_max_io_size = g_iosize_opts[rand() % SPDK_COUNTOF(g_iosize_opts)];
	}
	if (!g_max_qd_specified) {
		g_max_qd = g_max_qd_opts[rand() % SPDK_COUNTOF(g_max_qd_opts)];
	}

	printf("Test Options, seed = %u%s\n", seed, g_seed_specified ? " (from test arguments)" : "");
	printf("blocklen = %u%s, strip_size = %u%s, max_io_size = %u%s, max_qd = %u%s, g_max_base_drives = %u%s, g_max_redirectors = %u%s\n",
	       g_block_len, g_block_len_specified ? " (from args)" : "",
	       g_strip_size, g_strip_size_specified ? " (from args)" : "",
	       g_max_io_size, g_max_io_size_specified ? " (from args)" : "",
	       g_max_qd, g_max_qd_specified ? " (from args)" : "",
	       g_max_base_drives, g_max_base_drives_specified ? " (from args)" : "",
	       g_max_redirectors, g_max_redirectors_specified ? " (from args)" : "");
}

/* Set globals before every test run */
static void
set_globals(void)
{
	uint32_t max_splits;

	g_bdev_io_submit_status = 0;
	if (g_max_io_size < g_strip_size) {
		max_splits = 2;
	} else {
		max_splits = (g_max_io_size / g_strip_size) + 1;
	}
	if (max_splits < g_max_base_drives) {
		max_splits = g_max_base_drives;
	}

	g_io_output = calloc(max_splits, sizeof(struct io_output));
	SPDK_CU_ASSERT_FATAL(g_io_output != NULL);
	g_io_output_index = 0;
	memset(g_get_redirectors_output, 0, sizeof(g_get_redirectors_output));
	g_get_redirectors_count = 0;
	g_io_comp_status = 0;
	g_ignore_io_output = 0;
	g_config_level_create = 0;
	g_rpc_err = 0;
	g_test_multi_redirectors = 0;
	g_child_io_status_flag = true;
	TAILQ_INIT(&g_bdev_list);
	TAILQ_INIT(&g_io_waitq);
	rpc_req = NULL;
	rpc_req_size = 0;
	g_json_beg_res_ret_err = 0;
	g_json_decode_obj_err = 0;
	g_json_decode_obj_construct = 0;
	g_lba_offset = 0;
	g_normal_target_qd = REDIRECTOR_NORMAL_TARGET_QD;
	if (g_debug_print) {
		spdk_log_set_print_level(SPDK_LOG_DEBUG);
		spdk_log_set_flag("vbdev_redirector");
	}
}

static void
default_targets_cleanup(void)
{
	struct spdk_bdev *bdev;
	struct spdk_bdev *bdev_next;

	if (!TAILQ_EMPTY(&g_bdev_list)) {
		TAILQ_FOREACH_SAFE(bdev, &g_bdev_list, internal.link, bdev_next) {
			free(bdev->name);
			TAILQ_REMOVE(&g_bdev_list, bdev, internal.link);
			free(bdev);
		}
	}
}

/* Reset globals */
static void
reset_globals(void)
{
	if (g_io_output) {
		free(g_io_output);
		g_io_output = NULL;
	}
	rpc_req = NULL;
	rpc_req_size = 0;
}

void *
spdk_malloc(size_t size, size_t align, uint64_t *phys_addr, int socket_id, uint32_t flags)
{
	return malloc(size);
}

void *
spdk_zmalloc(size_t size, size_t align, uint64_t *phys_addr, int socket_id, uint32_t flags)
{
	void *buf = spdk_malloc(size, align, phys_addr, socket_id, flags);
	if (buf) {
		memset(buf, 0, size);
	}
	return buf;
}

void
spdk_free(void *buf)
{
	free(buf);
}

void
spdk_bdev_io_get_buf(struct spdk_bdev_io *bdev_io, spdk_bdev_io_get_buf_cb cb,
		     uint64_t len)
{
	SPDK_CU_ASSERT_FATAL(false);
}

/* Store the IO completion status in global variable to verify by various tests */
void
spdk_bdev_io_complete(struct spdk_bdev_io *bdev_io, enum spdk_bdev_io_status status)
{
	g_io_comp_status = ((status == SPDK_BDEV_IO_STATUS_SUCCESS) ? true : false);
}

/* It will cache the split IOs for verification */
int
spdk_bdev_writev_blocks(struct spdk_bdev_desc *desc, struct spdk_io_channel *ch,
			struct iovec *iov, int iovcnt,
			uint64_t offset_blocks, uint64_t num_blocks,
			spdk_bdev_io_completion_cb cb, void *cb_arg)
{
	struct io_output *p = &g_io_output[g_io_output_index];
	struct spdk_bdev_io *child_io;

	if (g_ignore_io_output) {
		return 0;
	}

	if (g_max_io_size < g_strip_size) {
		SPDK_CU_ASSERT_FATAL(g_io_output_index < 2);
	} else {
		SPDK_CU_ASSERT_FATAL(g_io_output_index < (g_max_io_size / g_strip_size) + 1);
	}
	if (g_bdev_io_submit_status == 0) {
		p->desc = desc;
		p->ch = ch;
		p->offset_blocks = offset_blocks;
		p->num_blocks = num_blocks;
		p->cb = cb;
		p->cb_arg = cb_arg;
		p->iotype = SPDK_BDEV_IO_TYPE_WRITE;
		g_io_output_index++;
		child_io = calloc(1, sizeof(struct spdk_bdev_io));
		SPDK_CU_ASSERT_FATAL(child_io != NULL);
		cb(child_io, g_child_io_status_flag, cb_arg);
	}

	return g_bdev_io_submit_status;
}

int
spdk_bdev_reset(struct spdk_bdev_desc *desc, struct spdk_io_channel *ch,
		spdk_bdev_io_completion_cb cb, void *cb_arg)
{
	struct io_output *p = &g_io_output[g_io_output_index];
	struct spdk_bdev_io *child_io;

	if (g_ignore_io_output) {
		return 0;
	}

	if (g_bdev_io_submit_status == 0) {
		p->desc = desc;
		p->ch = ch;
		p->cb = cb;
		p->cb_arg = cb_arg;
		p->iotype = SPDK_BDEV_IO_TYPE_RESET;
		g_io_output_index++;
		child_io = calloc(1, sizeof(struct spdk_bdev_io));
		SPDK_CU_ASSERT_FATAL(child_io != NULL);
		cb(child_io, g_child_io_status_flag, cb_arg);
	}

	return g_bdev_io_submit_status;
}

int
spdk_bdev_unmap_blocks(struct spdk_bdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t offset_blocks, uint64_t num_blocks,
		       spdk_bdev_io_completion_cb cb, void *cb_arg)
{
	struct io_output *p = &g_io_output[g_io_output_index];
	struct spdk_bdev_io *child_io;

	if (g_ignore_io_output) {
		return 0;
	}

	if (g_bdev_io_submit_status == 0) {
		p->desc = desc;
		p->ch = ch;
		p->offset_blocks = offset_blocks;
		p->num_blocks = num_blocks;
		p->cb = cb;
		p->cb_arg = cb_arg;
		p->iotype = SPDK_BDEV_IO_TYPE_UNMAP;
		g_io_output_index++;
		child_io = calloc(1, sizeof(struct spdk_bdev_io));
		SPDK_CU_ASSERT_FATAL(child_io != NULL);
		cb(child_io, g_child_io_status_flag, cb_arg);
	}

	return g_bdev_io_submit_status;
}

int
spdk_bdev_flush_blocks(struct spdk_bdev_desc *desc, struct spdk_io_channel *ch,
		       uint64_t offset_blocks, uint64_t num_blocks,
		       spdk_bdev_io_completion_cb cb, void *cb_arg)
{
	return 0;
}

bool
spdk_bdev_io_type_supported(struct spdk_bdev *bdev, enum spdk_bdev_io_type io_type)
{
	return true;
}

void
spdk_bdev_unregister(struct spdk_bdev *bdev, spdk_bdev_unregister_cb cb_fn, void *cb_arg)
{
	TAILQ_REMOVE(&g_bdev_list, bdev, internal.link);
	bdev->fn_table->destruct(bdev->ctxt);

	if (cb_fn) {
		cb_fn(cb_arg, 0);
	}
}

int
spdk_bdev_open(struct spdk_bdev *bdev, bool write, spdk_bdev_remove_cb_t remove_cb,
	       void *remove_ctx, struct spdk_bdev_desc **_desc)
{
	*_desc = (void *)0x1;
	return 0;
}

int
spdk_bdev_nvme_admin_passthru(struct spdk_bdev_desc *desc, struct spdk_io_channel *ch,
			      const struct spdk_nvme_cmd *cmd, void *buf, size_t nbytes,
			      spdk_bdev_io_completion_cb cb, void *cb_arg)
{
	cb(calloc(1, sizeof(struct spdk_bdev_io)), true, cb_arg);
	return 0;
}

void
spdk_bdev_io_get_nvme_status(const struct spdk_bdev_io *bdev_io, uint32_t *cdw0, int *sct, int *sc)
{
	assert(sct != NULL);
	assert(sc != NULL);
	assert(cdw0 != NULL);

	if (bdev_io->internal.status == SPDK_BDEV_IO_STATUS_NVME_ERROR) {
		*sct = bdev_io->internal.error.nvme.sct;
		*sc = bdev_io->internal.error.nvme.sc;
	} else if (bdev_io->internal.status == SPDK_BDEV_IO_STATUS_SUCCESS) {
		*sct = SPDK_NVME_SCT_GENERIC;
		*sc = SPDK_NVME_SC_SUCCESS;
	} else {
		*sct = SPDK_NVME_SCT_GENERIC;
		*sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
	}

	*cdw0 = bdev_io->internal.error.nvme.cdw0;
}

struct io_device {
	void				*io_device;
	char				*name;
	spdk_io_channel_create_cb	create_cb;
	spdk_io_channel_destroy_cb	destroy_cb;
	spdk_io_device_unregister_cb	unregister_cb;
	struct spdk_thread		*unregister_thread;
	uint32_t			ctx_size;
	uint32_t			for_each_count;
	TAILQ_ENTRY(io_device)		tailq;

	uint32_t			refcnt;

	bool				unregistered;
};

void
_ut_spdk_put_io_channel(struct spdk_io_channel *ch)
{
	if (ch == g_io_channel) {
		ch->ref--;
		if (ch->ref == 0) {
			ch->destroy_cb(ch->dev->io_device, spdk_io_channel_get_ctx(ch));
			g_io_channel = NULL;
		}
	} else {
		SPDK_CU_ASSERT_FATAL(ch == (void *)1);
	}
}

struct spdk_io_channel *
_ut_spdk_get_io_channel(void *io_device)
{
	if (g_io_channel && g_io_channel->dev) {
		if (g_io_channel->dev->io_device == io_device) {
			g_io_channel->ref++;
			return g_io_channel;
		}
	}
	return NULL;
}

void
spdk_poller_unregister(struct spdk_poller **ppoller)
{
}

struct spdk_poller *
spdk_poller_register(spdk_poller_fn fn,
		     void *arg,
		     uint64_t period_microseconds)
{
	return (void *)1;
}

void
_ut_spdk_io_device_unregister(void *io_device, spdk_io_device_unregister_cb unregister_cb)
{
	unregister_cb(io_device);
}

/* char * */
/* spdk_sprintf_alloc(const char *format, ...) */
/* { */
/* 	return strdup(format); */
/* } */

void
_ut_spdk_io_device_register(void *io_device, spdk_io_channel_create_cb create_cb,
			    spdk_io_channel_destroy_cb destroy_cb, uint32_t ctx_size,
			    const char *name)
{
}

int
spdk_json_write_name(struct spdk_json_write_ctx *w, const char *name)
{
	return 0;
}

int spdk_json_write_named_int64(struct spdk_json_write_ctx *w, const char *name, int64_t val)
{
	return 0;
}

int spdk_json_write_named_uint64(struct spdk_json_write_ctx *w, const char *name, uint64_t val)
{
	return 0;
}

int spdk_json_write_named_uint32(struct spdk_json_write_ctx *w, const char *name, uint32_t val)
{
	struct rpc_construct_redirector_bdev *req = rpc_req;
	if (strcmp(name, "strip_size_kb") == 0) {
		SPDK_CU_ASSERT_FATAL(val != val);
		/* SPDK_CU_ASSERT_FATAL(req->strip_size_kb == val); */
	} else if (strcmp(name, "blocklen_shift") == 0) {
		SPDK_CU_ASSERT_FATAL(spdk_u32log2(g_block_len) == val);
	} else if (strcmp(name, "num_default_targets") == 0) {
		SPDK_CU_ASSERT_FATAL(req->default_targets.num_default_targets == val);
		/* } else if (strcmp(name, "state") == 0) { */
		/* SPDK_CU_ASSERT_FATAL(val == REDIRECTOR_BDEV_STATE_ONLINE); */
	} else if (strcmp(name, "destruct_called") == 0) {
		SPDK_CU_ASSERT_FATAL(val == 0);
	} else if (strcmp(name, "num_default_targets_discovered") == 0) {
		SPDK_CU_ASSERT_FATAL(req->default_targets.num_default_targets == val);
	}
	return 0;
}

int spdk_json_write_uint32(struct spdk_json_write_ctx *w, uint32_t val)
{
	return 0;
}

int spdk_json_write_named_bool(struct spdk_json_write_ctx *w, const char *name, const bool val)
{
	return 0;
}

int spdk_json_write_named_string(struct spdk_json_write_ctx *w, const char *name, const char *val)
{
	return 0;
}

int
spdk_json_write_object_begin(struct spdk_json_write_ctx *w)
{
	return 0;
}

int
spdk_json_write_named_object_begin(struct spdk_json_write_ctx *w, const char *name)
{
	return 0;
}

int
spdk_json_write_named_array_begin(struct spdk_json_write_ctx *w, const char *name)
{
	return 0;
}

int
spdk_json_write_array_end(struct spdk_json_write_ctx *w)
{
	return 0;
}

int
spdk_json_write_object_end(struct spdk_json_write_ctx *w)
{
	return 0;
}

int
spdk_json_write_bool(struct spdk_json_write_ctx *w, bool val)
{
	return 0;
}

int spdk_json_write_null(struct spdk_json_write_ctx *w)
{
	return 0;
}

int
spdk_reactors_init(void)
{
	return 0;
}

char *
spdk_json_strdup(const struct spdk_json_val *val)
{
	size_t len;
	char *s;

	if (val->type != SPDK_JSON_VAL_STRING && val->type != SPDK_JSON_VAL_NAME) {
		return NULL;
	}

	len = val->len;

	if (memchr(val->start, '\0', len)) {
		/* String contains embedded NUL, so it is not a valid C string. */
		return NULL;
	}

	s = malloc(len + 1);
	if (s == NULL) {
		return s;
	}

	memcpy(s, val->start, len);
	s[len] = '\0';

	return s;
}

int
_ut_spdk_thread_lib_init(spdk_new_thread_fn new_thread_fn, size_t ctx_sz)
{
	return 0;
}

struct spdk_mempool *
spdk_mempool_create(const char *name, size_t count,
		    size_t ele_size, size_t cache_size, int socket_id)
{
	return NULL;
}

void
spdk_mempool_free(struct spdk_mempool *mp)
{
}

void *
spdk_mempool_get(struct spdk_mempool *mp)
{
	return NULL;
}

int
spdk_mempool_get_bulk(struct spdk_mempool *mp, void **ele_arr, size_t count)
{
	return 0;
}

void
spdk_mempool_put(struct spdk_mempool *mp, void *ele)
{
}

void
spdk_mempool_put_bulk(struct spdk_mempool *mp, void **ele_arr, size_t count)
{
}

void
spdk_ring_free(struct spdk_ring *ring)
{
}

size_t
spdk_ring_count(struct spdk_ring *ring)
{
	return 0;
}

size_t
spdk_ring_enqueue(struct spdk_ring *ring, void **objs, size_t count, size_t *free_space)
{
	return count;
}

size_t
spdk_ring_dequeue(struct spdk_ring *ring, void **objs, size_t count)
{
	return 0;
}

struct spdk_io_channel *
spdk_bdev_get_io_channel(struct spdk_bdev_desc *desc)
{
	return (void *)1;
}

void
_ut_spdk_for_each_thread(spdk_msg_fn fn, void *ctx, spdk_msg_fn cpl)
{
	fn(ctx);
	cpl(ctx);
}

struct spdk_io_channel_iter {
	void *io_device;
	struct io_device *dev;
	spdk_channel_msg fn;
	int status;
	void *ctx;
	struct spdk_io_channel *ch;

	struct spdk_thread *cur_thread;

	struct spdk_thread *orig_thread;
	spdk_channel_for_each_cpl cpl;
};

void
_ut_spdk_for_each_channel(void *io_device, spdk_channel_msg fn, void *ctx,
			  spdk_channel_for_each_cpl cpl)
{
	struct spdk_io_channel_iter ch_iter = {0};

	ch_iter.io_device = io_device;
	ch_iter.dev = io_device;
	ch_iter.fn = fn;
	ch_iter.ctx = ctx;
	ch_iter.cpl = cpl;
	if (g_io_channel && g_io_channel->dev == io_device) {
		ch_iter.ch = g_io_channel;
		fn(&ch_iter);
	}

	cpl(&ch_iter, 0);
}

uint64_t spdk_get_ticks(void)
{
	return 0;
}

uint64_t spdk_get_ticks_hz(void)
{
	return 0;
}

struct spdk_ring *
spdk_ring_create(enum spdk_ring_type type, size_t count, int socket_id)
{
	return NULL;
}

struct spdk_thread *
_ut_spdk_get_thread(void)
{
	return NULL;
}

int
_ut_spdk_thread_send_msg(const struct spdk_thread *thread, spdk_msg_fn fn, void *ctx)
{
	fn(ctx);
	return 0;
}

uint32_t
spdk_env_get_current_core(void)
{
	return 0;
}

void
spdk_bdev_free_io(struct spdk_bdev_io *bdev_io)
{
	if (bdev_io) {
		free(bdev_io);
	}
}

/* It will cache split IOs for verification */
int
spdk_bdev_readv_blocks(struct spdk_bdev_desc *desc, struct spdk_io_channel *ch,
		       struct iovec *iov, int iovcnt,
		       uint64_t offset_blocks, uint64_t num_blocks,
		       spdk_bdev_io_completion_cb cb, void *cb_arg)
{
	struct io_output *p = &g_io_output[g_io_output_index];
	struct spdk_bdev_io *child_io;

	if (g_ignore_io_output) {
		return 0;
	}

	SPDK_CU_ASSERT_FATAL(g_io_output_index <= (g_max_io_size / g_strip_size) + 1);
	if (g_bdev_io_submit_status == 0) {
		p->desc = desc;
		p->ch = ch;
		p->offset_blocks = offset_blocks;
		p->num_blocks = num_blocks;
		p->cb = cb;
		p->cb_arg = cb_arg;
		p->iotype = SPDK_BDEV_IO_TYPE_READ;
		g_io_output_index++;
		child_io = calloc(1, sizeof(struct spdk_bdev_io));
		SPDK_CU_ASSERT_FATAL(child_io != NULL);
		cb(child_io, g_child_io_status_flag, cb_arg);
	}

	return g_bdev_io_submit_status;
}

void
spdk_bdev_module_release_bdev(struct spdk_bdev *bdev)
{
	SPDK_CU_ASSERT_FATAL(bdev->internal.claim_module != NULL);
	bdev->internal.claim_module = NULL;
}

void
spdk_bdev_module_examine_done(struct spdk_bdev_module *module)
{
}

struct spdk_conf_section *
spdk_conf_find_section(struct spdk_conf *cp, const char *name)
{
	if (name == NULL || name[0] == '\0') {
		return NULL;
	}

	if (g_config_level_create && (0 == strcmp(name, "REDIRECTOR"))) {
		return (void *) 0x1;
	}
	return NULL;
}

struct spdk_conf_section *
spdk_conf_first_section(struct spdk_conf *cp)
{
	if (g_config_level_create) {
		return (void *) 0x1;
	}

	return NULL;
}

bool
spdk_conf_section_match_prefix(const struct spdk_conf_section *sp, const char *name_prefix)
{
	if (g_config_level_create) {
		return true;
	}

	return false;
}

char *
spdk_conf_section_get_val(struct spdk_conf_section *sp, const char *key)
{
	struct rpc_construct_redirector_bdev  *req = rpc_req;

	if (g_config_level_create && sp == (void *) 0x1) {
		if (strcmp(key, "Name") == 0) {
			return req->name;
		}
	}

	return NULL;
}

int
spdk_conf_section_get_intval(struct spdk_conf_section *sp, const char *key)
{
	return 0;
}

struct spdk_conf_section *
spdk_conf_next_section(struct spdk_conf_section *sp)
{
	return NULL;
}

char *
spdk_conf_section_get_nmval(struct spdk_conf_section *sp, const char *key, int idx1, int idx2)
{
	struct rpc_construct_redirector_bdev  *req = rpc_req;

	if (g_config_level_create && sp == (void *) 0x1) {
		if (strcmp(key, "RE") == 0) {
			if (idx2 >= g_max_base_drives) {
				return NULL;
			}
			return req->default_targets.default_target_names[idx2];
		}
	}

	return NULL;
}

char *
spdk_conf_section_get_nval(struct spdk_conf_section *sp, const char *key, int idx)
{
	return spdk_conf_section_get_nmval(sp, key, idx, 0);
}

void
spdk_bdev_close(struct spdk_bdev_desc *desc)
{
}

int
spdk_bdev_module_claim_bdev(struct spdk_bdev *bdev, struct spdk_bdev_desc *desc,
			    struct spdk_bdev_module *module)
{
	if (bdev->internal.claim_module != NULL) {
		return -1;
	}
	bdev->internal.claim_module = module;
	return 0;
}

int
spdk_bdev_register(struct spdk_bdev *bdev)
{
	TAILQ_INSERT_TAIL(&g_bdev_list, bdev, internal.link);
	return 0;
}

uint32_t
spdk_env_get_last_core(void)
{
	return 0;
}

int
spdk_json_decode_string(const struct spdk_json_val *val, void *out)
{
	return 0;
}

int
spdk_json_decode_bool(const struct spdk_json_val *val, void *out)
{
	return 0;
}

int
spdk_json_decode_uint16(const struct spdk_json_val *val, void *out)
{
	return 0;
}

int
spdk_json_decode_uint64(const struct spdk_json_val *val, void *out)
{
	return 0;
}

int
spdk_json_decode_object(const struct spdk_json_val *values,
			const struct spdk_json_object_decoder *decoders, size_t num_decoders, void *out)
{
	struct rpc_construct_redirector_bdev *req, *_out;
	size_t i;

	if (g_json_decode_obj_err) {
		return -1;
	} else if (g_json_decode_obj_construct) {
		req = rpc_req;
		_out = out;

		_out->name = strdup(req->name);
		spdk_uuid_copy(&_out->uuid, &req->uuid);
		SPDK_CU_ASSERT_FATAL(_out->name != NULL);
		_out->size_configured = req->size_configured;
		_out->size_config.blocklen = req->size_config.blocklen;
		_out->size_config.blockcnt = req->size_config.blockcnt;
		_out->size_config.required_alignment = req->size_config.required_alignment;
		_out->size_config.optimal_io_boundary = req->size_config.optimal_io_boundary;
		_out->default_targets.num_default_targets = req->default_targets.num_default_targets;
		for (i = 0; i < req->default_targets.num_default_targets; i++) {
			_out->default_targets.default_target_names[i] = strdup(
						req->default_targets.default_target_names[i]);
			SPDK_CU_ASSERT_FATAL(_out->default_targets.default_target_names[i]);
		}
	} else {
		memcpy(out, rpc_req, rpc_req_size);
	}

	return 0;
}

struct spdk_json_write_ctx *
spdk_jsonrpc_begin_result(struct spdk_jsonrpc_request *request)
{
	if (g_json_beg_res_ret_err) {
		return NULL;
	} else {
		return (void *)1;
	}
}

int
spdk_json_write_array_begin(struct spdk_json_write_ctx *w)
{
	return 0;
}

int
spdk_json_write_string(struct spdk_json_write_ctx *w, const char *val)
{
	if (g_test_multi_redirectors) {
		g_get_redirectors_output[g_get_redirectors_count] = strdup(val);
		SPDK_CU_ASSERT_FATAL(g_get_redirectors_output[g_get_redirectors_count] != NULL);
		g_get_redirectors_count++;
	}

	return 0;
}

ssize_t
spdk_json_parse(void *json, size_t size, struct spdk_json_val *values, size_t num_values,
		void **end, uint32_t flags)
{
	return 0;
}

void
spdk_jsonrpc_send_error_response(struct spdk_jsonrpc_request *request,
				 int error_code, const char *msg)
{
	g_rpc_err = 1;
}

void
spdk_jsonrpc_send_error_response_fmt(struct spdk_jsonrpc_request *request,
				     int error_code, const char *fmt, ...)
{
	g_rpc_err = 1;
}

void
spdk_jsonrpc_end_result(struct spdk_jsonrpc_request *request, struct spdk_json_write_ctx *w)
{
}

const char *
spdk_bdev_get_name(const struct spdk_bdev *bdev)
{
	return bdev->name;
}

struct spdk_bdev *
spdk_bdev_get_by_name(const char *bdev_name)
{
	struct spdk_bdev *bdev;

	if (!TAILQ_EMPTY(&g_bdev_list)) {
		TAILQ_FOREACH(bdev, &g_bdev_list, internal.link) {
			if (strcmp(bdev_name, bdev->name) == 0) {
				return bdev;
			}
		}
	}

	return NULL;
}

size_t
spdk_bdev_get_buf_align(const struct spdk_bdev *bdev)
{
	return 1 << bdev->required_alignment;
}

const char *
spdk_strerror(int errnum)
{
	return NULL;
}

int
spdk_json_decode_array(const struct spdk_json_val *values, spdk_json_decode_fn decode_func,
		       void *out, size_t max_size, size_t *out_size, size_t stride)
{
	return 0;
}

void
spdk_rpc_register_method(const char *method, spdk_rpc_method_handler func, uint32_t state_mask)
{
}

int
spdk_json_decode_uint32(const struct spdk_json_val *val, void *out)
{
	return 0;
}


void
spdk_bdev_module_list_add(struct spdk_bdev_module *bdev_module)
{
}

static void
bdev_io_cleanup(struct spdk_bdev_io *bdev_io)
{
	if (bdev_io->u.bdev.iovs) {
		if (bdev_io->u.bdev.iovs->iov_base) {
			free(bdev_io->u.bdev.iovs->iov_base);
			bdev_io->u.bdev.iovs->iov_base = NULL;
		}
		free(bdev_io->u.bdev.iovs);
		bdev_io->u.bdev.iovs = NULL;
	}
}

static void
bdev_io_initialize(struct spdk_bdev_io *bdev_io, struct spdk_bdev *bdev,
		   uint64_t lba, uint64_t blocks, int16_t iotype)
{
	bdev_io->bdev = bdev;
	bdev_io->u.bdev.offset_blocks = lba;
	bdev_io->u.bdev.num_blocks = blocks;
	bdev_io->type = iotype;

	if (bdev_io->type == SPDK_BDEV_IO_TYPE_UNMAP || bdev_io->type == SPDK_BDEV_IO_TYPE_FLUSH) {
		return;
	}

	bdev_io->u.bdev.iovcnt = 1;
	bdev_io->u.bdev.iovs = calloc(1, sizeof(struct iovec));
	SPDK_CU_ASSERT_FATAL(bdev_io->u.bdev.iovs != NULL);
	bdev_io->u.bdev.iovs->iov_base = calloc(1, bdev_io->u.bdev.num_blocks * g_block_len);
	SPDK_CU_ASSERT_FATAL(bdev_io->u.bdev.iovs->iov_base != NULL);
	bdev_io->u.bdev.iovs->iov_len = bdev_io->u.bdev.num_blocks * g_block_len;
	bdev_io->u.bdev.iovs = bdev_io->u.bdev.iovs;
}

static void
verify_reset_io(struct spdk_bdev_io *bdev_io, uint8_t num_base_drives,
		struct redirector_bdev_io_channel *ch_ctx, struct redirector_bdev *redirector_bdev,
		uint32_t io_status)
{
	uint32_t index = 0;

	SPDK_CU_ASSERT_FATAL(redirector_bdev != NULL);
	SPDK_CU_ASSERT_FATAL(num_base_drives != 0);
	SPDK_CU_ASSERT_FATAL(io_status != INVALID_IO_SUBMIT);

	SPDK_CU_ASSERT_FATAL(g_io_output_index == num_base_drives);
	for (index = 0; index < g_io_output_index; index++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[index].ch == g_io_output[index].ch);
		SPDK_CU_ASSERT_FATAL(redirector_bdev->targets[index].desc == g_io_output[index].desc);
		SPDK_CU_ASSERT_FATAL(bdev_io->type == g_io_output[index].iotype);
	}
	SPDK_CU_ASSERT_FATAL(g_io_comp_status == io_status);
}

static void
verify_io(struct spdk_bdev_io *bdev_io, uint8_t num_base_drives,
	  struct redirector_bdev_io_channel *ch_ctx, struct redirector_bdev *redirector_bdev,
	  uint32_t io_status)
{
	uint32_t strip_shift = spdk_u32log2(g_strip_size);
	uint64_t start_strip = bdev_io->u.bdev.offset_blocks >> strip_shift;
	uint64_t end_strip = (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1) >>
			     strip_shift;
	uint32_t splits_reqd = (end_strip - start_strip + 1);
	uint32_t strip;
	uint64_t pd_strip;
	uint64_t pd_idx;
	uint32_t offset_in_strip;
	uint64_t pd_lba;
	uint64_t pd_blocks;
	uint32_t index = 0;
	uint8_t *buf = bdev_io->u.bdev.iovs->iov_base;

	if (io_status == INVALID_IO_SUBMIT) {
		SPDK_CU_ASSERT_FATAL(g_io_comp_status == false);
		return;
	}
	SPDK_CU_ASSERT_FATAL(redirector_bdev != NULL);
	SPDK_CU_ASSERT_FATAL(num_base_drives != 0);

	SPDK_CU_ASSERT_FATAL(splits_reqd == g_io_output_index);
	for (strip = start_strip; strip <= end_strip; strip++, index++) {
		pd_strip = strip / num_base_drives;
		pd_idx = strip % num_base_drives;
		if (strip == start_strip) {
			offset_in_strip = bdev_io->u.bdev.offset_blocks & (g_strip_size - 1);
			pd_lba = (pd_strip << strip_shift) + offset_in_strip;
			if (strip == end_strip) {
				pd_blocks = bdev_io->u.bdev.num_blocks;
			} else {
				pd_blocks = g_strip_size - offset_in_strip;
			}
		} else if (strip == end_strip) {
			pd_lba = pd_strip << strip_shift;
			pd_blocks = ((bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1) &
				     (g_strip_size - 1)) + 1;
		} else {
			/* pd_lba = pd_strip << redirector_bdev->strip_size_shift; */
			/* pd_blocks = redirector_bdev->strip_size; */
		}
		SPDK_CU_ASSERT_FATAL(pd_lba == g_io_output[index].offset_blocks);
		SPDK_CU_ASSERT_FATAL(pd_blocks == g_io_output[index].num_blocks);
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[pd_idx].ch == g_io_output[index].ch);
		SPDK_CU_ASSERT_FATAL(redirector_bdev->targets[pd_idx].desc == g_io_output[index].desc);
		SPDK_CU_ASSERT_FATAL(bdev_io->type == g_io_output[index].iotype);
		buf += (pd_blocks << spdk_u32log2(g_block_len));
	}
	SPDK_CU_ASSERT_FATAL(g_io_comp_status == io_status);
}

static void
verify_io_without_payload(struct spdk_bdev_io *bdev_io, uint8_t num_base_drives,
			  struct redirector_bdev_io_channel *ch_ctx, struct redirector_bdev *redirector_bdev,
			  uint32_t io_status)
{
	uint32_t strip_shift = spdk_u32log2(g_strip_size);
	uint64_t start_offset_in_strip = bdev_io->u.bdev.offset_blocks % g_strip_size;
	uint64_t end_offset_in_strip = (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1) %
				       g_strip_size;
	uint64_t start_strip = bdev_io->u.bdev.offset_blocks >> strip_shift;
	uint64_t end_strip = (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1) >>
			     strip_shift;
	uint32_t n_disks_involved;
	uint64_t start_strip_disk_idx;
	uint64_t end_strip_disk_idx;
	uint64_t nblocks_in_start_disk;
	uint64_t offset_in_start_disk;
	uint32_t disk_idx;
	uint64_t base_io_idx;
	uint64_t sum_nblocks = 0;

	if (io_status == INVALID_IO_SUBMIT) {
		SPDK_CU_ASSERT_FATAL(g_io_comp_status == false);
		return;
	}
	SPDK_CU_ASSERT_FATAL(redirector_bdev != NULL);
	SPDK_CU_ASSERT_FATAL(num_base_drives != 0);
	SPDK_CU_ASSERT_FATAL(bdev_io->type != SPDK_BDEV_IO_TYPE_READ);
	SPDK_CU_ASSERT_FATAL(bdev_io->type != SPDK_BDEV_IO_TYPE_WRITE);

	n_disks_involved = spdk_min(end_strip - start_strip + 1, num_base_drives);
	SPDK_CU_ASSERT_FATAL(n_disks_involved == g_io_output_index);

	start_strip_disk_idx = start_strip % num_base_drives;
	end_strip_disk_idx = end_strip % num_base_drives;
	offset_in_start_disk = g_io_output[0].offset_blocks;
	nblocks_in_start_disk = g_io_output[0].num_blocks;

	for (base_io_idx = 0, disk_idx = start_strip_disk_idx; base_io_idx < n_disks_involved;
	     base_io_idx++, disk_idx++) {
		uint64_t start_offset_in_disk;
		uint64_t end_offset_in_disk;

		/* round disk_idx */
		if (disk_idx >= num_base_drives) {
			disk_idx %= num_base_drives;
		}

		/* start_offset_in_disk aligned in strip check:
		 * The first base io has a same start_offset_in_strip with the whole redirector io.
		 * Other base io should have aligned start_offset_in_strip which is 0.
		 */
		start_offset_in_disk = g_io_output[base_io_idx].offset_blocks;
		if (base_io_idx == 0) {
			SPDK_CU_ASSERT_FATAL(start_offset_in_disk % g_strip_size == start_offset_in_strip);
		} else {
			SPDK_CU_ASSERT_FATAL(start_offset_in_disk % g_strip_size == 0);
		}

		/* end_offset_in_disk aligned in strip check:
		 * Base io on disk at which end_strip is located, has a same end_offset_in_strip with the whole redirector io.
		 * Other base io should have aligned end_offset_in_strip.
		 */
		end_offset_in_disk = g_io_output[base_io_idx].offset_blocks +
				     g_io_output[base_io_idx].num_blocks - 1;
		if (disk_idx == end_strip_disk_idx) {
			SPDK_CU_ASSERT_FATAL(end_offset_in_disk % g_strip_size == end_offset_in_strip);
		} else {
			SPDK_CU_ASSERT_FATAL(end_offset_in_disk % g_strip_size == g_strip_size - 1);
		}

		/* start_offset_in_disk compared with start_disk.
		 * 1. For disk_idx which is larger than start_strip_disk_idx: Its start_offset_in_disk mustn't be
		 * larger than the start offset of start_offset_in_disk; And the gap must be less than strip size.
		 * 2. For disk_idx which is less than start_strip_disk_idx, Its start_offset_in_disk must be
		 * larger than the start offset of start_offset_in_disk; And the gap mustn't be less than strip size.
		 */
		if (disk_idx > start_strip_disk_idx) {
			SPDK_CU_ASSERT_FATAL(start_offset_in_disk <= offset_in_start_disk);
			SPDK_CU_ASSERT_FATAL(offset_in_start_disk - start_offset_in_disk < g_strip_size);
		} else if (disk_idx < start_strip_disk_idx) {
			SPDK_CU_ASSERT_FATAL(start_offset_in_disk > offset_in_start_disk);
			SPDK_CU_ASSERT_FATAL(g_io_output[base_io_idx].offset_blocks - offset_in_start_disk <= g_strip_size);
		}

		/* nblocks compared with start_disk:
		 * The gap between them must be within a strip size.
		 */
		if (g_io_output[base_io_idx].num_blocks <= nblocks_in_start_disk) {
			SPDK_CU_ASSERT_FATAL(nblocks_in_start_disk - g_io_output[base_io_idx].num_blocks <= g_strip_size);
		} else {
			SPDK_CU_ASSERT_FATAL(g_io_output[base_io_idx].num_blocks - nblocks_in_start_disk < g_strip_size);
		}

		sum_nblocks += g_io_output[base_io_idx].num_blocks;

		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[disk_idx].ch == g_io_output[base_io_idx].ch);
		SPDK_CU_ASSERT_FATAL(redirector_bdev->targets[disk_idx].desc == g_io_output[base_io_idx].desc);
		SPDK_CU_ASSERT_FATAL(bdev_io->type == g_io_output[base_io_idx].iotype);
	}

	/* Sum of each nblocks should be same with redirector bdev_io */
	SPDK_CU_ASSERT_FATAL(bdev_io->u.bdev.num_blocks == sum_nblocks);

	SPDK_CU_ASSERT_FATAL(g_io_comp_status == io_status);
}

static void
verify_redirector_config_present(const char *name, bool presence)
{
	struct redirector_config *redirector_cfg;
	bool cfg_found;

	cfg_found = false;

	TAILQ_FOREACH(redirector_cfg, &g_redirector_config, config_link) {
		if (redirector_cfg->redirector_name != NULL) {
			if (strcmp(name, redirector_cfg->redirector_name) == 0) {
				cfg_found = true;
				break;
			}
		}
	}

	if (presence == true) {
		SPDK_CU_ASSERT_FATAL(cfg_found == true);
	} else {
		SPDK_CU_ASSERT_FATAL(cfg_found == false);
	}
}

static void
verify_redirector_bdev_present(const char *name, bool presence)
{
	struct redirector_bdev *pbdev;
	bool   pbdev_found;

	pbdev_found = false;
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, name) == 0) {
			pbdev_found = true;
			break;
		}
	}
	if (presence == true) {
		SPDK_CU_ASSERT_FATAL(pbdev_found == true);
	} else {
		SPDK_CU_ASSERT_FATAL(pbdev_found == false);
	}
}

static void
verify_redirector_config(struct rpc_construct_redirector_bdev *r, bool presence)
{
	struct redirector_config *redirector_cfg = NULL;
	GSequenceIter *target_iter;
	struct redirector_target *iter_target;
	int i;
	int val;

	TAILQ_FOREACH(redirector_cfg, &g_redirector_config, config_link) {
		if (strcmp(r->name, redirector_cfg->redirector_name) == 0) {
			if (presence == false) {
				break;
			}
			/* SPDK_CU_ASSERT_FATAL(redirector_cfg->bdev != NULL); */
			/* SPDK_CU_ASSERT_FATAL(redirector_cfg->strip_size == r->strip_size_kb); */
			SPDK_CU_ASSERT_FATAL((size_t)g_sequence_get_length(redirector_cfg->targets) ==
					     r->default_targets.num_default_targets);
			/* SPDK_CU_ASSERT_FATAL(redirector_cfg->redirector_level == r->redirector_level); */
			i = 0;
			target_iter = g_sequence_get_begin_iter(redirector_cfg->targets);
			while (!g_sequence_iter_is_end(target_iter)) {
				iter_target = (struct redirector_target *)g_sequence_get(target_iter);
				val = strcmp(iter_target->name, r->default_targets.default_target_names[i++]);
				SPDK_CU_ASSERT_FATAL(val == 0);
				target_iter = g_sequence_iter_next(target_iter);
			}
			break;
		}
	}

	if (presence == true) {
		SPDK_CU_ASSERT_FATAL(redirector_cfg != NULL);
	} else {
		SPDK_CU_ASSERT_FATAL(redirector_cfg == NULL);
	}
}

static void
verify_redirector_bdev(struct rpc_construct_redirector_bdev *r, bool presence)
{
	struct redirector_bdev *pbdev;
	uint32_t i;
	struct spdk_bdev *bdev = NULL;
	bool   pbdev_found;
	uint64_t min_blockcnt = 0xFFFFFFFFFFFFFFFF;

	pbdev_found = false;
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, r->name) == 0) {
			pbdev_found = true;
			if (presence == false) {
				break;
			}
			/* SPDK_CU_ASSERT_FATAL(pbdev->config->redirector_bdev == pbdev); */
			SPDK_CU_ASSERT_FATAL(pbdev->targets != NULL);
			/* SPDK_CU_ASSERT_FATAL(pbdev->strip_size == ((r->strip_size_kb * 1024) / g_block_len)); */
			/* SPDK_CU_ASSERT_FATAL(pbdev->strip_size_shift == spdk_u32log2(((r->strip_size_kb * 1024) / g_block_len))); */
			/* SPDK_CU_ASSERT_FATAL(pbdev->blocklen_shift == spdk_u32log2(g_block_len)); */
			/* SPDK_CU_ASSERT_FATAL(pbdev->state == redirector_state); */
			SPDK_CU_ASSERT_FATAL(pbdev->num_rd_targets == r->default_targets.num_default_targets);
			/* SPDK_CU_ASSERT_FATAL(pbdev->num_rd_targets_discovered == r->default_targets.num_default_targets); */
			/* SPDK_CU_ASSERT_FATAL(pbdev->redirector_level == r->redirector_level); */
			/* SPDK_CU_ASSERT_FATAL(pbdev->destruct_called == false); */
			for (i = 0; i < pbdev->num_rd_targets; i++) {
				if (pbdev->targets[i].bdev) {
					bdev = spdk_bdev_get_by_name(pbdev->targets[i].bdev->name);
					SPDK_CU_ASSERT_FATAL(bdev != NULL);
					/* SPDK_CU_ASSERT_FATAL(pbdev->targets[i].bdev->remove_scheduled == false); */
				} else {
					SPDK_CU_ASSERT_FATAL(0);
				}

				if (bdev && bdev->blockcnt < min_blockcnt) {
					min_blockcnt = bdev->blockcnt;
				}
			}
			/* SPDK_CU_ASSERT_FATAL((((min_blockcnt / (r->strip_size_kb * 1024 / g_block_len)) * (r->strip_size_kb * 1024 / */
			/* g_block_len)) * r->default_targets.num_default_targets) == pbdev->bdev.blockcnt); */
			SPDK_CU_ASSERT_FATAL(strcmp(pbdev->redirector_bdev.product_name, "redirector") == 0);
			/* SPDK_CU_ASSERT_FATAL(pbdev->bdev.write_cache == 0); */
			SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.blocklen == g_block_len);
			if (pbdev->num_rd_targets > 0) {
				/* SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.optimal_io_boundary == pbdev->strip_size); */
				SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.split_on_optimal_io_boundary == true);
			} else {
				SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.optimal_io_boundary == 0);
				SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.split_on_optimal_io_boundary == false);
			}
			SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.ctxt == pbdev);
			SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.fn_table == &vbdev_redirector_fn_table);
			SPDK_CU_ASSERT_FATAL(pbdev->redirector_bdev.module == &redirector_if);
			break;
		}
	}
	if (presence == true) {
		SPDK_CU_ASSERT_FATAL(pbdev_found == true);
	} else {
		SPDK_CU_ASSERT_FATAL(pbdev_found == false);
	}
}

int
spdk_bdev_queue_io_wait(struct spdk_bdev *bdev, struct spdk_io_channel *ch,
			struct spdk_bdev_io_wait_entry *entry)
{
	SPDK_CU_ASSERT_FATAL(bdev == entry->bdev);
	SPDK_CU_ASSERT_FATAL(entry->cb_fn != NULL);
	SPDK_CU_ASSERT_FATAL(entry->cb_arg != NULL);
	TAILQ_INSERT_TAIL(&g_io_waitq, entry, link);
	return 0;
}


static uint32_t
get_num_elts_in_waitq(void)
{
	struct spdk_bdev_io_wait_entry *ele;
	uint32_t count = 0;

	TAILQ_FOREACH(ele, &g_io_waitq, link) {
		count++;
	}

	return count;
}

static void
process_io_waitq(void)
{
	struct spdk_bdev_io_wait_entry *ele;
	struct spdk_bdev_io_wait_entry *next_ele;

	TAILQ_FOREACH_SAFE(ele, &g_io_waitq, link, next_ele) {
		TAILQ_REMOVE(&g_io_waitq, ele, link);
		ele->cb_fn(ele->cb_arg);
	}
}

static void
create_default_targets(uint32_t num_targets, uint32_t bbdev_start_idx)
{
	uint32_t i;
	struct spdk_bdev *default_target;
	char name[16];
	uint16_t num_chars;

	for (i = 0; i < num_targets; i++, bbdev_start_idx++) {
		num_chars = snprintf(name, 16, "%s%02u%s", "Nvme", bbdev_start_idx, "n1");
		name[num_chars] = '\0';
		default_target = calloc(1, sizeof(struct spdk_bdev));
		SPDK_CU_ASSERT_FATAL(default_target != NULL);
		default_target->name = strdup(name);
		SPDK_CU_ASSERT_FATAL(default_target->name != NULL);
		default_target->blocklen = g_block_len;
		default_target->blockcnt = (uint64_t)1024 * 1024 * 1024 * 1024;
		TAILQ_INSERT_TAIL(&g_bdev_list, default_target, internal.link);
	}
}

static const char *default_rd_uuid = "0373a5d7-89c1-436c-8b3d-169e03f94817";

static void
create_test_construct_rd_bdev_2(struct rpc_construct_redirector_bdev *r,
				const char *redirector_name,
				uint32_t bbdev_start_idx, bool create_default_target, uint32_t min_targets)
{
	uint32_t i;
	char name[16];
	uint16_t num_chars;
	uint32_t bbdev_idx = bbdev_start_idx;
	uint32_t num_targets = MAX(g_max_base_drives, min_targets);

	r->name = strdup(redirector_name);
	spdk_uuid_parse(&r->uuid, default_rd_uuid);
	SPDK_CU_ASSERT_FATAL(r->name != NULL);
	/* TODO: Test with configured sizes */
	r->size_configured = false;
	/* r->size_config.blocklen = g_block_len; */
	/* r->size_config.blockcnt = 1024*2; */
	/* r->size_config.required_alignment = r->size_config.blocklen; */
	/* r->size_config.optimal_io_boundary = 1024*1024; */
	r->default_targets.num_default_targets = num_targets;
	for (i = 0; i < num_targets; i++, bbdev_idx++) {
		num_chars = snprintf(name, 16, "%s%02u%s", "Nvme", bbdev_idx, "n1");
		name[num_chars] = '\0';
		r->default_targets.default_target_names[i] = strdup(name);
		SPDK_CU_ASSERT_FATAL(r->default_targets.default_target_names[i] != NULL);
	}
	if (create_default_target == true) {
		create_default_targets(num_targets, bbdev_start_idx);
	}
}

static void
create_test_construct_rd_bdev(struct rpc_construct_redirector_bdev *r, const char *redirector_name,
			      uint32_t bbdev_start_idx,
			      bool create_default_target)
{
	create_test_construct_rd_bdev_2(r, redirector_name, bbdev_start_idx, create_default_target, 0);
}

static void
free_test_req(struct rpc_construct_redirector_bdev *r)
{
	uint8_t i;

	free(r->name);
	for (i = 0; i < r->default_targets.num_default_targets; i++) {
		free(r->default_targets.default_target_names[i]);
	}
}

static void
dump_rule_table(struct redirector_bdev *pbdev)
{
	GSequenceIter *rule_iter;
	struct location_hint *iter_rule;
	int rule_index;

	if (!g_verbose) { return; }
	if (!pbdev) { return; }
	if (!pbdev->locations) { return; }
	rule_iter = g_sequence_get_begin_iter(pbdev->locations);
	rule_index = 0;
	printf("Forwarding rules:\n");
	if (g_sequence_iter_is_end(rule_iter)) {
		printf("EMPTY\n");
	}
	while (!g_sequence_iter_is_end(rule_iter)) {
		iter_rule = (struct location_hint *)g_sequence_get(rule_iter);
		printf("Rule %d: LBA=%"PRIu64", target=%s (#%d)%s%s%s\n",
		       rule_index, iter_rule->extent.start_lba, location_hint_target_name(iter_rule),
		       iter_rule->target_index,
		       iter_rule->default_rule ? " (default)" : "",
		       iter_rule->authoritative ? " (auth)" : "",
		       iter_rule->rule_table ? "" : " (!!RULE_TABLE MISSING!!)");
		rule_iter = g_sequence_iter_next(rule_iter);
		rule_index++;
	}
}

static void
dump_hint_list(struct redirector_config *config)
{
	GSequenceIter *hint_iter;
	struct location_hint *iter_hint;
	int hint_index;

	if (!g_verbose) { return; }
	if (!config) { return; }
	hint_iter = g_sequence_get_begin_iter(config->hints);
	hint_index = 0;
	printf("Location hints:\n");
	if (g_sequence_iter_is_end(hint_iter)) {
		printf("EMPTY\n");
	}
	while (!g_sequence_iter_is_end(hint_iter)) {
		iter_hint = (struct location_hint *)g_sequence_get(hint_iter);
		printf("Hint %d: LBA=%"PRIu64", blocks=%"PRIu64", target=%s (#%d)%s%s%s%s\n",
		       hint_index, iter_hint->extent.start_lba, iter_hint->extent.blocks,
		       location_hint_target_name(iter_hint), iter_hint->target_index,
		       iter_hint->default_rule ? " (default)" : "",
		       iter_hint->authoritative ? " (auth)" : "",
		       iter_hint->persistent ? " (persistent)" : "",
		       iter_hint->rule_table ? " (!!RULE_TABLE!!)" : "");
		hint_iter = g_sequence_iter_next(hint_iter);
		hint_index++;
	}
}

static void
dump_target_list(struct redirector_config *config)
{
	GSequenceIter *target_iter;
	struct redirector_target *iter_target;
	int target_index;

	if (!g_verbose) { return; }
	if (!config) { return; }
	target_iter = g_sequence_get_begin_iter(config->targets);
	target_index = 0;
	printf("Target list:\n");
	if (g_sequence_iter_is_end(target_iter)) {
		printf("EMPTY\n");
	}
	while (!g_sequence_iter_is_end(target_iter)) {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		printf("Target %d: name=%s (#%d)%s%s\n",
		       target_index,
		       iter_target->name, iter_target->target_index,
		       iter_target->required ? " (required)" : "",
		       iter_target->persistent ? " (persistent)" : "");
		target_iter = g_sequence_iter_next(target_iter);
		target_index++;
	}
}

static void
test_construct_redirector(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);

	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	free_test_req(&req);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
test_delete_redirector(void)
{
	struct rpc_construct_redirector_bdev construct_req;
	struct rpc_delete_redirector destroy_req;

	set_globals();
	create_test_construct_rd_bdev(&construct_req, "redirector1", 0, true);
	rpc_req = &construct_req;
	rpc_req_size = sizeof(construct_req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(construct_req.name, false);
	verify_redirector_bdev_present(construct_req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&construct_req, true);
	verify_redirector_bdev(&construct_req, true);
	free_test_req(&construct_req);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static int
add_simple_hint(struct redirector_config *config, const struct location_hint *h)
{
	return redirector_add_hint(config,
				   h->extent.start_lba,
				   h->extent.blocks,
				   h->simple.target_name,
				   h->simple.target_start_lba,
				   NULL,
				   h->persistent,
				   h->authoritative,
				   true);
}

static int
remove_simple_hint(struct redirector_config *config, const struct location_hint *h)
{
	return redirector_remove_hint(config,
				      h->extent.start_lba,
				      h->extent.blocks,
				      h->simple.target_name);
}

static void
test_add_hints(void)
{
	struct rpc_construct_redirector_bdev construct_req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_config *config;
	struct redirector_bdev *pbdev;
	struct location_hint hint1 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0x1000,
			.blocks = 0x8000
		},
		.simple = {
			.target_name = "t1",
			.target_start_lba = 0x1000,
		},
		.persistent = true,
		.authoritative = true
	};
	struct location_hint hint2 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0x80,
			.blocks = 0x80
		},
		.simple = {
			.target_name = "t2",
			.target_start_lba = 0x80,
		},
		.persistent = false,
		.authoritative = false
	};

	struct location_hint hint3 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0x80,
			.blocks = 0x80
		},
		.simple = {
			.target_name = "t3",
			.target_start_lba = 0x80,
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint4_conf = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0,
			.blocks = 0xffff
		},
		.simple = {
			.target_name = "t4",
			.target_start_lba = 0,
		},
		.persistent = true,
		.authoritative = false
	};
	struct location_hint hint4 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0,
			.blocks = 0xfff
		},
		.simple = {
			.target_name = "t1",
			.target_start_lba = 0,
		},
		.persistent = true,
		.authoritative = false
	};
	struct location_hint *sorted_hints[] = {&hint4, &hint2, &hint3, &hint1};
	GSequenceIter *hint_iter;
	gpointer iter_data;
	struct location_hint *iter_hint;
	int hints_length;
	int rc;
	struct redirector_location_hint_data_and_target_compare_opts ignore_target_opts = {
		.ignore_target = true,
		.ignore_flags = false,
		.ignore_target_start_lba = false,
		.ignore_hint_type = false,
		.compare_general_hint_type = true,
		.ignore_hint_source = false,
	};
	struct redirector_location_hint_data_and_target_compare_opts exact_match_opts = {
		.ignore_target = false,
		.ignore_flags = false,
		.ignore_target_start_lba = false,
		.ignore_hint_type = false,
		.compare_general_hint_type = false,
		.ignore_hint_source = false,
	};
	struct redirector_location_hint_data_and_target_compare_opts flags_type_source_opts = {
		.ignore_target = true,
		.ignore_flags = false,
		.ignore_target_start_lba = true,
		.ignore_hint_type = false,
		.compare_general_hint_type = true,
		.ignore_hint_source = false,
	};
	struct redirector_location_hint_data_and_target_compare_opts target_flags_type_source_opts = {
		.ignore_target = false,
		.ignore_flags = false,
		.ignore_target_start_lba = true,
		.ignore_hint_type = false,
		.compare_general_hint_type = true,
		.ignore_hint_source = false,
	};
	struct redirector_location_hint_data_and_target_compare_opts target_flags_offset_type_source_opts
		= {
		.ignore_target = false,
		.ignore_flags = false,
		.ignore_target_start_lba = false,
		.ignore_hint_type = false,
		.compare_general_hint_type = true,
		.ignore_hint_source = false,
	};

	SPDK_CU_ASSERT_FATAL(0 == location_hint_extent_compare(&hint2, &hint3));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(&hint2, &hint3, &ignore_target_opts));
	SPDK_CU_ASSERT_FATAL(-1 == location_hint_equal(&hint2, &hint3, &exact_match_opts));

	set_globals();
	create_test_construct_rd_bdev_2(&construct_req, "redirector1", 0, true, 4);
	rpc_req = &construct_req;
	rpc_req_size = sizeof(construct_req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(construct_req.name, false);
	verify_redirector_bdev_present(construct_req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&construct_req, true);
	verify_redirector_bdev(&construct_req, true);

	/* Use target names for hints */
	hint1.simple.target_name = strdup(construct_req.default_targets.default_target_names[0]);
	hint2.simple.target_name = strdup(construct_req.default_targets.default_target_names[1]);
	hint3.simple.target_name = strdup(construct_req.default_targets.default_target_names[2]);
	hint4.simple.target_name = strdup(construct_req.default_targets.default_target_names[3]);
	free_test_req(&construct_req);

	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, construct_req.name) == 0) {
			break;
		}
	}

	config = vbdev_redirector_find_config("redirector1");
	SPDK_CU_ASSERT_FATAL(config);

	dump_hint_list(config);
	dump_target_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint1);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint2);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint3);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	/* conflicts with auth */
	rc = add_simple_hint(config, &hint4_conf);
	CU_ASSERT(rc == -EINVAL);

	rc = add_simple_hint(config, &hint4);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	hints_length = g_sequence_get_length(config->hints);
	SPDK_CU_ASSERT_FATAL(4 == hints_length);

	hint_iter = g_sequence_get_begin_iter(config->hints);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;
	hint_iter = g_sequence_iter_next(hint_iter);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;
	hint_iter = g_sequence_iter_next(hint_iter);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;
	hint_iter = g_sequence_iter_next(hint_iter);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;

	hint_iter = g_sequence_get_begin_iter(config->hints);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;
	SPDK_CU_ASSERT_FATAL(0 == location_hint_extent_compare(sorted_hints[0], iter_hint));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[0], iter_hint, &flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[0], iter_hint,
			     &target_flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[0], iter_hint,
			     &target_flags_offset_type_source_opts));

	hint_iter = g_sequence_iter_next(hint_iter);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;
	SPDK_CU_ASSERT_FATAL(0 == location_hint_extent_compare(sorted_hints[1], iter_hint));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[1], iter_hint, &flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[1], iter_hint,
			     &target_flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[1], iter_hint,
			     &target_flags_offset_type_source_opts));

	hint_iter = g_sequence_iter_next(hint_iter);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;
	SPDK_CU_ASSERT_FATAL(0 == location_hint_extent_compare(sorted_hints[2], iter_hint));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[2], iter_hint, &flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[2], iter_hint,
			     &target_flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[2], iter_hint,
			     &target_flags_offset_type_source_opts));

	hint_iter = g_sequence_iter_next(hint_iter);
	iter_data = g_sequence_get(hint_iter);
	SPDK_CU_ASSERT_FATAL(iter_data);
	iter_hint = (struct location_hint *)iter_data;
	SPDK_CU_ASSERT_FATAL(0 == location_hint_extent_compare(sorted_hints[3], iter_hint));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[3], iter_hint, &flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[3], iter_hint,
			     &target_flags_type_source_opts));
	SPDK_CU_ASSERT_FATAL(0 == location_hint_equal(sorted_hints[3], iter_hint,
			     &target_flags_offset_type_source_opts));

	/* There shouldn't be any more */
	hint_iter = g_sequence_iter_next(hint_iter);
	SPDK_CU_ASSERT_FATAL(g_sequence_iter_is_end(hint_iter));

	/* Remove a hint */
	rc = remove_simple_hint(config, &hint2);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);
	int new_hints_length = g_sequence_get_length(config->hints);
	CU_ASSERT(new_hints_length = hints_length - 1);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
ut_sync_cb(void *ctx, int rc)
{
	*(int *)ctx = rc;
}

static int
redirector_remove_target_sync(struct redirector_config *config,
			      char *target_name,
			      bool retain_hints)
{
	int rc;

	redirector_remove_target(config, target_name, retain_hints, false, false, ut_sync_cb, &rc);
	return rc;
}

static void
test_add_remove_targets(void)
{
	struct rpc_construct_redirector_bdev construct_req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_config *config;
	struct redirector_bdev *pbdev;
	GSequenceIter *target_iter;
	struct redirector_target *iter_target;
	unsigned int index;
	int rc;
	int targets_count;
	int new_targets_count;

	set_globals();
	create_test_construct_rd_bdev(&construct_req, "redirector1", 0, true);
	rpc_req = &construct_req;
	rpc_req_size = sizeof(construct_req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(construct_req.name, false);
	verify_redirector_bdev_present(construct_req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&construct_req, true);
	verify_redirector_bdev(&construct_req, true);

	config = vbdev_redirector_find_config("redirector1");
	SPDK_CU_ASSERT_FATAL(config);

	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, construct_req.name) == 0) {
			break;
		}
	}

	/* Verify initial targets match create request */
	target_iter = g_sequence_get_begin_iter(config->targets);
	for (index = 0; index < construct_req.default_targets.num_default_targets; index++) {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		CU_ASSERT(strcmp(construct_req.default_targets.default_target_names[index],
				 iter_target->name) == 0);
		target_iter = g_sequence_iter_next(target_iter);
	}

	targets_count = g_sequence_get_length(config->targets);

	dump_hint_list(config);
	dump_target_list(config);
	dump_rule_table(pbdev);

	/* Add some targets */
	struct rpc_redirector_add_target req = {"redirector1", "AA", false, false, false};
	rc = redirector_add_target(&req);
	dump_hint_list(config);
	dump_target_list(config);
	dump_rule_table(pbdev);

	CU_ASSERT(rc == 0);
	CU_ASSERT(g_sequence_get_length(config->targets) == targets_count + 1);
	target_iter = g_sequence_get_begin_iter(config->targets);
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	CU_ASSERT(strcmp("AA", iter_target->name) == 0);
	targets_count++;

	/* Add of exact dup ignored */
	req = (struct rpc_redirector_add_target) {"redirector1", "AA", false, false, false};
	rc = redirector_add_target(&req);
	CU_ASSERT(rc == 0);
	CU_ASSERT(g_sequence_get_length(config->targets) == targets_count);

	/* Add of dup with different flags fails */
	req = (struct rpc_redirector_add_target) {"redirector1", "AA", true, false, false};
	rc = redirector_add_target(&req);
	CU_ASSERT(rc == -EEXIST);
	CU_ASSERT(g_sequence_get_length(config->targets) == targets_count);
	req = (struct rpc_redirector_add_target) {"redirector1", "AA", false, true, false};
	rc = redirector_add_target(&req);
	CU_ASSERT(rc == -EEXIST);
	CU_ASSERT(g_sequence_get_length(config->targets) == targets_count);

	req = (struct rpc_redirector_add_target) {"redirector1", "ZZ", false, false, false};
	rc = redirector_add_target(&req);
	dump_hint_list(config);
	dump_target_list(config);
	dump_rule_table(pbdev);
	CU_ASSERT(rc == 0);
	CU_ASSERT(g_sequence_get_length(config->targets) == targets_count + 1);
	target_iter = g_sequence_get_end_iter(config->targets);
	target_iter = g_sequence_iter_prev(target_iter);
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	CU_ASSERT(strcmp("ZZ", iter_target->name) == 0);
	targets_count++;

	/* Remove some targets */
	targets_count = g_sequence_get_length(config->targets);
	rc = redirector_remove_target_sync(config, "ZZ", false);
	CU_ASSERT(rc == 0);
	new_targets_count = g_sequence_get_length(config->targets);
	CU_ASSERT(new_targets_count == targets_count - 1);
	rc = redirector_remove_target_sync(config, "AA", false);
	CU_ASSERT(rc == 0);
	new_targets_count = g_sequence_get_length(config->targets);
	CU_ASSERT(new_targets_count == targets_count - 2);

	free_test_req(&construct_req);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
test_select_target(void)
{
	struct rpc_construct_redirector_bdev construct_req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct io_device io_dev = {0};
	struct redirector_bdev_io_channel *rd_ch;
	struct redirector_config *config;
	struct location_hint hint1 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0,
			.blocks = 0
		},
		.simple = {
			.target_name = "t1",
		},
		.persistent = true,
		.authoritative = false
	};
	struct location_hint hint2 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 1,
			.blocks = 1
		},
		.simple = {
			.target_name = "t2",
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint3 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 8,
			.blocks = 1
		},
		.simple = {
			.target_name = "t2",
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint4 = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0,
			.blocks = 0xffff
		},
		.simple = {
			.target_name = "t4",
		},
		.persistent = true,
		.authoritative = false
	};
	int hints_length;
	int rules_length;
	int target_index;
	GSequenceIter *target_iter;
	struct redirector_target *iter_target;
	char *target_name1;
	char *target_name2;
	char *target_name3;
	char *target_name4;
	char *target_name5;
	char *target_name6;
	int rc;
	bool multiple_base_drives = g_max_base_drives > 1;

	set_globals();
	create_test_construct_rd_bdev(&construct_req, "redirector1", 0, true);
	rpc_req = &construct_req;
	rpc_req_size = sizeof(construct_req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(construct_req.name, false);
	verify_redirector_bdev_present(construct_req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&construct_req, true);
	verify_redirector_bdev(&construct_req, true);

	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, construct_req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	hint1.extent.blocks = redirector_max_blocks(pbdev);

	config = vbdev_redirector_find_config("redirector1");
	SPDK_CU_ASSERT_FATAL(config);

	dump_hint_list(config);
	dump_target_list(config);
	dump_rule_table(pbdev);

	ch = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch->dev = &io_dev;
	ch->dev->io_device = pbdev;
	ch->destroy_cb = redirector_bdev_ch_destroy_cb;
	rd_ch = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, rd_ch) == 0);
	g_io_channel = (struct spdk_io_channel *)ch;
	SPDK_CU_ASSERT_FATAL(g_io_channel == spdk_get_io_channel(pbdev));

	/* Verify initial targets match create request */
	target_iter = g_sequence_get_begin_iter(config->targets);
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	target_name1 = strdup(iter_target->name);
	target_iter = g_sequence_iter_next(target_iter);
	if (g_sequence_iter_is_end(target_iter)) {
		target_name2 = strdup(target_name1);
	} else {
		iter_target = (struct redirector_target *)g_sequence_get(target_iter);
		target_name2 = strdup(iter_target->name);
	}

	hint1.simple.target_name = target_name1;
	hint2.simple.target_name = target_name2;
	hint3.simple.target_name = target_name2;

	/* returns 0 when hints table is empty */
	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 1, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0x7F, NULL);
	CU_ASSERT(target_index == 0);

	rc = add_simple_hint(config, &hint1);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint2);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint3);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint4);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	hints_length = g_sequence_get_length(config->hints);
	SPDK_CU_ASSERT_FATAL(4 == hints_length);

	/*
	 * Given the location hints:
	 *
	 * (0, MAX): t1
	 * (1,1): t2
	 * (8,1): t3
	 *
	 * The rule table prodiced should look like:
	 *
	 * 0: t1
	 * 1: t2
	 * 2: t1
	 * 8: t2
	 * 9: t1
	 */

	/* Apply rules to channel by creating a new one */
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	spdk_put_io_channel(ch);
	SPDK_CU_ASSERT_FATAL(g_io_channel == NULL);
	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, rd_ch) == 0);
	g_io_channel = ch;
	SPDK_CU_ASSERT_FATAL(ch == spdk_get_io_channel(pbdev));

	rules_length = g_sequence_get_length(pbdev->applied_rules);
	SPDK_CU_ASSERT_FATAL(5 == rules_length);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 1, NULL);
	CU_ASSERT(target_index == multiple_base_drives ? 1 : 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 2, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 3, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 4, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 5, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 6, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 7, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 8, NULL);
	CU_ASSERT(target_index == multiple_base_drives ? 1 : 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 9, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 10, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0x7F, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0x80, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0xffff, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0x10000, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0x10001, NULL);
	CU_ASSERT(target_index == 0);

	SPDK_CU_ASSERT_FATAL(ch != NULL);
	spdk_put_io_channel(ch);
	SPDK_CU_ASSERT_FATAL(g_io_channel == NULL);

	free_test_req(&construct_req);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	/* Second test case */
	uint8_t saved_max_base_drives = g_max_base_drives;
	g_max_base_drives += 6;
	create_test_construct_rd_bdev(&construct_req, "redirector1", 0, true);
	rpc_req = &construct_req;
	rpc_req_size = sizeof(construct_req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(construct_req.name, false);
	verify_redirector_bdev_present(construct_req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&construct_req, true);
	verify_redirector_bdev(&construct_req, true);

	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, construct_req.name) == 0) {
			break;
		}
	}
	ch->dev->io_device = pbdev;

	/* Apply rules to channel by creating a new one */
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch->dev = &io_dev;
	ch->dev->io_device = pbdev;
	ch->destroy_cb = redirector_bdev_ch_destroy_cb;
	rd_ch = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, rd_ch) == 0);
	g_io_channel = ch;
	SPDK_CU_ASSERT_FATAL(ch == spdk_get_io_channel(pbdev));

	/*
	 * Check for overlap at begin:
	 * ___,___!___,___!___,___!___,___!
	 * 11111111111111111111111111111111
	 * 2222222222222222................
	 * ...............333..............
	 * ................5...............
	 * ................44444444........
	 * ................666666666666....
	 * ....................22..........
	 *
	 * Given the location hints:
	 *
	 * ( 0,MAX): t1 (default)
	 * ( 0, 16): t2
	 * (15,  3): t3
	 * (16,  1): t5
	 * (16,  8): t4
	 * (16, 12): t6
	 * (20,  2): t2
	 *
	 * The rule table produced should look like:
	 *
	 * 0: t2
	 * 15: t3
	 * 16: t5
	 * 17: t3
	 * 18: t4
	 * 20: t2
	 * 22: t4
	 * 24: t6
	 * 29: t1
	 */
	struct location_hint hint1b = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0,
			.blocks = 0
		},
		.simple = {
			.target_name = "t1",
		},
		.persistent = true,
		.authoritative = false
	};
	struct location_hint hint2b = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 0,
			.blocks = 16
		},
		.simple = {
			.target_name = "t2",
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint3b = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 15,
			.blocks = 3
		},
		.simple = {
			.target_name = "t3",
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint4b = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 16,
			.blocks = 1
		},
		.simple = {
			.target_name = "t5",
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint5b = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 16,
			.blocks = 8
		},
		.simple = {
			.target_name = "t4",
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint6b = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 16,
			.blocks = 12
		},
		.simple = {
			.target_name = "t6",
		},
		.persistent = false,
		.authoritative = false
	};
	struct location_hint hint7b = {
		.hint_type = RD_HINT_TYPE_SIMPLE_NQN,
		.extent = {
			.start_lba = 20,
			.blocks = 2
		},
		.simple = {
			.target_name = "t2",
		},
		.persistent = false,
		.authoritative = false
	};

	hint1b.extent.blocks = redirector_max_blocks(pbdev);

	config = vbdev_redirector_find_config("redirector1");
	SPDK_CU_ASSERT_FATAL(config);

	dump_hint_list(config);
	dump_target_list(config);
	dump_rule_table(pbdev);

	target_iter = g_sequence_get_begin_iter(config->targets);
	SPDK_CU_ASSERT_FATAL(!g_sequence_iter_is_end(target_iter));
	target_iter = g_sequence_iter_next(target_iter);
	SPDK_CU_ASSERT_FATAL(!g_sequence_iter_is_end(target_iter));
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	target_name1 = strdup(iter_target->name);

	target_iter = g_sequence_iter_next(target_iter);
	SPDK_CU_ASSERT_FATAL(!g_sequence_iter_is_end(target_iter));
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	target_name2 = strdup(iter_target->name);

	target_iter = g_sequence_iter_next(target_iter);
	SPDK_CU_ASSERT_FATAL(!g_sequence_iter_is_end(target_iter));
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	target_name3 = strdup(iter_target->name);

	target_iter = g_sequence_iter_next(target_iter);
	SPDK_CU_ASSERT_FATAL(!g_sequence_iter_is_end(target_iter));
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	target_name4 = strdup(iter_target->name);

	target_iter = g_sequence_iter_next(target_iter);
	SPDK_CU_ASSERT_FATAL(!g_sequence_iter_is_end(target_iter));
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	target_name5 = strdup(iter_target->name);

	target_iter = g_sequence_iter_next(target_iter);
	SPDK_CU_ASSERT_FATAL(!g_sequence_iter_is_end(target_iter));
	iter_target = (struct redirector_target *)g_sequence_get(target_iter);
	target_name6 = strdup(iter_target->name);

	hint1b.simple.target_name = target_name1;
	hint2b.simple.target_name = target_name2;
	hint3b.simple.target_name = target_name3;
	hint4b.simple.target_name = target_name5;
	hint5b.simple.target_name = target_name4;
	hint6b.simple.target_name = target_name6;
	hint7b.simple.target_name = target_name2;

	/* returns 0 when hints table is empty */
	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 1, NULL);
	CU_ASSERT(target_index == 0);

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0x7F, NULL);
	CU_ASSERT(target_index == 0);

	rc = add_simple_hint(config, &hint1b);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint2b);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint3b);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint4b);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint5b);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint6b);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	rc = add_simple_hint(config, &hint7b);
	CU_ASSERT(rc == 0);

	dump_hint_list(config);
	dump_rule_table(pbdev);

	hints_length = g_sequence_get_length(config->hints);
	CU_ASSERT(7 == hints_length);

	/* Looking for:
	 * 0: t2
	 * 15: t3
	 * 16: t5
	 * 17: t3 <=== This isn't working yet. Once 4 is on the rule stack, it never looks at 3
	 * 18: t4
	 * 20: t2
	 * 22: t4
	 * 24: t6
	 * 29: t1
	 */

	/* Apply rules to channel by creating a new one */
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	spdk_put_io_channel(ch);
	SPDK_CU_ASSERT_FATAL(g_io_channel == NULL);
	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, rd_ch) == 0);
	g_io_channel = ch;
	SPDK_CU_ASSERT_FATAL(ch == spdk_get_io_channel(pbdev));

	rules_length = g_sequence_get_length(pbdev->applied_rules);
	/* CU_ASSERT(9 == rules_length); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 0, NULL);
	/* CU_ASSERT(target_index == 1); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 1, NULL);
	/* CU_ASSERT(target_index == 1); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 14, NULL);
	/* CU_ASSERT(target_index == 1); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 15, NULL);
	/* CU_ASSERT(target_index == 2); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 16, NULL);
	/* CU_ASSERT(target_index == 4); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 17, NULL);
	/* CU_ASSERT(target_index == 2); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 18, NULL);
	/* CU_ASSERT(target_index == 3); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 19, NULL);
	/* CU_ASSERT(target_index == 3); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 20, NULL);
	/* CU_ASSERT(target_index == 1); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 21, NULL);
	/* CU_ASSERT(target_index == 1); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 22, NULL);
	/* CU_ASSERT(target_index == 3); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 23, NULL);
	/* CU_ASSERT(target_index == 3); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 24, NULL);
	/* CU_ASSERT(target_index == 5); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 25, NULL);
	/* CU_ASSERT(target_index == 5); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 28, NULL);
	/* CU_ASSERT(target_index == 5); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 29, NULL);
	/* CU_ASSERT(target_index == 0); */

	target_index = vbdev_redirector_select_target(pbdev, rd_ch, 30, NULL);
	/* CU_ASSERT(target_index == 0); */

	SPDK_CU_ASSERT_FATAL(ch != NULL);
	spdk_put_io_channel(ch);
	SPDK_CU_ASSERT_FATAL(g_io_channel == NULL);

	free_test_req(&construct_req);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	g_max_base_drives = saved_max_base_drives;
	reset_globals();
	free(target_name1);
	free(target_name2);
}

static void
test_construct_redirector_invalid_args(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;

	set_globals();
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);

	/* TODO: Add case where a target bdev is repeated */

	/* create_test_construct_rd_bdev(&req, "redirector1", 0, true); */
	/* verify_redirector_config_present(req.name, false); */
	/* verify_redirector_bdev_present(req.name, false); */
	/* /\* req.redirector_level = 1; *\/ */
	/* g_rpc_err = 0; */
	/* g_json_decode_obj_construct = 1; */
	/* spdk_rpc_construct_redirector_bdev(NULL, NULL); */
	/* SPDK_CU_ASSERT_FATAL(g_rpc_err == 1); */
	/* free_test_req(&req); */
	/* verify_redirector_config_present("redirector1", false); */
	/* verify_redirector_bdev_present("redirector1", false); */

	/* TODO: Add case where target bdev register fails (non-dup) */

	/* create_test_construct_rd_bdev(&req, "redirector1", 0, false); */
	/* verify_redirector_config_present(req.name, false); */
	/* verify_redirector_bdev_present(req.name, false); */
	/* g_rpc_err = 0; */
	/* g_json_decode_obj_err = 1; */
	/* g_json_decode_obj_construct = 1; */
	/* spdk_rpc_construct_redirector_bdev(NULL, NULL); */
	/* SPDK_CU_ASSERT_FATAL(g_rpc_err == 1); */
	/* g_json_decode_obj_err = 0; */
	/* free_test_req(&req); */
	/* verify_redirector_config_present("redirector1", false); */
	/* verify_redirector_bdev_present("redirector1", false); */

	/* Success (deferred) */
	create_test_construct_rd_bdev(&req, "redirector1", 0, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, false);
	free_test_req(&req);

	/* Fail (already exists) */
	create_test_construct_rd_bdev(&req, "redirector1", 0, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 1);
	free_test_req(&req);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);
	rpc_req = &req;
	rpc_req_size = sizeof(req);

	/* Success */
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	free_test_req(&req);

	/* Fail (all target bdevs claimed by redirector1) */
	create_test_construct_rd_bdev(&req, "redirector2", 0, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 1);
	free_test_req(&req);
	verify_redirector_config_present("redirector2", true);
	verify_redirector_bdev_present("redirector2", false);
	destroy_req.name = strdup("redirector2");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	verify_redirector_config_present("redirector2", false);
	verify_redirector_bdev_present("redirector2", false);
	rpc_req = &req;
	rpc_req_size = sizeof(req);

	/* Fail (one target bdev claimed by redirector1) */
	create_test_construct_rd_bdev(&req, "redirector2", g_max_base_drives, true);
	free(req.default_targets.default_target_names[g_max_base_drives - 1]);
	req.default_targets.default_target_names[g_max_base_drives - 1] = strdup("Nvme00n1");
	SPDK_CU_ASSERT_FATAL(req.default_targets.default_target_names[g_max_base_drives - 1] != NULL);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 1);
	free_test_req(&req);
	verify_redirector_config_present("redirector2", true);
	verify_redirector_bdev_present("redirector2", false);
	destroy_req.name = strdup("redirector2");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	verify_redirector_config_present("redirector2", false);
	verify_redirector_bdev_present("redirector2", false);
	rpc_req = &req;
	rpc_req_size = sizeof(req);

	/* Success */
	create_test_construct_rd_bdev(&req, "redirector2", g_max_base_drives * 2, true);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	free_test_req(&req);
	verify_redirector_config_present("redirector2", true);
	verify_redirector_bdev_present("redirector2", true);

	/* TODO: Add case where two redirectors have same target bdevs, but the
	   bdevs don't exist yet. */

	/* Delete & recreate redirector2 while redirector1 remains */
	destroy_req.name = strdup("redirector2");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	verify_redirector_config_present("redirector2", false);
	verify_redirector_bdev_present("redirector2", false);

	create_test_construct_rd_bdev(&req, "redirector2", g_max_base_drives, true);
	g_rpc_err = 0;
	g_json_beg_res_ret_err = 1;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	free_test_req(&req);
	verify_redirector_config_present("redirector2", true);
	verify_redirector_bdev_present("redirector2", true);
	verify_redirector_config_present("redirector1", true);
	verify_redirector_bdev_present("redirector1", true);
	g_json_beg_res_ret_err = 0;

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	destroy_req.name = strdup("redirector2");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
test_delete_redirector_invalid_args(void)
{
	struct rpc_construct_redirector_bdev construct_req;
	struct rpc_delete_redirector destroy_req;

	set_globals();
	create_test_construct_rd_bdev(&construct_req, "redirector1", 0, true);
	rpc_req = &construct_req;
	rpc_req_size = sizeof(construct_req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(construct_req.name, false);
	verify_redirector_bdev_present(construct_req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&construct_req, true);
	verify_redirector_bdev(&construct_req, true);
	free_test_req(&construct_req);

	destroy_req.name = strdup("redirector2");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 1);

	destroy_req.name = strdup("redirector1");
	g_rpc_err = 0;
	g_json_decode_obj_err = 1;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 1);
	g_json_decode_obj_err = 0;
	g_rpc_err = 0;
	free(destroy_req.name);
	verify_redirector_config_present("redirector1", true);
	verify_redirector_bdev_present("redirector1", true);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
test_io_channel(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct redirector_bdev_io_channel *ch_ctx;
	uint32_t i;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);

	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);

	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	ch_ctx = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);

	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
	for (i = 0; i < req.default_targets.num_default_targets; i++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[i].ch == (void *)0x1);
	}
	redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
	free_test_req(&req);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	free(ch_ctx);
	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
test_write_io(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct redirector_bdev_io_channel *ch_ctx;
	uint32_t i;
	struct spdk_bdev_io *bdev_io;
	uint32_t count;
	uint64_t io_len;
	uint64_t lba;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	ch = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch_ctx = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);

	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
	for (i = 0; i < req.default_targets.num_default_targets; i++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[i].ch == (void *)0x1);
	}

	lba = 0;
	for (count = 0; count < g_max_qd; count++) {
		bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
		SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
		io_len = (rand() % g_strip_size) + 1;
		bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, lba, io_len, SPDK_BDEV_IO_TYPE_WRITE);
		lba += g_strip_size;
		memset(g_io_output, 0, (g_max_io_size / g_strip_size) + 1 * sizeof(struct io_output));
		g_io_output_index = 0;
		vbdev_redirector_submit_request(ch, bdev_io);
		verify_io(bdev_io, req.default_targets.num_default_targets, ch_ctx, pbdev,
			  g_child_io_status_flag);
		bdev_io_cleanup(bdev_io);
		free(bdev_io);
	}
	free_test_req(&req);

	redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
	/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel == NULL); */
	free(ch);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
test_read_io(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct redirector_bdev_io_channel *ch_ctx;
	uint32_t i;
	struct spdk_bdev_io *bdev_io;
	uint32_t count;
	uint64_t io_len;
	uint64_t lba;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	ch = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch_ctx = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);

	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
	for (i = 0; i < req.default_targets.num_default_targets; i++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[i].ch == (void *)0x1);
	}
	free_test_req(&req);

	lba = 0;
	for (count = 0; count < g_max_qd; count++) {
		bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
		SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
		io_len = (rand() % g_strip_size) + 1;
		bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, lba, io_len, SPDK_BDEV_IO_TYPE_READ);
		lba += g_strip_size;
		memset(g_io_output, 0, (g_max_io_size / g_strip_size) + 1 * sizeof(struct io_output));
		g_io_output_index = 0;
		vbdev_redirector_submit_request(ch, bdev_io);
		verify_io(bdev_io, req.default_targets.num_default_targets, ch_ctx, pbdev,
			  g_child_io_status_flag);
		bdev_io_cleanup(bdev_io);
		free(bdev_io);
	}

	redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
	/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel == NULL); */
	free(ch);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
redirector_bdev_io_generate_by_strips(uint64_t n_strips)
{
	uint64_t lba;
	uint64_t nblocks;
	uint64_t start_offset;
	uint64_t end_offset;
	uint64_t offsets_in_strip[3];
	uint64_t start_bdev_idx;
	uint64_t start_bdev_offset;
	uint64_t start_bdev_idxs[3];
	int i, j, l;

	/* 3 different situations of offset in strip */
	offsets_in_strip[0] = 0;
	offsets_in_strip[1] = g_strip_size >> 1;
	offsets_in_strip[2] = g_strip_size - 1;

	/* 3 different situations of start_bdev_idx */
	start_bdev_idxs[0] = 0;
	start_bdev_idxs[1] = g_max_base_drives >> 1;
	start_bdev_idxs[2] = g_max_base_drives - 1;

	/* consider different offset in strip */
	for (i = 0; i < 3; i++) {
		start_offset = offsets_in_strip[i];
		for (j = 0; j < 3; j++) {
			end_offset = offsets_in_strip[j];
			if (n_strips == 1 && start_offset > end_offset) {
				continue;
			}

			/* consider at which default_target lba is started. */
			for (l = 0; l < 3; l++) {
				start_bdev_idx = start_bdev_idxs[l];
				start_bdev_offset = start_bdev_idx * g_strip_size;
				lba = g_lba_offset + start_bdev_offset + start_offset;
				nblocks = (n_strips - 1) * g_strip_size + end_offset - start_offset + 1;

				g_io_ranges[g_io_range_idx].lba = lba;
				g_io_ranges[g_io_range_idx].nblocks = nblocks;

				SPDK_CU_ASSERT_FATAL(g_io_range_idx < MAX_TEST_IO_RANGE);
				g_io_range_idx++;
			}
		}
	}
}

static void
redirector_bdev_io_generate(void)
{
	uint64_t n_strips;
	uint64_t n_strips_span = g_max_base_drives;
	uint64_t n_strips_times[5] = {g_max_base_drives + 1, g_max_base_drives * 2 - 1, g_max_base_drives * 2,
				      g_max_base_drives * 3, g_max_base_drives * 4
				     };
	uint32_t i;

	g_io_range_idx = 0;

	/* consider different number of strips from 1 to strips spanned target bdevs,
	 * and even to times of strips spanned target bdevs
	 */
	for (n_strips = 1; n_strips < n_strips_span; n_strips++) {
		redirector_bdev_io_generate_by_strips(n_strips);
	}

	for (i = 0; i < SPDK_COUNTOF(n_strips_times); i++) {
		n_strips = n_strips_times[i];
		redirector_bdev_io_generate_by_strips(n_strips);
	}
}

static void
test_unmap_io(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct redirector_bdev_io_channel *ch_ctx;
	uint32_t i;
	struct spdk_bdev_io *bdev_io;
	uint32_t count;
	uint64_t io_len;
	uint64_t lba;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	ch = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch_ctx = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);

	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
	for (i = 0; i < req.default_targets.num_default_targets; i++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[i].ch == (void *)0x1);
	}

	SPDK_CU_ASSERT_FATAL(vbdev_redirector_io_type_supported(pbdev, SPDK_BDEV_IO_TYPE_UNMAP) == true);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_io_type_supported(pbdev, SPDK_BDEV_IO_TYPE_FLUSH) == true);

	redirector_bdev_io_generate();
	for (count = 0; count < g_io_range_idx; count++) {
		bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
		SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
		io_len = g_io_ranges[count].nblocks;
		lba = g_io_ranges[count].lba;
		bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, lba, io_len, SPDK_BDEV_IO_TYPE_UNMAP);
		memset(g_io_output, 0, g_max_base_drives * sizeof(struct io_output));
		g_io_output_index = 0;
		vbdev_redirector_submit_request(ch, bdev_io);
		verify_io_without_payload(bdev_io, req.default_targets.num_default_targets, ch_ctx, pbdev,
					  g_child_io_status_flag);
		bdev_io_cleanup(bdev_io);
		free(bdev_io);
	}
	free_test_req(&req);

	redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
	/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel == NULL); */
	free(ch);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

/* Test IO failures */
static void
test_io_failure(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct redirector_bdev_io_channel *ch_ctx;
	uint32_t i;
	struct spdk_bdev_io *bdev_io;
	uint32_t count;
	uint64_t io_len;
	uint64_t lba;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	ch = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch_ctx = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);

	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
	for (i = 0; i < req.default_targets.num_default_targets; i++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[i].ch == (void *)0x1);
	}
	free_test_req(&req);

	lba = 0;
	for (count = 0; count < 1; count++) {
		bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
		SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
		io_len = (rand() % g_strip_size) + 1;
		bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, lba, io_len, SPDK_BDEV_IO_TYPE_INVALID);
		lba += g_strip_size;
		memset(g_io_output, 0, (g_max_io_size / g_strip_size) + 1 * sizeof(struct io_output));
		g_io_output_index = 0;
		vbdev_redirector_submit_request(ch, bdev_io);
		verify_io(bdev_io, req.default_targets.num_default_targets, ch_ctx, pbdev,
			  INVALID_IO_SUBMIT);
		bdev_io_cleanup(bdev_io);
		free(bdev_io);
	}


	lba = 0;
	g_child_io_status_flag = false;
	for (count = 0; count < 1; count++) {
		bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
		SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
		io_len = (rand() % g_strip_size) + 1;
		bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, lba, io_len, SPDK_BDEV_IO_TYPE_WRITE);
		lba += g_strip_size;
		memset(g_io_output, 0, (g_max_io_size / g_strip_size) + 1 * sizeof(struct io_output));
		g_io_output_index = 0;
		vbdev_redirector_submit_request(ch, bdev_io);
		verify_io(bdev_io, req.default_targets.num_default_targets, ch_ctx, pbdev,
			  g_child_io_status_flag);
		bdev_io_cleanup(bdev_io);
		free(bdev_io);
	}

	redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
	/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel == NULL); */
	free(ch);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

/* Test reset IO */
static void
test_reset_io(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct redirector_bdev_io_channel *ch_ctx;
	uint32_t i;
	struct spdk_bdev_io *bdev_io;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	ch = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch_ctx = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);

	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
	for (i = 0; i < req.default_targets.num_default_targets; i++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[i].ch == (void *)0x1);
	}
	free_test_req(&req);

	g_bdev_io_submit_status = 0;
	g_child_io_status_flag = true;

	SPDK_CU_ASSERT_FATAL(vbdev_redirector_io_type_supported(pbdev, SPDK_BDEV_IO_TYPE_RESET) == true);

	bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
	SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
	bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, 0, 1, SPDK_BDEV_IO_TYPE_RESET);
	memset(g_io_output, 0, g_max_base_drives * sizeof(struct io_output));
	g_io_output_index = 0;
	vbdev_redirector_submit_request(ch, bdev_io);
	verify_reset_io(bdev_io, req.default_targets.num_default_targets, ch_ctx, pbdev,
			true);
	bdev_io_cleanup(bdev_io);
	free(bdev_io);

	redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
	/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel == NULL); */
	free(ch);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

/* Test waitq logic */
static void
test_io_waitq(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct redirector_bdev_io_channel *ch_ctx;
	uint32_t i;
	struct spdk_bdev_io *bdev_io;
	struct spdk_bdev_io *bdev_io_next;
	uint32_t count;
	uint64_t lba;
	TAILQ_HEAD(, spdk_bdev_io) head_io;

	set_globals();
	g_normal_target_qd = 1024;
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);
	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);
	ch = calloc(1, sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	ch_ctx = spdk_io_channel_get_ctx(ch);
	SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);

	SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
	/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel != NULL); */
	for (i = 0; i < req.default_targets.num_default_targets; i++) {
		SPDK_CU_ASSERT_FATAL(ch_ctx->targets[i].ch == (void *)0x1);
	}
	free_test_req(&req);

	lba = 0;
	TAILQ_INIT(&head_io);
	for (count = 0; count < 128; count++) {
		bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
		SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
		TAILQ_INSERT_TAIL(&head_io, bdev_io, module_link);
		bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, lba, 8, SPDK_BDEV_IO_TYPE_WRITE);
		g_bdev_io_submit_status = -ENOMEM;
		lba += g_strip_size;
		vbdev_redirector_submit_request(ch, bdev_io);
	}

	g_ignore_io_output = 1;

	count = get_num_elts_in_waitq();
	SPDK_CU_ASSERT_FATAL(count == 128);
	g_bdev_io_submit_status = 0;
	process_io_waitq();
	SPDK_CU_ASSERT_FATAL(TAILQ_EMPTY(&g_io_waitq));

	TAILQ_FOREACH_SAFE(bdev_io, &head_io, module_link, bdev_io_next) {
		bdev_io_cleanup(bdev_io);
		free(bdev_io);
	}

	redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
	/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel == NULL); */
	g_ignore_io_output = 0;
	free(ch);
	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

/* Create multiple redirectors, destroy redirectors without IO, get_redirectors related tests */
static void
test_multi_redirector_no_io(void)
{
	struct rpc_construct_redirector_bdev *construct_req;
	struct rpc_delete_redirector destroy_req;
	/* struct rpc_get_redirector_bdevs get_redirectors_req; */
	uint32_t i;
	char name[16];
	uint32_t count;
	uint32_t bbdev_idx = 0;

	set_globals();
	construct_req = calloc(MAX_REDIRECTORS, sizeof(struct rpc_construct_redirector_bdev));
	SPDK_CU_ASSERT_FATAL(construct_req != NULL);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	for (i = 0; i < g_max_redirectors; i++) {
		count = snprintf(name, 16, "%s%u", "redirector", i);
		name[count] = '\0';
		create_test_construct_rd_bdev(&construct_req[i], name, bbdev_idx, true);
		verify_redirector_config_present(name, false);
		verify_redirector_bdev_present(name, false);
		bbdev_idx += g_max_base_drives;
		rpc_req = &construct_req[i];
		rpc_req_size = sizeof(construct_req[0]);
		g_rpc_err = 0;
		g_json_decode_obj_construct = 1;
		spdk_rpc_construct_redirector_bdev(NULL, NULL);
		SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
		verify_redirector_config(&construct_req[i], true);
		verify_redirector_bdev(&construct_req[i], true);
	}

	for (i = 0; i < g_max_redirectors; i++) {
		SPDK_CU_ASSERT_FATAL(construct_req[i].name != NULL);
		destroy_req.name = strdup(construct_req[i].name);
		count = snprintf(name, 16, "%s", destroy_req.name);
		name[count] = '\0';
		rpc_req = &destroy_req;
		rpc_req_size = sizeof(destroy_req);
		g_rpc_err = 0;
		g_json_decode_obj_construct = 0;
		spdk_rpc_delete_redirector_bdev(NULL, NULL);
		SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
		verify_redirector_config_present(name, false);
		verify_redirector_bdev_present(name, false);
	}
	g_test_multi_redirectors = 0;
	vbdev_redirector_finish();
	for (i = 0; i < g_max_redirectors; i++) {
		free_test_req(&construct_req[i]);
	}
	free(construct_req);
	default_targets_cleanup();
	reset_globals();
}

/* Create multiple redirectors, fire IOs randomly on various redirectors */
static void
test_multi_redirector_with_io(void)
{
	struct rpc_construct_redirector_bdev *construct_req;
	struct rpc_delete_redirector destroy_req;
	uint32_t i, j;
	char name[16];
	uint32_t count;
	uint32_t bbdev_idx = 0;
	struct redirector_bdev *pbdev;
	struct spdk_io_channel *ch;
	struct redirector_bdev_io_channel *ch_ctx;
	struct spdk_bdev_io *bdev_io;
	uint64_t io_len;
	uint64_t lba;
	struct spdk_io_channel *ch_random;
	struct redirector_bdev_io_channel *ch_ctx_random;
	int16_t iotype;
	uint32_t redirector_random;

	set_globals();
	construct_req = calloc(g_max_redirectors, sizeof(struct rpc_construct_redirector_bdev));
	SPDK_CU_ASSERT_FATAL(construct_req != NULL);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	ch = calloc(g_max_redirectors,
		    sizeof(struct spdk_io_channel) + sizeof(struct redirector_bdev_io_channel));
	SPDK_CU_ASSERT_FATAL(ch != NULL);
	for (i = 0; i < g_max_redirectors; i++) {
		count = snprintf(name, 16, "%s%u", "redirector", i);
		name[count] = '\0';
		create_test_construct_rd_bdev(&construct_req[i], name, bbdev_idx, true);
		verify_redirector_config_present(name, false);
		verify_redirector_bdev_present(name, false);
		bbdev_idx += g_max_base_drives;
		rpc_req = &construct_req[i];
		rpc_req_size = sizeof(construct_req[0]);
		g_rpc_err = 0;
		g_json_decode_obj_construct = 1;
		spdk_rpc_construct_redirector_bdev(NULL, NULL);
		SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
		verify_redirector_config(&construct_req[i], true);
		verify_redirector_bdev(&construct_req[i], true);
		TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
			if (strcmp(pbdev->redirector_bdev.name, construct_req[i].name) == 0) {
				break;
			}
		}
		SPDK_CU_ASSERT_FATAL(pbdev != NULL);
		ch_ctx = spdk_io_channel_get_ctx(&ch[i]);
		SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);
		SPDK_CU_ASSERT_FATAL(redirector_bdev_ch_create_cb(pbdev, ch_ctx) == 0);
		/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel != NULL); */
		for (j = 0; j < construct_req[i].default_targets.num_default_targets; j++) {
			SPDK_CU_ASSERT_FATAL(ch_ctx->targets[j].ch == (void *)0x1);
		}
	}

	lba = 0;
	for (count = 0; count < g_max_qd; count++) {
		bdev_io = calloc(1, sizeof(struct spdk_bdev_io) + sizeof(struct redirector_bdev_io));
		SPDK_CU_ASSERT_FATAL(bdev_io != NULL);
		io_len = (rand() % g_strip_size) + 1;
		iotype = (rand() % 2) ? SPDK_BDEV_IO_TYPE_WRITE : SPDK_BDEV_IO_TYPE_READ;
		memset(g_io_output, 0, (g_max_io_size / g_strip_size) + 1 * sizeof(struct io_output));
		g_io_output_index = 0;
		redirector_random = rand() % g_max_redirectors;
		ch_random = &ch[redirector_random];
		ch_ctx_random = spdk_io_channel_get_ctx(ch_random);
		TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
			if (strcmp(pbdev->redirector_bdev.name, construct_req[redirector_random].name) == 0) {
				break;
			}
		}
		bdev_io_initialize(bdev_io, &pbdev->redirector_bdev, lba, io_len, iotype);
		lba += g_strip_size;
		SPDK_CU_ASSERT_FATAL(pbdev != NULL);
		vbdev_redirector_submit_request(ch_random, bdev_io);
		verify_io(bdev_io, g_max_base_drives, ch_ctx_random, pbdev,
			  g_child_io_status_flag);
		bdev_io_cleanup(bdev_io);
		free(bdev_io);
	}

	for (i = 0; i < g_max_redirectors; i++) {
		TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
			if (strcmp(pbdev->redirector_bdev.name, construct_req[i].name) == 0) {
				break;
			}
		}
		SPDK_CU_ASSERT_FATAL(pbdev != NULL);
		ch_ctx = spdk_io_channel_get_ctx(&ch[i]);
		SPDK_CU_ASSERT_FATAL(ch_ctx != NULL);
		redirector_bdev_ch_destroy_cb(pbdev, ch_ctx);
		/* SPDK_CU_ASSERT_FATAL(ch_ctx->target_channel == NULL); */
		destroy_req.name = strdup(construct_req[i].name);
		count = snprintf(name, 16, "%s", destroy_req.name);
		name[count] = '\0';
		rpc_req = &destroy_req;
		rpc_req_size = sizeof(destroy_req);
		g_rpc_err = 0;
		g_json_decode_obj_construct = 0;
		spdk_rpc_delete_redirector_bdev(NULL, NULL);
		SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
		verify_redirector_config_present(name, false);
		verify_redirector_bdev_present(name, false);
	}
	vbdev_redirector_finish();
	for (i = 0; i < g_max_redirectors; i++) {
		free_test_req(&construct_req[i]);
	}
	free(construct_req);
	free(ch);
	default_targets_cleanup();
	reset_globals();
}

static void
test_io_type_supported(void)
{
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_io_type_supported(NULL, SPDK_BDEV_IO_TYPE_READ) == true);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_io_type_supported(NULL, SPDK_BDEV_IO_TYPE_WRITE) == true);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_io_type_supported(NULL, SPDK_BDEV_IO_TYPE_INVALID) == false);
}

#if defined(VBDEV_REDIRECTOR_USE_TEXT_CONFIG)
static void
test_create_redirector_from_config(void)
{
	struct rpc_construct_redirector_bdev req;
	struct spdk_bdev *bdev;
	struct rpc_delete_redirector destroy_req;
	/* bool can_claim; */
	/* struct redirector_config *redirector_cfg; */
	/* uint32_t default_target_slot; */

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	g_config_level_create = 1;
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	g_config_level_create = 0;

	verify_redirector_config_present("redirector1", true);
	verify_redirector_bdev_present("redirector1", true);

	TAILQ_FOREACH(bdev, &g_bdev_list, internal.link) {
		vbdev_redirector_examine(bdev);
	}

	/* can_claim = redirector_bdev_can_claim_bdev("Invalid", &redirector_cfg, &default_target_slot); */
	/* SPDK_CU_ASSERT_FATAL(can_claim == false); */

	verify_redirector_config(&req, true);
	verify_redirector_bdev(&req, true);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	free_test_req(&req);
	default_targets_cleanup();
	reset_globals();
}
#endif

#if defined(VBDEV_REDIRECTOR_USE_TEXT_CONFIG)
static void
test_create_redirector_from_config_invalid_params(void)
{
	struct rpc_construct_redirector_bdev req;
	uint8_t count;

	set_globals();
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	g_config_level_create = 1;

	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	free(req.name);
	req.name = NULL;
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() != 0);
	free_test_req(&req);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	create_test_construct_rd_bdev(&req, "redirector1", 0, false);
	/* req.strip_size_kb = 1234; */
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() != 0);
	free_test_req(&req);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	create_test_construct_rd_bdev(&req, "redirector1", 0, false);
	/* req.redirector_level = 1; */
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() != 0);
	free_test_req(&req);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	create_test_construct_rd_bdev(&req, "redirector1", 0, false);
	/* req.redirector_level = 1; */
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() != 0);
	free_test_req(&req);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	create_test_construct_rd_bdev(&req, "redirector1", 0, false);
	req.default_targets.num_default_targets++;
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() != 0);
	req.default_targets.num_default_targets--;
	free_test_req(&req);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	create_test_construct_rd_bdev(&req, "redirector1", 0, false);
	req.default_targets.num_default_targets--;
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() != 0);
	req.default_targets.num_default_targets++;
	free_test_req(&req);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	if (g_max_target_drives > 1) {
		create_test_construct_rd_bdev(&req, "redirector1", 0, false);
		count = snprintf(req.default_targets.default_target_names[g_max_base_drives - 1], 15, "%s",
				 "Nvme00n1");
		req.default_targets.default_target_names[g_max_base_drives - 1][count] = '\0';
		SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() != 0);
		free_test_req(&req);
		verify_redirector_config_present("redirector1", false);
		verify_redirector_bdev_present("redirector1", false);
	}

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}
#endif

static void
test_redirector_json_dump_info(void)
{
	struct rpc_construct_redirector_bdev req;
	struct rpc_delete_redirector destroy_req;
	struct redirector_bdev *pbdev;

	set_globals();
	create_test_construct_rd_bdev(&req, "redirector1", 0, true);
	rpc_req = &req;
	rpc_req_size = sizeof(req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);

	verify_redirector_config_present(req.name, false);
	verify_redirector_bdev_present(req.name, false);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_bdev(&req, true);

	TAILQ_FOREACH(pbdev, &g_redirector_bdevs, bdev_link) {
		if (strcmp(pbdev->redirector_bdev.name, req.name) == 0) {
			break;
		}
	}
	SPDK_CU_ASSERT_FATAL(pbdev != NULL);

	SPDK_CU_ASSERT_FATAL(vbdev_redirector_dump_info_json(pbdev, NULL) == 0);

	free_test_req(&req);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

static void
test_context_size(void)
{
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_get_ctx_size() == sizeof(struct redirector_bdev_io));
}

static void
test_asym_base_drives_blockcnt(void)
{
	struct rpc_construct_redirector_bdev construct_req;
	struct rpc_delete_redirector destroy_req;
	struct spdk_bdev *bbdev;
	uint32_t i;

	set_globals();
	create_test_construct_rd_bdev(&construct_req, "redirector1", 0, true);
	rpc_req = &construct_req;
	rpc_req_size = sizeof(construct_req);
	SPDK_CU_ASSERT_FATAL(vbdev_redirector_init() == 0);
	verify_redirector_config_present(construct_req.name, false);
	verify_redirector_bdev_present(construct_req.name, false);
	g_rpc_err = 0;
	for (i = 0; i < construct_req.default_targets.num_default_targets; i++) {
		bbdev = spdk_bdev_get_by_name(construct_req.default_targets.default_target_names[i]);
		SPDK_CU_ASSERT_FATAL(bbdev != NULL);
		bbdev->blockcnt = rand() + 1;
	}
	g_json_decode_obj_construct = 1;
	spdk_rpc_construct_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config(&construct_req, true);
	verify_redirector_bdev(&construct_req, true);
	free_test_req(&construct_req);

	destroy_req.name = strdup("redirector1");
	rpc_req = &destroy_req;
	rpc_req_size = sizeof(destroy_req);
	g_rpc_err = 0;
	g_json_decode_obj_construct = 0;
	spdk_rpc_delete_redirector_bdev(NULL, NULL);
	SPDK_CU_ASSERT_FATAL(g_rpc_err == 0);
	verify_redirector_config_present("redirector1", false);
	verify_redirector_bdev_present("redirector1", false);

	vbdev_redirector_finish();
	default_targets_cleanup();
	reset_globals();
}

int main(int argc, char **argv)
{
	CU_pSuite       suite = NULL;
	CU_pSuite       disabled_suite = NULL;
	unsigned int    num_failures;
	int		c;
	while (1) {
		static struct option long_options[] = {
			{"block_len",	    required_argument,	0, 'k'},
			{"strip_size",	    required_argument,	0, 't'},
			{"max_io_size",	    required_argument,	0, 'i'},
			{"max_qd",	    required_argument,	0, 'q'},
			{"max_base_drives", required_argument,	0, 'b'},
			{"max_redirectors", required_argument,	0, 'r'},
			{"seed",	    required_argument,	0, 's'},
			{"verbose",	    no_argument,	0, 'v'},
			{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "k:t:i:q:b:r:s:v", long_options, &option_index);

		if (-1 == c) {
			break;
		}

		switch (c) {
		case 'k':
			g_block_len = strtol(optarg, NULL, 10);
			g_block_len_specified = true;
			break;
		case 't':
			g_strip_size = strtol(optarg, NULL, 10);
			g_strip_size_specified = true;
			break;
		case 'i':
			g_max_io_size = strtol(optarg, NULL, 10);
			g_max_io_size_specified = true;
			break;
		case 'q':
			g_max_qd = strtol(optarg, NULL, 10);
			g_max_qd_specified = true;
			break;
		case 'b':
			g_max_base_drives = strtol(optarg, NULL, 10);
			g_max_base_drives_specified = true;
			break;
		case 'r':
			g_max_redirectors = strtol(optarg, NULL, 10);
			g_max_redirectors_specified = true;
			break;
		case 's':
			g_seed = strtol(optarg, NULL, 10);
			g_seed_specified = true;
			break;
		case 'v':
			if (g_verbose) {
				g_debug_print = true;
			}
			g_verbose = true;
			break;
		case '?':
			break;
		default:
			abort();
		}
	}

	if (CU_initialize_registry() != CUE_SUCCESS) {
		return CU_get_error();
	}

	suite = CU_add_suite("redirector", NULL, NULL);
	if (suite == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	disabled_suite = CU_add_suite("redirector-tbd", NULL, NULL);
	if (disabled_suite == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	if (
		CU_add_test(suite, "test_construct_redirector", test_construct_redirector) == NULL ||
		CU_add_test(suite, "test_delete_redirector", test_delete_redirector) == NULL ||
		CU_add_test(suite, "test_add_hints", test_add_hints) == NULL ||
		CU_add_test(suite, "test_add_remove_targets", test_add_remove_targets) == NULL ||
		CU_add_test(suite, "test_select_target", test_select_target) == NULL ||
		CU_add_test(suite, "test_construct_redirector_invalid_args",
			    test_construct_redirector_invalid_args) == NULL ||
		CU_add_test(suite, "test_delete_redirector_invalid_args",
			    test_delete_redirector_invalid_args) == NULL ||
		CU_add_test(suite, "test_io_channel", test_io_channel) == NULL ||
		CU_add_test(suite, "test_reset_io", test_reset_io) == NULL    ||
		CU_add_test(disabled_suite, "test_write_io", test_write_io) == NULL    ||
		CU_add_test(disabled_suite, "test_read_io", test_read_io) == NULL     ||
		CU_add_test(disabled_suite, "test_unmap_io", test_unmap_io) == NULL     ||
		CU_add_test(disabled_suite, "test_io_failure", test_io_failure) == NULL ||
		CU_add_test(suite, "test_io_waitq", test_io_waitq) == NULL ||
		CU_add_test(suite, "test_multi_redirector_no_io", test_multi_redirector_no_io) == NULL ||
		CU_add_test(disabled_suite, "test_multi_redirector_with_io",
			    test_multi_redirector_with_io) == NULL ||
		CU_add_test(disabled_suite, "test_io_type_supported", test_io_type_supported) == NULL ||
#if defined(VBDEV_REDIRECTOR_USE_TEXT_CONFIG)
		CU_add_test(suite, "test_create_redirector_from_config",
			    test_create_redirector_from_config) == NULL ||
		CU_add_test(suite, "test_create_redirector_from_config_invalid_params",
			    test_create_redirector_from_config_invalid_params) == NULL ||
#endif
		CU_add_test(suite, "test_redirector_json_dump_info", test_redirector_json_dump_info) == NULL ||
		CU_add_test(suite, "test_context_size", test_context_size) == NULL ||
		CU_add_test(suite, "test_asym_base_drives_blockcnt", test_asym_base_drives_blockcnt) == NULL
		/* TODO: simple hint IO case (bypass hint config API) */
	) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	set_test_opts();
	/* CU_basic_run_tests(); */
	CU_basic_run_suite(suite);
	num_failures = CU_get_number_of_failures();
	CU_cleanup_registry();
	return num_failures;
}

DEFINE_STUB(spdk_bdev_write_zeroes_blocks, int,
	    (struct spdk_bdev_desc *desc, struct spdk_io_channel *ch,
	     uint64_t offset_blocks, uint64_t num_blocks,
	     spdk_bdev_io_completion_cb cb, void *cb_arg), 0);
