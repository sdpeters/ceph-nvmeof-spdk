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

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_rpc_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_hints.h"
#include "vbdev_redirector_targets.h"
#include "vbdev_redirector.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk_internal/log.h"

/* Free the allocated memory resource after the RPC handling. */
static void
free_rpc_construct_redirector_bdev(struct rpc_construct_redirector_bdev *r)
{
	size_t target_name_index;

	free(r->name);
	free(r->nqn);
	for (target_name_index = 0;
	     target_name_index < r->default_targets.num_default_targets;
	     target_name_index++) {
		free(r->default_targets.default_target_names[target_name_index]);
	}
}

static int
decode_default_targets(const struct spdk_json_val *val, void *out)
{
	struct rpc_construct_redirector_default_targets *default_targets = out;
	return spdk_json_decode_array(val, spdk_json_decode_string, default_targets->default_target_names,
				      REDIRECTOR_MAX_TARGET_BDEVS,
				      &default_targets->num_default_targets, sizeof(char *));
}

static int
decode_spdk_uuid(const struct spdk_json_val *val, void *out)
{
	struct spdk_uuid *uuid = out;
	char *uuid_str;
	int parse_error;

	/* Get a null-terminated copy to parse */
	uuid_str = spdk_json_strdup(val);
	if (!uuid_str) {
		return -1;
	}

	parse_error = spdk_uuid_parse(uuid, uuid_str);
	free(uuid_str);
	if (parse_error) {
		return -1;
	}

	return 0;
}

/* Structure to decode the input parameters for this RPC method. */
static const struct spdk_json_object_decoder rpc_construct_redirector_bdev_decoders[] = {
	{"name", offsetof(struct rpc_construct_redirector_bdev, name), spdk_json_decode_string},
	{"default_target_names", offsetof(struct rpc_construct_redirector_bdev, default_targets), decode_default_targets},
	{"size_configured", offsetof(struct rpc_construct_redirector_bdev, size_configured), spdk_json_decode_bool, true},
	{"blockcnt", offsetof(struct rpc_construct_redirector_bdev, size_config.blockcnt), spdk_json_decode_uint64, true},
	{"blocklen", offsetof(struct rpc_construct_redirector_bdev, size_config.blocklen), spdk_json_decode_uint32, true},
	{"required_alignment", offsetof(struct rpc_construct_redirector_bdev, size_config.required_alignment), spdk_json_decode_uint32, true},
	{"optimal_io_boundary", offsetof(struct rpc_construct_redirector_bdev, size_config.optimal_io_boundary), spdk_json_decode_uint32, true},
	{"uuid", offsetof(struct rpc_construct_redirector_bdev, uuid), decode_spdk_uuid, true},
	{"nqn", offsetof(struct rpc_construct_redirector_bdev, nqn), spdk_json_decode_string, true},
};

/*
 * Construct the redirector bdev, or arrange for it to be constructed when the things it needs become available.
 *
 * This bdev might not be namespace aware (that's an NVMe thing), so unless something special is done it will
 * expose only one ADNN logical namespace (and it probably doesn't know what that namespace's local or global
 * IDs are). It's TBD whether namespace awareness will happen here, or in some enclosing NVMe redirector
 * wrapper.
 *
 * The redirector bdev will not be created until its required targets can be opened. Normally that includes all
 * the default targets specified in this RPC call.
 */
static void
spdk_rpc_construct_redirector_bdev(struct spdk_jsonrpc_request *request,
				   const struct spdk_json_val *params)
{
	struct rpc_construct_redirector_bdev req = {NULL};
	struct spdk_json_write_ctx *w;
	int rc;

	if (spdk_json_decode_object(params, rpc_construct_redirector_bdev_decoders,
				    SPDK_COUNTOF(rpc_construct_redirector_bdev_decoders),
				    &req)) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "spdk_json_decode_object failed\n");
		goto invalid;
	}

	rc = create_redirector(&req);
	if (rc != 0) {
		goto invalid;
	}

	w = spdk_jsonrpc_begin_result(request);
	if (w == NULL) {
		free_rpc_construct_redirector_bdev(&req);
		return;
	}

	spdk_json_write_bool(w, true);
	spdk_jsonrpc_end_result(request, w);
	free_rpc_construct_redirector_bdev(&req);
	return;

invalid:
	free_rpc_construct_redirector_bdev(&req);
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, "Invalid parameters");
}
SPDK_RPC_REGISTER("construct_redirector_bdev", spdk_rpc_construct_redirector_bdev, SPDK_RPC_RUNTIME)

static void
free_rpc_delete_redirector(struct rpc_delete_redirector *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_delete_redirector_decoders[] = {
	{"name", offsetof(struct rpc_delete_redirector, name), spdk_json_decode_string},
};

static void
_spdk_rpc_delete_redirector_bdev_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;
	struct spdk_json_write_ctx *w;

	w = spdk_jsonrpc_begin_result(request);
	if (w == NULL) {
		return;
	}

	spdk_json_write_bool(w, bdeverrno == 0);
	spdk_jsonrpc_end_result(request, w);
}

/*
 * Unregisters the redirector bdev (if one was ever created) and removes the redirector from this app's
 * persistent configuration (when the config is next written).
 *
 * Completes when the redirector bdev (if any) is destroyed and the config removal is done.
 */
static void
spdk_rpc_delete_redirector_bdev(struct spdk_jsonrpc_request *request,
				const struct spdk_json_val *params)
{
	struct rpc_delete_redirector req = {NULL};
	/* struct spdk_bdev *bdev; */
	int rc;

	if (spdk_json_decode_object(params, rpc_delete_redirector_decoders,
				    SPDK_COUNTOF(rpc_delete_redirector_decoders),
				    &req)) {
		rc = -EINVAL;
		goto invalid;
	}

	rc = delete_redirector(&req, _spdk_rpc_delete_redirector_bdev_cb, request);
	if (0 != rc) {
		goto invalid;
	}

	free_rpc_delete_redirector(&req);

	return;

invalid:
	free_rpc_delete_redirector(&req);
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, spdk_strerror(-rc));
}
SPDK_RPC_REGISTER("delete_redirector_bdev", spdk_rpc_delete_redirector_bdev, SPDK_RPC_RUNTIME)

static void
free_rpc_redirector_add_target(struct rpc_redirector_add_target *req)
{
	free(req->redirector_name);
	free(req->target_name);
}

static const struct spdk_json_object_decoder rpc_redirector_add_target_decoders[] = {
	{"redirector", offsetof(struct rpc_redirector_add_target, redirector_name), spdk_json_decode_string},
	{"target", offsetof(struct rpc_redirector_add_target, target_name), spdk_json_decode_string},
	{"persistent_config", offsetof(struct rpc_redirector_add_target, persistent), spdk_json_decode_bool},
	{"required", offsetof(struct rpc_redirector_add_target, required), spdk_json_decode_bool},
	{"is_redirector", offsetof(struct rpc_redirector_add_target, redirector), spdk_json_decode_bool},
	{"dont_probe", offsetof(struct rpc_redirector_add_target, dont_probe), spdk_json_decode_bool},
};

/*
 * Adds a target to the redirector by bdev name.
 *
 * The target may be another redirector (which we assume can complete IO to any LBA of the redirector's
 * namespace), or not (in which case we'll only send IO to it for LBAs covered by location hints pointing to
 * this target).
 *
 * Redirectors that know the NGUID of the namespace they provide can identify other redirectors for the same
 * namespace without being told they're redirectors.
 */
static void
spdk_rpc_redirector_add_target(struct spdk_jsonrpc_request *request,
			       const struct spdk_json_val *params)
{
	struct rpc_redirector_add_target req = {NULL};
	struct spdk_json_write_ctx *w;
	int rc;

	if (spdk_json_decode_object(params, rpc_redirector_add_target_decoders,
				    SPDK_COUNTOF(rpc_redirector_add_target_decoders),
				    &req)) {
		SPDK_NOTICELOG("JSON decode failed\n");
		rc = -EINVAL;
		goto invalid;
	}

	/* Complete synchronously, and without waiting for the effects to be applied */
	rc = redirector_add_target(&req);
	if (0 != rc) {
		SPDK_NOTICELOG("Failed to add target %s to redirector %s\n", req.target_name, req.redirector_name);
		goto invalid;
	}

	/* SPDK_NOTICELOG("Added target %s to redirector %s\n", req.target_name, req.redirector_name); */
	w = spdk_jsonrpc_begin_result(request);
	if (w == NULL) {
		free_rpc_redirector_add_target(&req);
		return;
	}

	spdk_json_write_bool(w, true);
	spdk_jsonrpc_end_result(request, w);
	free_rpc_redirector_add_target(&req);

	return;

invalid:
	free_rpc_redirector_add_target(&req);
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, spdk_strerror(-rc));
}
SPDK_RPC_REGISTER("redirector_add_target", spdk_rpc_redirector_add_target, SPDK_RPC_RUNTIME)

static void
free_rpc_redirector_remove_target(struct rpc_redirector_remove_target *req)
{
	free(req->redirector_name);
	free(req->target_name);
}

static const struct spdk_json_object_decoder rpc_redirector_remove_target_decoders[] = {
	{"redirector", offsetof(struct rpc_redirector_remove_target, redirector_name), spdk_json_decode_string},
	{"target", offsetof(struct rpc_redirector_remove_target, target_name), spdk_json_decode_string},
	{"retain_hints", offsetof(struct rpc_redirector_remove_target, retain_hints), spdk_json_decode_bool, true},
};

struct rpc_redirector_remove_target_ctx {
	struct spdk_jsonrpc_request *request;
	struct rpc_redirector_remove_target req;
	struct redirector_config *config;
};

static void
spdk_rpc_redirector_remove_target_done(void *cb_arg, int rc)
{
	struct rpc_redirector_remove_target_ctx *ctx = cb_arg;
	struct spdk_json_write_ctx *w;

	if (0 != rc) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Removal of target %s on redirector %s failed\n",
			      ctx->req.target_name, ctx->req.redirector_name);
		spdk_jsonrpc_send_error_response(ctx->request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
						 spdk_strerror(-rc));
		goto exit;
	}

	w = spdk_jsonrpc_begin_result(ctx->request);
	if (w == NULL) {
		goto exit;
		return;
	}

	spdk_json_write_bool(w, true);
	spdk_jsonrpc_end_result(ctx->request, w);
exit:
	free_rpc_redirector_remove_target(&ctx->req);
	free(ctx);
}

/*
 * Removes a target from this redirector (and its persistent config), and optionally also removes every location
 * hint point to the removed target.
 *
 * Completes when there are no IOs in flight to the removed target, and the target bdev is closed.
 */
static void
spdk_rpc_redirector_remove_target(struct spdk_jsonrpc_request *request,
				  const struct spdk_json_val *params)
{
	struct rpc_redirector_remove_target_ctx *ctx;
	int rc;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		rc = -ENOMEM;
		goto send_error;
	}

	ctx->request = request;
	ctx->req.retain_hints = true;
	if (spdk_json_decode_object(params, rpc_redirector_remove_target_decoders,
				    SPDK_COUNTOF(rpc_redirector_remove_target_decoders),
				    &ctx->req)) {
		rc = -EINVAL;
		goto invalid;
	}

	ctx->config = vbdev_redirector_find_config(ctx->req.redirector_name);
	if (!ctx->config) {
		rc = -ENODEV;
		goto invalid;
	}

	redirector_remove_target(ctx->config, ctx->req.target_name, ctx->req.retain_hints, false, false,
				 spdk_rpc_redirector_remove_target_done, ctx);

	return;

invalid:
	free_rpc_redirector_remove_target(&ctx->req);
	free(ctx);
send_error:
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, spdk_strerror(-rc));
}
SPDK_RPC_REGISTER("redirector_remove_target", spdk_rpc_redirector_remove_target, SPDK_RPC_RUNTIME)

static void
free_rpc_redirector_add_hint(struct rpc_redirector_add_hint *req)
{
	free(req->redirector_name);
	free(req->target_name);
}

static const struct spdk_json_object_decoder rpc_redirector_add_hint_decoders[] = {
	{"redirector", offsetof(struct rpc_redirector_add_hint, redirector_name), spdk_json_decode_string},
	{"target", offsetof(struct rpc_redirector_add_hint, target_name), spdk_json_decode_string},
	{"start_lba", offsetof(struct rpc_redirector_add_hint, start_lba), spdk_json_decode_uint64},
	{"blocks", offsetof(struct rpc_redirector_add_hint, blocks), spdk_json_decode_uint64},
	{"target_start_lba", offsetof(struct rpc_redirector_add_hint, target_start_lba), spdk_json_decode_uint64},
	{"persistent_config", offsetof(struct rpc_redirector_add_hint, persistent), spdk_json_decode_bool},
	{"authoritative", offsetof(struct rpc_redirector_add_hint, authoritative), spdk_json_decode_bool},
};

/*
 * Adds a location hint to this redirector, directing IO to an LBA range to the named target.
 *
 * If the named target doesn't exist, the hint will have no effect until the target appears. Hints pointing to
 * nonexistent targets and not marked as persistent may be dropped at some point.
 *
 * Completes once this hint is in the redirector's configuration and applying it to the data path has begun, but
 * doesn't wait for it to be applied to the data path. IOs may be in flight (and new ones still dispatched) to
 * destinations other than what this hint specifies for a short time after this completes.
 */
static void
spdk_rpc_redirector_add_hint(struct spdk_jsonrpc_request *request,
			     const struct spdk_json_val *params)
{
	struct rpc_redirector_add_hint req = {NULL};
	struct redirector_config *config;
	struct spdk_json_write_ctx *w;
	int rc;

	if (spdk_json_decode_object(params, rpc_redirector_add_hint_decoders,
				    SPDK_COUNTOF(rpc_redirector_add_hint_decoders),
				    &req)) {
		SPDK_NOTICELOG("JSON decode failed\n");
		rc = -EINVAL;
		goto invalid;
	}

	/* SPDK_NOTICELOG("Looking for redirector %s\n", req.redirector_name); */
	config = vbdev_redirector_find_config(req.redirector_name);
	if (!config) {
		SPDK_NOTICELOG("Redirector %s not found\n", req.redirector_name);
		rc = -ENODEV;
		goto invalid;
	}

	/* Complete synchronously, and without waiting for the effects to be applied */
	rc = redirector_add_hint_rpc(config, req.start_lba, req.blocks, req.target_name,
				     req.target_start_lba, req.persistent, req.authoritative, true);
	if (0 != rc) {
		SPDK_NOTICELOG("Failed to add hint (%"PRId64",%"PRId64":%s@%"PRId64") to redirector %s\n",
			       req.start_lba, req.blocks, req.target_name, req.target_start_lba, req.redirector_name);
		goto invalid;
	}
	SPDK_NOTICELOG("Added hint (%"PRId64",%"PRId64":%s@%"PRId64"%s) to redirector %s\n",
		       req.start_lba, req.blocks, req.target_name, req.target_start_lba,
		       req.authoritative ? " [AUTH]" : "", req.redirector_name);

	w = spdk_jsonrpc_begin_result(request);
	if (w == NULL) {
		free_rpc_redirector_add_hint(&req);
		return;
	}

	spdk_json_write_bool(w, true);
	spdk_jsonrpc_end_result(request, w);
	free_rpc_redirector_add_hint(&req);

	return;

invalid:
	free_rpc_redirector_add_hint(&req);
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, spdk_strerror(-rc));
}
SPDK_RPC_REGISTER("redirector_add_hint", spdk_rpc_redirector_add_hint, SPDK_RPC_RUNTIME)

static void
free_rpc_redirector_remove_hint(struct rpc_redirector_remove_hint *req)
{
	free(req->redirector_name);
	free(req->target_name);
}

static const struct spdk_json_object_decoder rpc_redirector_remove_hint_decoders[] = {
	{"redirector", offsetof(struct rpc_redirector_remove_hint, redirector_name), spdk_json_decode_string},
	{"target", offsetof(struct rpc_redirector_remove_hint, target_name), spdk_json_decode_string},
	{"start_lba", offsetof(struct rpc_redirector_remove_hint, start_lba), spdk_json_decode_uint64},
	{"blocks", offsetof(struct rpc_redirector_remove_hint, blocks), spdk_json_decode_uint64},
};

/*
 * Removes all matching (target, start_lba, and blocks) location hints from this redirector. IO to the specified
 * LBA range will be routed according to the remaining location hints in this redirector (or to one of its
 * default targets if no hints remain).
 *
 * Completes once the matching hints are removed from the redirector's configuration and applying the current
 * set of hints to the data path has begun, but doesn't wait for it to be applied to the data path. IOs may be
 * in flight (and new ones still dispatched) to destinations as specified in this hint for a short time after
 * this completes.
 */
static void
spdk_rpc_redirector_remove_hint(struct spdk_jsonrpc_request *request,
				const struct spdk_json_val *params)
{
	struct rpc_redirector_remove_hint req = {NULL};
	struct redirector_config *config;
	struct spdk_json_write_ctx *w;
	int rc;

	if (spdk_json_decode_object(params, rpc_redirector_remove_hint_decoders,
				    SPDK_COUNTOF(rpc_redirector_remove_hint_decoders),
				    &req)) {
		SPDK_NOTICELOG("JSON decode failed\n");
		rc = -EINVAL;
		goto invalid;
	}

	/* SPDK_NOTICELOG("Looking for redirector %s\n", req.redirector_name); */
	config = vbdev_redirector_find_config(req.redirector_name);
	if (!config) {
		SPDK_NOTICELOG("Redirector %s not found\n", req.redirector_name);
		rc = -ENODEV;
		goto invalid;
	}

	/* Complete synchronously, and without waiting for the effects to be applied */
	rc = redirector_remove_hint(config, req.start_lba, req.blocks, req.target_name);
	if (0 != rc) {
		SPDK_NOTICELOG("Failed to remove hint (%"PRId64",%"PRId64":%s) from redirector %s\n",
			       req.start_lba, req.blocks, req.target_name, req.redirector_name);
		goto invalid;
	}
	SPDK_NOTICELOG("Removed hint (%"PRId64",%"PRId64":%s) from redirector %s\n",
		       req.start_lba, req.blocks, req.target_name, req.redirector_name);

	w = spdk_jsonrpc_begin_result(request);
	if (w == NULL) {
		free_rpc_redirector_remove_hint(&req);
		return;
	}

	spdk_json_write_bool(w, true);
	spdk_jsonrpc_end_result(request, w);
	free_rpc_redirector_remove_hint(&req);

	return;

invalid:
	free_rpc_redirector_remove_hint(&req);
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, spdk_strerror(-rc));
}
SPDK_RPC_REGISTER("redirector_remove_hint", spdk_rpc_redirector_remove_hint, SPDK_RPC_RUNTIME)

static void
rpc_redirector_add_hash_hint_destruct(struct rpc_redirector_add_hash_hint *req)
{
	free(req->redirector_name);
	free(req->hash_hint_file);
}

static const struct spdk_json_object_decoder rpc_redirector_add_hash_hint_decoders[] = {
	{"redirector", offsetof(struct rpc_redirector_add_hash_hint, redirector_name), spdk_json_decode_string},
	{"hash_hint_file", offsetof(struct rpc_redirector_add_hash_hint, hash_hint_file), spdk_json_decode_string},
	{"persistent_config", offsetof(struct rpc_redirector_add_hash_hint, persistent), spdk_json_decode_bool},
	{"authoritative", offsetof(struct rpc_redirector_add_hash_hint, authoritative), spdk_json_decode_bool},
};

static void
rpc_redirector_hash_hint_nqn_table_destruct(struct rpc_redirector_hash_hint_nqn_table *nqn_table)
{
	size_t nqn_index;

	for (nqn_index = 0;
	     nqn_index < nqn_table->num_nqns;
	     nqn_index++) {
		free(nqn_table->nqns[nqn_index]);
	}
}

struct rpc_redirector_hash_hint_nqn_table *
alloc_rpc_redirector_hash_hint_nqn_table(size_t num_nqns)
{
	struct rpc_redirector_hash_hint_nqn_table *nqn_table;

	nqn_table = calloc(1, sizeof(*nqn_table) + (num_nqns * sizeof(nqn_table->nqns[0])));
	if (!nqn_table) {
		SPDK_ERRLOG("Failed to allocate RPC NQN table\n");
		return NULL;
	}
	nqn_table->num_nqns = num_nqns;
	return nqn_table;
}

void
free_rpc_redirector_hash_hint_nqn_table(struct rpc_redirector_hash_hint_nqn_table *nqn_table)
{
	if (!nqn_table) { return; }
	rpc_redirector_hash_hint_nqn_table_destruct(nqn_table);
	free(nqn_table);
}

struct rpc_redirector_hash_hint_hash_table *
alloc_rpc_redirector_hash_hint_hash_table(size_t num_buckets)
{
	struct rpc_redirector_hash_hint_hash_table *hash_table;

	hash_table = calloc(1, sizeof(*hash_table) + (num_buckets * sizeof(hash_table->buckets[0])));
	if (!hash_table) {
		SPDK_ERRLOG("Failed to allocate RPC hash table\n");
		return NULL;
	}
	hash_table->num_buckets = num_buckets;
	return hash_table;
}

void
free_rpc_redirector_hash_hint_hash_table(struct rpc_redirector_hash_hint_hash_table *hash_table)
{
	if (!hash_table) { return; }
	rpc_redirector_hash_hint_hash_table_destruct(hash_table);
	free(hash_table);
}

static void
rpc_redirector_hash_hint_params_destruct(struct rpc_redirector_hash_hint_params *params)
{
	free(params->object_name_format);
	free(params->hash_fn);
	free_rpc_redirector_hash_hint_nqn_table(params->nqn_table);
	free_rpc_redirector_hash_hint_hash_table(params->hash_table);
}

static int
rpc_redirector_hash_hint_params_init(struct rpc_redirector_hash_hint_params *params)
{
	params->nqn_table = alloc_rpc_redirector_hash_hint_nqn_table(
				    REDIRECTOR_HASH_HINT_MAX_NQN_TABLE_SIZE);
	if (!params->nqn_table) {
		return -1;
	}

	params->hash_table = alloc_rpc_redirector_hash_hint_hash_table(
				     REDIRECTOR_HASH_HINT_MAX_HASH_TABLE_SIZE);
	if (!params->hash_table) {
		return -1;
	}

	params->nqn_table->num_nqns = 0;
	params->hash_table->num_buckets = 0;
	return 0;
}

static int
decode_hash_hint_label(const struct spdk_json_val *val, void *out)
{
	/* We don't need anything in the hash hint label */
	/*struct rpc_redirector_hash_hint_label_params *label = out; */
	return 0;
}

static int
decode_hash_hint_nqn_table(const struct spdk_json_val *val, void *out)
{
	struct rpc_redirector_hash_hint_nqn_table **nqn_table_pp = out;
	struct rpc_redirector_hash_hint_nqn_table *nqn_table = *nqn_table_pp;
	return spdk_json_decode_array(val, spdk_json_decode_string, nqn_table->nqns,
				      REDIRECTOR_HASH_HINT_MAX_NQN_TABLE_SIZE,
				      &nqn_table->num_nqns, sizeof(char *));
}

static int
decode_hash_hint_hash_table(const struct spdk_json_val *val, void *out)
{
	/* We don't need anything in the hash hint label */
	struct rpc_redirector_hash_hint_hash_table **hash_table_pp = out;
	struct rpc_redirector_hash_hint_hash_table *hash_table = *hash_table_pp;
	return spdk_json_decode_array(val, spdk_json_decode_uint16, hash_table->buckets,
				      REDIRECTOR_HASH_HINT_MAX_HASH_TABLE_SIZE,
				      &hash_table->num_buckets, sizeof(uint16_t));
}

static const struct spdk_json_object_decoder rpc_redirector_hash_hint_params_decoders[] = {
	{"label", offsetof(struct rpc_redirector_hash_hint_params, label), decode_hash_hint_label, true},
	{"ln_nguid", offsetof(struct rpc_redirector_hash_hint_params, ln_nguid), decode_spdk_uuid},
	{"ns_bytes", offsetof(struct rpc_redirector_hash_hint_params, ns_bytes), spdk_json_decode_uint64},
	{"object_bytes", offsetof(struct rpc_redirector_hash_hint_params, object_bytes), spdk_json_decode_uint64},
	{"object_name_format", offsetof(struct rpc_redirector_hash_hint_params, object_name_format), spdk_json_decode_string},
	{"hash_fn", offsetof(struct rpc_redirector_hash_hint_params, hash_fn), spdk_json_decode_string},
	{"nqn_table", offsetof(struct rpc_redirector_hash_hint_params, nqn_table), decode_hash_hint_nqn_table},
	{"hash_table", offsetof(struct rpc_redirector_hash_hint_params, hash_table), decode_hash_hint_hash_table},
};

static void *
read_file(const char *filename, size_t *size)
{
	FILE *file = fopen(filename, "r");
	void *data = NULL;
	long int rc = 0;

	if (file == NULL) {
		/* errno is set by fopen */
		return NULL;
	}

	rc = fseek(file, 0, SEEK_END);
	if (rc == 0) {
		rc = ftell(file);
		rewind(file);
	}

	if (rc != -1) {
		*size = rc;
		data = malloc(*size);
	}

	if (data != NULL) {
		rc = fread(data, 1, *size, file);
		if (rc != (long int)*size) {
			free(data);
			data = NULL;
			errno = EIO;
		}
	}

	fclose(file);
	return data;
}

/*
 * Adds/replaces a consistent hash location hint to this redirector, directing IO to groups of LBAs to targets
 * selected by a hash function from a target list. A redirector has at most one hash hint. The hash hint
 * applies to all LBAs, and conflicts with any other all-LBAs hint that already exists.
 *
 * Completes once this hint is in the redirector's configuration and applying it to the data path has begun, but
 * doesn't wait for it to be applied to the data path. IOs may be in flight (and new ones still dispatched) to
 * destinations other than what this hint specifies for a short time after this completes.
 */
static void
spdk_rpc_redirector_add_hash_hint(struct spdk_jsonrpc_request *request,
				  const struct spdk_json_val *params)
{
	struct rpc_redirector_add_hash_hint req = {NULL};
	struct spdk_json_val *values = NULL;
	void *json = NULL, *end;
	ssize_t values_cnt, rc;
	size_t json_size;
	struct rpc_redirector_hash_hint_params hint_params = {NULL};
	struct spdk_json_write_ctx *w;

	if (0 != rpc_redirector_hash_hint_params_init(&hint_params)) {
		rc = -errno;
		SPDK_NOTICELOG("Failed to init hash hint parameters struct for redirector %s\n",
			       req.redirector_name);
		goto invalid;
	}

	if (spdk_json_decode_object(params, rpc_redirector_add_hash_hint_decoders,
				    SPDK_COUNTOF(rpc_redirector_add_hash_hint_decoders),
				    &req)) {
		SPDK_NOTICELOG("JSON decode failed\n");
		rc = -EINVAL;
		goto invalid;
	}

	/* Parse hash hint JSON file */
	json = read_file(req.hash_hint_file, &json_size);
	if (!json) {
		rc = -errno;
		SPDK_NOTICELOG("Failed to parse hash hint parameters file %s for redirector %s\n",
			       req.hash_hint_file, req.redirector_name);
		goto invalid;
	}

	rc = spdk_json_parse(json, json_size, NULL, 0, &end,
			     SPDK_JSON_PARSE_FLAG_ALLOW_COMMENTS);
	if (rc < 0) {
		SPDK_NOTICELOG("Failed to parse hash hint parameters file %s for redirector %s\n",
			       req.hash_hint_file, req.redirector_name);
		goto invalid;
	}

	values_cnt = rc;
	values = calloc(values_cnt, sizeof(struct spdk_json_val));
	if (values == NULL) {
		rc = -ENOMEM;
		SPDK_NOTICELOG("Failed to parse hash hint parameters file %s for redirector %s\n",
			       req.hash_hint_file, req.redirector_name);
		goto invalid;
	}

	rc = spdk_json_parse(json, json_size, values, values_cnt, &end,
			     SPDK_JSON_PARSE_FLAG_ALLOW_COMMENTS);
	if (rc != values_cnt) {
		SPDK_NOTICELOG("Failed to parse hash hint parameters file %s for redirector %s\n",
			       req.hash_hint_file, req.redirector_name);
		goto invalid;
	}

	if (spdk_json_decode_object(values, rpc_redirector_hash_hint_params_decoders,
				    SPDK_COUNTOF(rpc_redirector_hash_hint_params_decoders),
				    &hint_params)) {
		SPDK_NOTICELOG("JSON decode of hash hint parameters file %s for redirector %s failed\n",
			       req.hash_hint_file, req.redirector_name);
		rc = -EINVAL;
		goto invalid;
	}

	/* Complete synchronously, and without waiting for the effects to be applied */
	rc = redirector_add_hash_hint_rpc(&req, &hint_params, true);
	if (0 != rc) {
		SPDK_NOTICELOG("Failed to add hash hint with parameters file %s to redirector %s\n",
			       req.hash_hint_file, req.redirector_name);
		goto invalid;
	}
	SPDK_NOTICELOG("Added%s hash hint with parameters file %s to redirector %s\n",
		       req.authoritative ? " (auth)" : "", req.hash_hint_file, req.redirector_name);

	w = spdk_jsonrpc_begin_result(request);
	if (w == NULL) {
		rpc_redirector_add_hash_hint_destruct(&req);
		return;
	}

	spdk_json_write_bool(w, true);
	spdk_jsonrpc_end_result(request, w);
	rpc_redirector_add_hash_hint_destruct(&req);
	rpc_redirector_hash_hint_params_destruct(&hint_params);
	free(json);
	free(values);

	return;

invalid:
	rpc_redirector_add_hash_hint_destruct(&req);
	rpc_redirector_hash_hint_params_destruct(&hint_params);
	free(json);
	free(values);
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, spdk_strerror(-rc));
}
SPDK_RPC_REGISTER("redirector_add_hash_hint", spdk_rpc_redirector_add_hash_hint, SPDK_RPC_RUNTIME)

static void
free_rpc_redirector_remove_hash_hint(struct rpc_redirector_remove_hash_hint *req)
{
	free(req->redirector_name);
}

static const struct spdk_json_object_decoder rpc_redirector_remove_hash_hint_decoders[] = {
	{"redirector", offsetof(struct rpc_redirector_remove_hash_hint, redirector_name), spdk_json_decode_string},
};

/*
 * Removes the consistent hash location hint from this redirector. There can only be one.
 *
 * Completes once the matching hints are removed from the redirector's configuration and applying the current
 * set of hints to the data path has begun, but doesn't wait for it to be applied to the data path. IOs may be
 * in flight (and new ones still dispatched) to destinations as specified in this hint for a short time after
 * this completes.
 */
static void
spdk_rpc_redirector_remove_hash_hint(struct spdk_jsonrpc_request *request,
				     const struct spdk_json_val *params)
{
	struct rpc_redirector_remove_hash_hint req = {NULL};
	struct redirector_config *config;
	struct spdk_json_write_ctx *w;
	int rc;

	if (spdk_json_decode_object(params, rpc_redirector_remove_hash_hint_decoders,
				    SPDK_COUNTOF(rpc_redirector_remove_hash_hint_decoders),
				    &req)) {
		SPDK_NOTICELOG("JSON decode failed\n");
		rc = -EINVAL;
		goto invalid;
	}

	/* SPDK_NOTICELOG("Looking for redirector %s\n", req.redirector_name); */
	config = vbdev_redirector_find_config(req.redirector_name);
	if (!config) {
		SPDK_NOTICELOG("Redirector %s not found\n", req.redirector_name);
		rc = -ENODEV;
		goto invalid;
	}

	/* Complete synchronously, and without waiting for the effects to be applied */
	rc = redirector_remove_hash_hint(config);
	if (0 != rc) {
		SPDK_NOTICELOG("Failed to remove hash hint from redirector %s\n", req.redirector_name);
		goto invalid;
	}
	SPDK_NOTICELOG("Removed hash hint from redirector %s\n", req.redirector_name);

	w = spdk_jsonrpc_begin_result(request);
	if (w == NULL) {
		free_rpc_redirector_remove_hash_hint(&req);
		return;
	}

	spdk_json_write_bool(w, true);
	spdk_jsonrpc_end_result(request, w);
	free_rpc_redirector_remove_hash_hint(&req);

	return;

invalid:
	free_rpc_redirector_remove_hash_hint(&req);
	spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS, spdk_strerror(-rc));
}
SPDK_RPC_REGISTER("redirector_remove_hash_hint", spdk_rpc_redirector_remove_hash_hint,
		  SPDK_RPC_RUNTIME)
