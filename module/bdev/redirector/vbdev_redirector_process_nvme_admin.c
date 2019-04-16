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
 * Process NVMe admin commands to this redirector. A redirector must
 * identify itself by NGUID and/or UUID to be recognized as a
 * redirector by other redirectors. It must also provide a location
 * hint log page (and some additional log pages if the consistent hash
 * hint is used). It should be able to identify itself by NQN to
 * enable redirectors to be connected directly via the bdev interface
 * (used extensively in testing, and potentially useful in some ADNN
 * systems).
 *
 * When connected to peers via MVMe-oF some of these admin commands
 * will be handled by the NVMF target.
 */

#include "spdk/stdinc.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_internal.h"
#include "vbdev_redirector_process_nvme_admin.h"
#include "vbdev_redirector_nvme_hints.h"
#include "vbdev_redirector.h"
#include "spdk/bdev.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/bdev_module.h"
#include "spdk/version.h"
#include "spdk_internal/log.h"

/* Returned for IDENTIFY_CTRLR, which only happens when redirectors connect
 * to each other using the bdev interface */
static union spdk_nvme_vs_register g_rd_ctrlr_ver = {};
static uint16_t g_rd_ctrlr_cntlid = 0;

#define RD_MN "SPDK redirector bdev"

/*
 * Report the SPDK version as the firmware revision.
 * SPDK_VERSION_STRING won't fit into FR (only 8 bytes), so try to fit the most important parts.
 */
#define RD_FW_VERSION SPDK_VERSION_MAJOR_STRING SPDK_VERSION_MINOR_STRING SPDK_VERSION_PATCH_STRING

/*
 * Redirector functions for handling incoming NVME_ADMIN commands
 *
 * This includes GET_LOG_PAGE for the location hint log page, and various IDENTIFY commands (some of which are only
 * used when redirectors are connected as bare bdevs, rather than via NVMF).
 */

static int
vbdev_redirector_process_get_redirector_log_page(struct spdk_io_channel *ch,
		struct spdk_bdev_io *bdev_io,
		void *log_page_buf, uint64_t log_page_size, const char *log_page_name)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct spdk_nvme_cmd *cmd = &bdev_io->u.nvme_passthru.cmd;
	uint64_t offset, len;
	uint32_t numdl, numdu;

	assert(bdev_io->u.nvme_passthru.buf);
	offset = (uint64_t)cmd->cdw12 | ((uint64_t)cmd->cdw13 << 32);
	assert(!(offset & 3));
	numdl = (cmd->cdw10 >> 16) & 0xFFFFu;
	numdu = (cmd->cdw11) & 0xFFFFu;
	len = ((numdu << 16) + numdl + (uint64_t)1) * 4;
	assert(len <= bdev_io->u.nvme_passthru.nbytes);
	if (offset > log_page_size) {
		SPDK_ERRLOG("offset (%" PRIu64 ") > %s page size (%" PRIu64 ")\n",
			    offset, log_page_name, log_page_size);
		goto invalid_field;
	}
	/* Adjust bytes copied to log page length */
	size_t bytes_copied = spdk_min(bdev_io->u.nvme_passthru.nbytes, log_page_size - offset);
	memcpy(bdev_io->u.nvme_passthru.buf, log_page_buf + offset, bytes_copied);
	/* Zero any remaining buffer */
	if (bytes_copied < bdev_io->u.nvme_passthru.nbytes) {
		memset(bdev_io->u.nvme_passthru.buf + bytes_copied, 0,
		       bdev_io->u.nvme_passthru.nbytes - bytes_copied);
	}
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR, "Redirector %s %s page size %" PRIu64 "\n",
		      rd_node->config->redirector_name, log_page_name, log_page_size);
	vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	return 0;

invalid_field:
	bdev_io->internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
	bdev_io->internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FIELD;
	return SPDK_BDEV_IO_STATUS_NVME_ERROR;
}

static bool
vbdev_redirector_has_location_hint_log_page(struct spdk_io_channel *ch)
{
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);

	return (NULL != rd_ch->hint_log_page);
}

static int
vbdev_redirector_process_get_location_hint_log_page(struct spdk_io_channel *ch,
		struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);

	return vbdev_redirector_process_get_redirector_log_page(ch, bdev_io,
			(void *)rd_ch->hint_log_page,
			rd_ch_get_hint_log_page_size(rd_ch),
			"hint");
}

static bool
vbdev_redirector_has_nqn_list_log_page(struct spdk_io_channel *ch)
{
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);

	return (NULL != rd_ch->nqn_list_log_page);
}

static int
vbdev_redirector_process_get_nqn_list_log_page(struct spdk_io_channel *ch,
		struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);

	return vbdev_redirector_process_get_redirector_log_page(ch, bdev_io,
			(void *)rd_ch->nqn_list_log_page,
			rd_ch_get_nqn_list_log_page_size(rd_ch),
			"nqn list");
}

static bool
vbdev_redirector_has_hash_table_log_page(struct spdk_io_channel *ch)
{
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);

	return (NULL != rd_ch->hash_table_log_page);
}

static int
vbdev_redirector_process_get_hash_table_log_page(struct spdk_io_channel *ch,
		struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev_io_channel *rd_ch = spdk_io_channel_get_ctx(ch);

	return vbdev_redirector_process_get_redirector_log_page(ch, bdev_io,
			(void *)rd_ch->hash_table_log_page,
			rd_ch_get_hash_table_log_page_size(rd_ch),
			"hash table");
}

static int
vbdev_redirector_process_get_log_page(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct spdk_nvme_cmd *cmd = &bdev_io->u.nvme_passthru.cmd;
	uint64_t offset, len;
	uint32_t numdl, numdu;
	uint8_t lid;

	assert(bdev_io->u.nvme_passthru.buf);
	offset = (uint64_t)cmd->cdw12 | ((uint64_t)cmd->cdw13 << 32);
	if (offset & 3) {
		SPDK_ERRLOG("Invalid log page offset 0x%" PRIx64 "\n", offset);
		bdev_io->internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
		bdev_io->internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FIELD;
		return SPDK_BDEV_IO_STATUS_NVME_ERROR;
	}

	numdl = (cmd->cdw10 >> 16) & 0xFFFFu;
	numdu = (cmd->cdw11) & 0xFFFFu;
	len = ((numdu << 16) + numdl + (uint64_t)1) * 4;
	if (len > bdev_io->u.nvme_passthru.nbytes) {
		SPDK_ERRLOG("Get log page: len (%" PRIu64 ") > buf size (%zu)\n",
			    len, bdev_io->u.nvme_passthru.nbytes);
		bdev_io->internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
		bdev_io->internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FIELD;
		return SPDK_BDEV_IO_STATUS_NVME_ERROR;
	}

	lid = cmd->cdw10 & 0xFF;
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s get log page: LID=0x%02X offset=0x%" PRIx64 " len=0x%" PRIx64 "\n",
		      rd_node->config->redirector_name, lid, offset, len);

	switch (lid) {
	case SPDK_NVME_LOG_ERROR:
	case SPDK_NVME_LOG_HEALTH_INFORMATION:
	case SPDK_NVME_LOG_FIRMWARE_SLOT:
	case SPDK_NVME_LOG_COMMAND_EFFECTS_LOG:
	case SPDK_NVME_LOG_CHANGED_NS_LIST:
	case SPDK_NVME_LOG_RESERVATION_NOTIFICATION:
		vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
		return 0;
	case RD_LOCATION_HINT_LOG_PAGE:
		if (!vbdev_redirector_has_location_hint_log_page(ch)) {
			goto invalid_log_page;
		}
		return vbdev_redirector_process_get_location_hint_log_page(ch, bdev_io);
	case RD_NQN_LIST_LOG_PAGE:
		if (!vbdev_redirector_has_nqn_list_log_page(ch)) {
			goto invalid_log_page;
		}
		return vbdev_redirector_process_get_nqn_list_log_page(ch, bdev_io);
	case RD_HASH_HINT_HASH_TABLE_LOG_PAGE:
		if (!vbdev_redirector_has_hash_table_log_page(ch)) {
			goto invalid_log_page;
		}
		return vbdev_redirector_process_get_hash_table_log_page(ch, bdev_io);
	default:
		goto invalid_log_page;
	}

invalid_log_page:
	SPDK_ERRLOG("Unsupported Get Log Page 0x%02X\n", lid);
	bdev_io->internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
	bdev_io->internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FIELD;
	return SPDK_BDEV_IO_STATUS_NVME_ERROR;
}

static int
vbdev_redirector_process_identify_ns(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct spdk_nvme_ns_data *nsdata = bdev_io->u.nvme_passthru.buf;
	uint64_t num_blocks;

	assert(bdev_io->u.nvme_passthru.buf);
	assert(sizeof(*nsdata) <= bdev_io->u.nvme_passthru.nbytes);
	memset(bdev_io->u.nvme_passthru.buf, 0, bdev_io->u.nvme_passthru.nbytes);

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s identify namespace\n",
		      rd_node->config->redirector_name);

	num_blocks = rd_node->redirector_bdev.blockcnt;

	nsdata->nsze = num_blocks;
	nsdata->ncap = num_blocks;
	nsdata->nuse = num_blocks;
	nsdata->nlbaf = 0;
	nsdata->flbas.format = 0;
	nsdata->lbaf[0].ms = 0;
	nsdata->lbaf[0].lbads = spdk_u32log2(rd_node->redirector_bdev.blocklen);
	nsdata->noiob = rd_node->redirector_bdev.optimal_io_boundary;
	nsdata->nmic.can_share = 1;

	memcpy(&nsdata->nguid, &rd_node->redirector_bdev.uuid, sizeof(nsdata->nguid));

	vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	return 0;
}

static int
vbdev_redirector_process_identify_ns_descriptor_list(struct spdk_io_channel *ch,
		struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct spdk_nvme_ns_id_desc *desc = bdev_io->u.nvme_passthru.buf;

	assert(bdev_io->u.nvme_passthru.buf);
	assert(sizeof(*desc) <= bdev_io->u.nvme_passthru.nbytes);
	memset(bdev_io->u.nvme_passthru.buf, 0, bdev_io->u.nvme_passthru.nbytes);

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s identify namespace descriptor list\n",
		      rd_node->config->redirector_name);

	desc->nidt = SPDK_NVME_NIDT_UUID;
	desc->nidl = sizeof(rd_node->redirector_bdev.uuid);
	memcpy(&desc->nid, &rd_node->redirector_bdev.uuid, sizeof(rd_node->redirector_bdev.uuid));

	vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	return 0;
}

/* The whole reason the redirector responds to IDENTIFY_CTRLR at all
 * is to return this redirectors nqn string (if known) to an upstream
 * redirector connected to it via the local bdev interface. */
static int
vbdev_redirector_process_identify_ctrlr(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct spdk_nvme_ctrlr_data *cdata = bdev_io->u.nvme_passthru.buf;

	assert(bdev_io->u.nvme_passthru.buf);
	assert(sizeof(*cdata) <= bdev_io->u.nvme_passthru.nbytes);
	memset(bdev_io->u.nvme_passthru.buf, 0, bdev_io->u.nvme_passthru.nbytes);

	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s identify controller\n",
		      rd_node->config->redirector_name);

	spdk_strcpy_pad(cdata->mn, RD_MN, sizeof(cdata->mn), ' ');
	spdk_strcpy_pad(cdata->fr, RD_FW_VERSION, sizeof(cdata->fr), ' ');
	cdata->mdts = spdk_u32log2(rd_node->config->optimal_io_boundary / 4096);
	cdata->cntlid = g_rd_ctrlr_cntlid;
	cdata->ver = g_rd_ctrlr_ver;
	cdata->lpa.edlp = 1;
	cdata->elpe = 127;
	cdata->maxcmd = REDIRECTOR_NORMAL_TARGET_QD;
	cdata->sgls.supported = 1;
	cdata->sgls.keyed_sgl = 1;
	cdata->sgls.sgl_offset = 1;
	if (rd_node->config->nqn) {
		spdk_strcpy_pad(cdata->subnqn, rd_node->config->nqn, sizeof(cdata->subnqn), '\0');
	}

	vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	return 0;
}

static int
vbdev_redirector_process_identify(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct spdk_nvme_cmd *cmd = &bdev_io->u.nvme_passthru.cmd;
	uint8_t cns;

	assert(bdev_io->u.nvme_passthru.buf);

	cns = cmd->cdw10 & 0xFF;

	switch (cns) {
	case SPDK_NVME_IDENTIFY_NS:
		return vbdev_redirector_process_identify_ns(ch, bdev_io);
	case SPDK_NVME_IDENTIFY_NS_ID_DESCRIPTOR_LIST:
		return vbdev_redirector_process_identify_ns_descriptor_list(ch, bdev_io);
	case SPDK_NVME_IDENTIFY_CTRLR:
		return vbdev_redirector_process_identify_ctrlr(ch, bdev_io);
	case SPDK_NVME_IDENTIFY_ACTIVE_NS_LIST:
	default:
		goto invalid_cns;
	}

invalid_cns:
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s identify command with unsupported CNS 0x%02x\n",
		      rd_node->config->redirector_name, cns);
	bdev_io->internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
	bdev_io->internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FIELD;
	return SPDK_BDEV_IO_STATUS_NVME_ERROR;
}

int
vbdev_redirector_process_nvme_admin_cmd(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct redirector_bdev *rd_node = SPDK_CONTAINEROF(bdev_io->bdev, struct redirector_bdev,
					  redirector_bdev);
	struct spdk_nvme_cmd *cmd = &bdev_io->u.nvme_passthru.cmd;

	if (bdev_io->u.nvme_passthru.buf == NULL) {
		SPDK_ERRLOG("get log command with no buffer\n");
		bdev_io->internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
		bdev_io->internal.error.nvme.sc = SPDK_NVME_SC_INVALID_FIELD;
		return SPDK_BDEV_IO_STATUS_NVME_ERROR;
	}

	switch (cmd->opc) {
	case SPDK_NVME_OPC_GET_LOG_PAGE:
		return vbdev_redirector_process_get_log_page(ch, bdev_io);
	case SPDK_NVME_OPC_IDENTIFY:
		return vbdev_redirector_process_identify(ch, bdev_io);
	case SPDK_NVME_OPC_ABORT:
	case SPDK_NVME_OPC_GET_FEATURES:
	case SPDK_NVME_OPC_SET_FEATURES:
	case SPDK_NVME_OPC_ASYNC_EVENT_REQUEST:
	case SPDK_NVME_OPC_KEEP_ALIVE:
		goto empty_success;

	case SPDK_NVME_OPC_CREATE_IO_SQ:
	case SPDK_NVME_OPC_CREATE_IO_CQ:
	case SPDK_NVME_OPC_DELETE_IO_SQ:
	case SPDK_NVME_OPC_DELETE_IO_CQ:
		/* Create and Delete I/O CQ/SQ not allowed in NVMe-oF */
		goto invalid_opcode;

	default:
		goto invalid_opcode;
	}

invalid_opcode:
	SPDK_ERRLOG("Unsupported admin opcode 0x%x\n", cmd->opc);
	bdev_io->internal.error.nvme.sct = SPDK_NVME_SCT_GENERIC;
	bdev_io->internal.error.nvme.sc = SPDK_NVME_SC_INVALID_OPCODE;
	return SPDK_BDEV_IO_STATUS_NVME_ERROR;

empty_success:
	SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
		      "Redirector %s no-op NVME admin command ch=%p bdev_io=%p opc=%d\n",
		      rd_node->config->redirector_name, ch, bdev_io, cmd->opc);
	vbdev_redirector_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
	return 0;
}
