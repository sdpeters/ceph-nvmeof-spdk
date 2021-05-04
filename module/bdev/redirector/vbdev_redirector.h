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

#ifndef SPDK_VBDEV_REDIRECTOR_H
#define SPDK_VBDEV_REDIRECTOR_H

#include "spdk/bdev_module.h"

#define REDIRECTOR_MAX_TARGET_BDEVS 255
#define REDIRECTOR_HASH_HINT_MAX_NQN_TABLE_SIZE REDIRECTOR_MAX_TARGET_BDEVS
#define REDIRECTOR_HASH_HINT_MAX_HASH_TABLE_SIZE (1024 * 1024)

#define RD_LOCATION_HINT_LOG_PAGE (SPDK_NVME_LOG_VENDOR_SPECIFIC_START + 1)
#define RD_NQN_LIST_LOG_PAGE (SPDK_NVME_LOG_VENDOR_SPECIFIC_START + 2)
#define RD_HASH_HINT_HASH_TABLE_LOG_PAGE (SPDK_NVME_LOG_VENDOR_SPECIFIC_START + 3)

/*
 * RE: {NORMAL,MAC}_TARGET_QD
 *
 * The idea here is to limit IOs in flight to default or suboptimal targets to something on the low side, but
 * allow as many in flight as the transport allows to the best target. The rationale is that once we've sent
 * an IO to a non-optimal target we have to wait for it to complete even if we discover the optimal target
 * (via a location hint) before then. So, since default targets may be slow anyway, we accept the throttling
 * of IO to them for the opportunity to reroute these queued IOs to the better target while they're queued for
 * the default target.
 *
 * The plan is to use REDIRECTOR_NORMAL_TARGET_QD to each target by default. In LBA regions covered by hints
 * naming a target, we'll use REDIRECTOR_MAX_TARGET_QD.
 *
 * The actual target QD can't be any larger than what the transport allows. The redirector should queue IOs in
 * excess of that itself rather than allowing the transport to do it, for the same reason as the default
 * target case (queued IOs can be rerouted to subsequently appearing targets with higher QDs, but IOs in
 * flight to a target cannot).
 *
 * Ultimately we may want location hints to be able to specify a target QD. This would enable a DVM to
 * throttle traffic to specific targets by LN.
 *
 * Currently the channel rule and target table treats all LBAs that map to any target the same. Until this
 * gains the ability to apply different QDs to the same target based on the hint (or lack thereof) mapping
 * that LBA to that target, we can't really do this.
 */
//#define REDIRECTOR_NORMAL_TARGET_QD 16
#define REDIRECTOR_NORMAL_TARGET_QD REDIRECTOR_MAX_TARGET_QD
#define REDIRECTOR_MAX_TARGET_QD ((1024 * 64)-1)

#endif /* SPDK_VBDEV_REDIRECTOR_H */
