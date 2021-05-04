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

#ifndef SPDK_VBDEV_REDIRECTOR_DEBUG_H
#define SPDK_VBDEV_REDIRECTOR_DEBUG_H

/*
 * We control the conditional generation of redirector debug and debug logging code with these
 * macros These must each evaluate to a boolean constant at compile time. When used in an if
 * statement, the code for the enclosed clause shouldn't be generated at all.
 *
 * SPDK_DEBUGLOG will test the appropriate runtime debug enable flag and not evaluate any of the log
 * message format arguments (which may call functions, etc.) if it's not enabled, but the code for
 * this is still generated in the calling function.
 *
 * These macros don't allow enabling at runtime, but when disabled they emit no code (unless the
 * optimizer is not removing unreachable code). Unlike an ifdef, these get compiled whether they're
 * enabled or not. While those disabled clauses remain untested, they will at least compile when
 * they're next enabled (unlike rarely used ifdefs which can be silently broken by later
 * commits). Since the code in these disabled clauses is still compiled, it still refers to the
 * variables declared for it (unlike an ifdef, where you may need to ifdef the local variables used
 * by the ifdefed clause).
 *
 * Obviously these can be used to do more than enable a debug log message. They're used here to
 * enable some strategically placed asserts in debug builds that are inappropriate for a release
 * build. This is especially true for asserts on expressions too costly to leave in the release
 * build.
 */

/* Change to 1 to log during hint add/remove */
#define RD_DEBUG_LOG_HINTS 0

/* Change to 1 to log during update_locations */
#define RD_DEBUG_LOG_RULE_TABLE 0

/* Change to 1 to log during hint learning */
#define RD_DEBUG_LOG_HINT_LEARNING 0

/* Change to 1 to log things about target LBA translation */
#define RD_DEBUG_LOG_TARGET_TRANSLATION 0

/* Change to 1 to log things about target selection by NQN */
#define RD_DEBUG_LOG_NQN_TARGET 0

/* Change to 1 to log things about channel creation & state update */
#define RD_DEBUG_LOG_CHANNEL_STUFF 0

/* Change to 1 to log things about JSON output */
#define RD_DEBUG_LOG_JSON_STUFF 0

/* Change to 1 to log things about IO type translation and emulation */
#define RD_DEBUG_LOG_IO_TYPE_TRANSLATION 0

/* Change to 1 to enable asserts on IO alignment */
#define RD_IO_ALIGN_ASSERTS 0

/* Change to 1 to log hints during update_locations */
#define RD_DEBUG_LOG_NVME_HINTS 0

/* Change to 1 to log bdev self ref counting */
#define RD_DEBUG_LOG_BDEV_SELF_REF 0

#endif /* SPDK_VBDEV_REDIRECTOR_DEBUG_H */
