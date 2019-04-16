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
 *
 *   This file incorporates work covered by the following copyright and
 *   permission notice:
 *
 *   Files: src/include/ceph_hash.cc
 *   Copyright: None
 *   License: Public domain
 *
 *   Files: src/include/rados.h, except ceph_stable_mod(), which is public domain
 *   Copyright: the authors
 *   License: LGPL-2.1 or LGPL-3 (see COPYING-LGPL2.1 and COPYING-LGPL3)
 */

#include "spdk/stdinc.h"
#include "spdk/likely.h"

#include "vbdev_redirector_types.h"
#include "vbdev_redirector_ceph_hash.h"
#include "spdk_internal/log.h"

/* The rjenkins hash is from Ceph in src/common/ceph_hash.cc, and is public domain. */

/*
 * Robert Jenkins' function for mixing 32-bit values
 * http://burtleburtle.net/bob/hash/evahash.html
 * a, b = random bits, c = input and output
 */
#define mix(a, b, c) do {			\
		a = a-b;  a = a-c;  a = a^(c>>13);	\
		b = b-c;  b = b-a;  b = b^(a<<8);	\
		c = c-a;  c = c-b;  c = c^(b>>13);	\
		a = a-b;  a = a-c;  a = a^(c>>12);	\
		b = b-c;  b = b-a;  b = b^(a<<16);	\
		c = c-a;  c = c-b;  c = c^(b>>5);	\
		a = a-b;  a = a-c;  a = a^(c>>3);	\
		b = b-c;  b = b-a;  b = b^(a<<10);	\
		c = c-a;  c = c-b;  c = c^(b>>15);	\
	} while (0)

static uint32_t ceph_str_hash_rjenkins(const char *str, unsigned length)
{
	const unsigned char *k = (const unsigned char *)str;
	uint32_t a, b, c;  /* the internal state */
	uint32_t len;      /* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = 0x9e3779b9;      /* the golden ratio; an arbitrary value */
	b = a;
	c = 0;               /* variable initialization of internal state */

	/* handle most of the key */
	while (len >= 12) {
		a = a + (k[0] + ((uint32_t)k[1] << 8) + ((uint32_t)k[2] << 16) +
			 ((uint32_t)k[3] << 24));
		b = b + (k[4] + ((uint32_t)k[5] << 8) + ((uint32_t)k[6] << 16) +
			 ((uint32_t)k[7] << 24));
		c = c + (k[8] + ((uint32_t)k[9] << 8) + ((uint32_t)k[10] << 16) +
			 ((uint32_t)k[11] << 24));
		mix(a, b, c);
		k = k + 12;
		len = len - 12;
	}

	/* handle the last 11 bytes */
	c = c + length;
	switch (len) {            /* all the case statements fall through */
	case 11:
		c = c + ((uint32_t)k[10] << 24);
	// fall through
	case 10:
		c = c + ((uint32_t)k[9] << 16);
	// fall through
	case 9:
		c = c + ((uint32_t)k[8] << 8);
	/* the first byte of c is reserved for the length */
	// fall through
	case 8:
		b = b + ((uint32_t)k[7] << 24);
	// fall through
	case 7:
		b = b + ((uint32_t)k[6] << 16);
	// fall through
	case 6:
		b = b + ((uint32_t)k[5] << 8);
	// fall through
	case 5:
		b = b + k[4];
	// fall through
	case 4:
		a = a + ((uint32_t)k[3] << 24);
	// fall through
	case 3:
		a = a + ((uint32_t)k[2] << 16);
	// fall through
	case 2:
		a = a + ((uint32_t)k[1] << 8);
	// fall through
	case 1:
		a = a + k[0];
		/* case 0: nothing left to add */
		// fall through
	}
	mix(a, b, c);

	return c;
}

/*
 * This is the function Ceph uses to map an object name hash to a PG (hash table bucket)
 *
 * The ceph_stable_mod() function (from src/include/rados.h) is public domain as of
 * 6 October 2020, commit fa5d9f8846e63cfdfbb9767bd60966451375fb73
 */
static inline uint64_t ceph_stable_mod(uint64_t x, uint64_t b, uint64_t bmask)
{
	if ((x & bmask) < b) {
		return x & bmask;
	} else {
		return x & (bmask >> 1);
	}
}

static inline uint64_t bucket_number_mask(uint64_t num_buckets)
{
	return (1 << (spdk_u64log2(num_buckets - 1) + 1)) - 1;
}

#define RD_MAX_OBJECT_NAME_LEN 255

int vbdev_redirector_get_ceph_hash_bucket_for_object(struct redirector_bdev *rd_node,
		const struct location_hint *hint,
		const uint64_t object_number,
		uint64_t *bucket_number)
{
	char object_name[RD_MAX_OBJECT_NAME_LEN];
	uint32_t object_name_hash;
	int rc;

	rc = snprintf(object_name, sizeof(object_name), hint->hash.object_name_format, object_number);
	if (spdk_unlikely((rc < 0) || (rc >= (int)sizeof(object_name)))) {
		SPDK_DEBUGLOG(SPDK_LOG_VBDEV_REDIRECTOR,
			      "Redirector %s snprintf(\"%s\", %016lx) failed (%d)\n",
			      rd_node->config->redirector_name,
			      hint->hash.object_name_format, object_number, rc);
		return -1;
	}
	object_name_hash = ceph_str_hash_rjenkins(object_name, strlen(object_name));
	*bucket_number = ceph_stable_mod(object_name_hash,
					 hint->hash.hash_table->num_buckets,
					 bucket_number_mask(hint->hash.hash_table->num_buckets));
	return 0;
}
