/* $OpenBSD: tlstree.h,v 1.4 2019/11/21 20:02:20 tim Exp $ */
/* Copyright (c) 2020, Dmitry Baryshkov
 *
 * Sponsored by ROSA Linux
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/kdftree.h>
#include "kdftree_locl.h"
#include <string.h>

#define ll2c(l,c)	(*((c)++)=(unsigned char)(((l)>>56)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>48)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>40)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)    )&0xff))

#define c2ll(c,l)	(l =((uint64_t)(*((c)++)))    , \
			 l|=((uint64_t)(*((c)++)))<< 8, \
			 l|=((uint64_t)(*((c)++)))<<16, \
			 l|=((uint64_t)(*((c)++)))<<24, \
			 l|=((uint64_t)(*((c)++)))<<32, \
			 l|=((uint64_t)(*((c)++)))<<40, \
			 l|=((uint64_t)(*((c)++)))<<48, \
			 l|=((uint64_t)(*((c)++)))<<56)

#define TLSTREE_L1 ((const unsigned char *)"level1")
#define TLSTREE_L2 ((const unsigned char *)"level2")
#define TLSTREE_L3 ((const unsigned char *)"level3")
#define TLSTREE_L_LENGTH 6

#define TLSTREE_KEY_LENGTH 32

struct TLSTREE_CTX_st {
	uint64_t seq;
	const TLSTREE_CONST *tlsconst;
	HMAC_CTX ctx1, ctx2, ctx3;
	unsigned char current[TLSTREE_KEY_LENGTH];
};

TLSTREE_CTX *
TLSTREE_CTX_new(void)
{
	TLSTREE_CTX *ctx;

	ctx = malloc(sizeof(TLSTREE_CTX));
	if (!ctx)
		return NULL;

	HMAC_CTX_init(&ctx->ctx1);
	HMAC_CTX_init(&ctx->ctx2);
	HMAC_CTX_init(&ctx->ctx3);
	ctx->tlsconst = NULL;

	return ctx;
}

void
TLSTREE_CTX_free(TLSTREE_CTX *ctx)
{
	if (ctx == NULL)
		return;

	HMAC_CTX_cleanup(&ctx->ctx1);
	HMAC_CTX_cleanup(&ctx->ctx2);
	HMAC_CTX_cleanup(&ctx->ctx3);
}

static int tlstree_one(HMAC_CTX *ctx, const unsigned char *label, uint64_t seq, unsigned char *out)
{
	unsigned char seed[8], *p = seed;
	static const unsigned char data1[1] = { 0x01 };
	static const unsigned char data2[2] = { 0x01, 0x00 };
	int dummy = TLSTREE_KEY_LENGTH;

	ll2c(seq, p);
	return kdf_tree_block(ctx, data1, 1, label, TLSTREE_L_LENGTH, seed, 8, data2, 2, out, &dummy);
}

int
TLSTREE_Init(TLSTREE_CTX *ctx,
		const TLSTREE_CONST *tlsconst,
		const EVP_MD *md, ENGINE *impl,
		const unsigned char *key,
		int key_length)
{
	unsigned char tmp[TLSTREE_KEY_LENGTH];

	/* Support only reasonable cases, which allow simplification of KDF_TREE calls */
	if (key_length != EVP_MD_size(md) ||
	    key_length != TLSTREE_KEY_LENGTH)
		return 0;

	if (!ctx || !tlsconst || !md || !key)
		return 0;

	ctx->tlsconst = tlsconst;
	ctx->seq = 0;

	if (!HMAC_Init_ex(&ctx->ctx1, key, TLSTREE_KEY_LENGTH, md, impl) ||
	    !tlstree_one(&ctx->ctx1, TLSTREE_L1, 0, tmp) ||
	    !HMAC_Init_ex(&ctx->ctx2, tmp, TLSTREE_KEY_LENGTH, md, impl) ||
	    !tlstree_one(&ctx->ctx2, TLSTREE_L2, 0, tmp) ||
	    !HMAC_Init_ex(&ctx->ctx3, tmp, TLSTREE_KEY_LENGTH, md, impl) ||
	    !tlstree_one(&ctx->ctx3, TLSTREE_L3, 0, ctx->current))
		return 0;

	return 1;
}

int
TLSTREE_GET(TLSTREE_CTX *ctx,
		unsigned char *seq,
		unsigned char *out)
{
	uint64_t s;
	unsigned char *p = seq;
	unsigned char tmp[TLSTREE_KEY_LENGTH];

	c2ll(p, s);

	if ((s & ctx->tlsconst->c1) != (ctx->seq & ctx->tlsconst->c1)) {
		if (!tlstree_one(&ctx->ctx1, TLSTREE_L1, 0, tmp) ||
		    !HMAC_Init_ex(&ctx->ctx2, tmp, TLSTREE_KEY_LENGTH, NULL, NULL))
			return 0;
	}
	if ((s & ctx->tlsconst->c2) != (ctx->seq & ctx->tlsconst->c2)) {
		if (!tlstree_one(&ctx->ctx2, TLSTREE_L2, 0, tmp) ||
		    !HMAC_Init_ex(&ctx->ctx3, tmp, TLSTREE_KEY_LENGTH, NULL, NULL))
			return 0;
	}
	if ((s & ctx->tlsconst->c3) != (ctx->seq & ctx->tlsconst->c3)) {
		if (!tlstree_one(&ctx->ctx3, TLSTREE_L3, 0, ctx->current))
			return 0;
	}

	memcpy(out, ctx->current, TLSTREE_KEY_LENGTH);

	return 1;
}
