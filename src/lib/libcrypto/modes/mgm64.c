/* $OpenBSD: mgm64.c,v 1.22 2018/01/24 23:03:37 kettenis Exp $ */
/*
 * Copyright (c) 2020 Dmitry Baryshkov <dbaryshkov@gmail.com>
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

#include <string.h>
#include <machine/endian.h>

#include <openssl/crypto.h>
#include "modes_lcl.h"

#define MGM64_BLOCK_SIZE 8
#define MGM64_POLYNOMIAL U64(0x1b)

static u64
mgm64_gf_shift (const u64 x)
{
  long mask;

  /* Shift uses big-endian representation. */
#if BYTE_ORDER != LITTLE_ENDIAN
  mask = - ((x >> 63) & 1);
  return (x << 1) ^ (mask & (MGM64_POLYNOMIAL));
#else /* ! WORDS_BIGENDIAN */
#define RSHIFT_WORD(x) \
  ((((x) & UINT64_C(0x7f7f7f7f7f7f7f7f)) << 1) \
   | (((x) & UINT64_C(0x8080808080808000)) >> 15))
  mask = - ((x >> 7) & 1);
  return RSHIFT_WORD(x) ^ (mask & (MGM64_POLYNOMIAL << 56));
# undef RSHIFT_WORD
#endif /* ! WORDS_BIGENDIAN */
}

static void
mgm64_gf_mul_sum(MGM64_CONTEXT *ctx, u64 x, const uint8_t *y)
{
	u64 V, Z;
	unsigned i;

	V = x;
	Z = 0;

	for (i = 0; i < MGM64_BLOCK_SIZE; i++)
	{
		uint8_t b = y[MGM64_BLOCK_SIZE - i - 1];
		unsigned j;
		for (j = 0; j < 8; j++, b >>= 1)
		{
			if (b & 1) {
				Z ^= V;
			}

			V = mgm64_gf_shift(V);
		}
	}

	ctx->sum ^= Z;
}

static inline void mgm64_inc(unsigned char *counter, u32 n)
{
	u8  c;

	do {
		--n;
		c = counter[n];
		++c;
		counter[n] = c;
		if (c) return;
	} while (n);
}

void mgm64_hash_block(MGM64_CONTEXT *ctx, const u8 *data)
{
	union {u64 u; u8 c[MGM64_BLOCK_SIZE]; } tmp;

	(*ctx->block)(ctx->z, tmp.c, ctx->key);
	mgm64_gf_mul_sum(ctx, tmp.u, data);
	mgm64_inc(ctx->z, MGM64_BLOCK_SIZE / 2);
}

void CRYPTO_mgm64_init(MGM64_CONTEXT *ctx, void *key, block64_f block)
{
	memset(ctx,0,sizeof(*ctx));
	ctx->block = block;
	ctx->key   = key;
}

void CRYPTO_mgm64_setiv(MGM64_CONTEXT *ctx, const unsigned char *iv)
{
	memcpy(ctx->y, iv, MGM64_NONCE_LEN);
	memcpy(ctx->z, iv, MGM64_NONCE_LEN);

	ctx->y[0] &= 0x7f;
	ctx->z[0] |= 0x80;

	(*ctx->block)(ctx->y, ctx->y, ctx->key);
	(*ctx->block)(ctx->z, ctx->z, ctx->key);

	ctx->sum = 0;
	memset(ctx->len, 0, MGM64_BLOCK_SIZE);
}

int CRYPTO_mgm64_aad(MGM64_CONTEXT *ctx, const unsigned char *aad,
			size_t len)
{
	unsigned int n;

	if (ctx->len[1])
		return -2;

	ctx->len[0] += len * 8;

	n = ctx->a_remain;
	if (n) {
		while (n && len) {
			ctx->part[n] = *(aad++);
			--len;
			n = (n + 1) % MGM64_BLOCK_SIZE;
		}
		if (n == 0) {
			mgm64_hash_block(ctx, ctx->part);
		} else {
			ctx->a_remain = n;
			return 0;
		}
	}

	while (len >= MGM64_BLOCK_SIZE) {
		mgm64_hash_block(ctx, aad);
		aad += MGM64_BLOCK_SIZE;
		len -= MGM64_BLOCK_SIZE;
	}

	if (len)
		memcpy(ctx->part, aad, len);

	ctx->a_remain = len;
	return 0;
}

int CRYPTO_mgm64_encrypt(MGM64_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	unsigned int n;

	/* Handle AAD remainder */
	if (ctx->a_remain) {
		memset(ctx->part + ctx->a_remain, 0, MGM64_BLOCK_SIZE - ctx->a_remain);
		mgm64_hash_block(ctx, ctx->part);
		ctx->a_remain = 0;
	}

	ctx->len[1] += len * 8;

	n = ctx->d_remain;
	if (n) {
		while (n && len) {
			ctx->part[n] ^= *(in++);
			*(out++) = ctx->part[n];
			--len;
			n = (n + 1) % MGM64_BLOCK_SIZE;
		}
		if (n == 0) {
			mgm64_hash_block(ctx, ctx->part);
		} else {
			ctx->d_remain = n;
			return 0;
		}
	}

	while (len >= MGM64_BLOCK_SIZE) {
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm64_inc(ctx->y + MGM64_BLOCK_SIZE / 2, MGM64_BLOCK_SIZE / 2);
		for (n = 0; n < MGM64_BLOCK_SIZE; n++) {
			out[n] = ctx->part[n] ^ in[n];
		}
		mgm64_hash_block(ctx, out);
		in += MGM64_BLOCK_SIZE;
		out += MGM64_BLOCK_SIZE;
		len -= MGM64_BLOCK_SIZE;
	}

	if (len) {
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm64_inc(ctx->y + MGM64_BLOCK_SIZE / 2, MGM64_BLOCK_SIZE / 2);
		for (n = 0; n < len; n++) {
			ctx->part[n] ^= *(in++);
			*(out++) = ctx->part[n];
		}
	}

	ctx->d_remain = len;

	return 0;
}

int CRYPTO_mgm64_decrypt(MGM64_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	unsigned int n;

	/* Handle AAD remainder */
	if (ctx->a_remain) {
		memset(ctx->part + ctx->a_remain, 0, MGM64_BLOCK_SIZE - ctx->a_remain);
		mgm64_hash_block(ctx, ctx->part);
		ctx->a_remain = 0;
	}

	ctx->len[1] += len * 8;

	n = ctx->d_remain;
	if (n) {
		while (n && len) {
			u8 tmp = *(in++);
			*(out++) = ctx->part[n] ^ tmp;
			ctx->part[n] = tmp;
			n = (n + 1) % MGM64_BLOCK_SIZE;
		}
		if (n == 0) {
			mgm64_hash_block(ctx, ctx->part);
		} else {
			ctx->d_remain = n;
			return 0;
		}
	}

	while (len >= MGM64_BLOCK_SIZE) {
		mgm64_hash_block(ctx, in);
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm64_inc(ctx->y + MGM64_BLOCK_SIZE / 2, MGM64_BLOCK_SIZE / 2);
		for (n = 0; n < MGM64_BLOCK_SIZE; n++) {
			out[n] = ctx->part[n] ^ in[n];
		}
		in += MGM64_BLOCK_SIZE;
		out += MGM64_BLOCK_SIZE;
		len -= MGM64_BLOCK_SIZE;
	}

	if (len) {
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm64_inc(ctx->y + MGM64_BLOCK_SIZE / 2, MGM64_BLOCK_SIZE / 2);
		for (n = 0; n < len; n++) {
			u8 tmp = *(in++);
			*(out++) = ctx->part[n] ^ tmp;
			ctx->part[n] = tmp;
		}
	}

	ctx->d_remain = len;

	return 0;
}

int CRYPTO_mgm64_finish(MGM64_CONTEXT *ctx,const unsigned char *tag,
			size_t len)
{
	/* Handle AAD and data remainder */
	if (ctx->a_remain) {
		memset(ctx->part + ctx->a_remain, 0, MGM64_BLOCK_SIZE - ctx->a_remain);
		mgm64_hash_block(ctx, ctx->part);
	}

	if (ctx->d_remain) {
		memset(ctx->part + ctx->d_remain, 0, MGM64_BLOCK_SIZE - ctx->d_remain);
		mgm64_hash_block(ctx, ctx->part);
	}

#if BYTE_ORDER == LITTLE_ENDIAN
#ifdef BSWAP4
	ctx->len[0] = BSWAP4(ctx->len[0]);
	ctx->len[1] = BSWAP4(ctx->len[1]);
#else
	ctx->len[0] = GETU32((unsigned char *)&ctx->len[0]);
	ctx->len[1] = GETU32((unsigned char *)&ctx->len[1]);
#endif
#endif
	mgm64_hash_block(ctx, (unsigned char *)ctx->len);

	(*ctx->block)((unsigned char *)&ctx->sum, (unsigned char *)&ctx->sum, ctx->key);

	if (tag && len<=sizeof(ctx->sum))
		return memcmp(&ctx->sum, tag, len);
	else
		return -1;
}

void CRYPTO_mgm64_tag(MGM64_CONTEXT *ctx, unsigned char *tag, size_t len)
{
	CRYPTO_mgm64_finish(ctx, NULL, 0);
	memcpy(tag, &ctx->sum, len<=sizeof(ctx->sum)?len:sizeof(ctx->sum));
}
