/* $OpenBSD: mgm128.c,v 1.22 2018/01/24 23:03:37 kettenis Exp $ */
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

#define MGM128_BLOCK_SIZE 16
#define MGM128_POLYNOMIAL U64(0x87)

static void
mgm128_gf_shift (u64 r[2], const u64 x[2])
{
  long mask;

  /* Shift uses big-endian representation. */
#if BYTE_ORDER != LITTLE_ENDIAN
  mask = - ((x[0] >> 63) & 1);
  r[0] = (x[0] << 1) | (x[1] >> 63);
  r[1] = (x[1] << 1) ^ (mask & (MGM128_POLYNOMIAL));
#else /* ! WORDS_BIGENDIAN */
#define RSHIFT_WORD(x) \
  ((((x) & UINT64_C(0x7f7f7f7f7f7f7f7f)) << 1) \
   | (((x) & UINT64_C(0x8080808080808000)) >> 15))
  mask = - ((x[0] >> 7) & 1);
  r[0] = RSHIFT_WORD(x[0]) | ((x[1] & 0x80) << 49);
  r[1] = RSHIFT_WORD(x[1]) ^ (mask & (MGM128_POLYNOMIAL << 56));
# undef RSHIFT_WORD
#endif /* ! WORDS_BIGENDIAN */
}

static void
mgm128_gf_mul_sum(MGM128_CONTEXT *ctx, u64 *x, const uint8_t *y)
{
	u64 V[2], Z[2];
	unsigned i;

	memcpy(V, x, sizeof(V));
	memset(Z, 0, sizeof(Z));

	for (i = 0; i < MGM128_BLOCK_SIZE; i++)
	{
		uint8_t b = y[MGM128_BLOCK_SIZE - i - 1];
		unsigned j;
		for (j = 0; j < 8; j++, b >>= 1)
		{
			if (b & 1) {
				Z[0] ^= V[0];
				Z[1] ^= V[1];
			}

			mgm128_gf_shift(V, V);
		}
	}

	ctx->sum[0] ^= Z[0];
	ctx->sum[1] ^= Z[1];
}

static inline void mgm128_inc(unsigned char *counter, u32 n)
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

void mgm128_hash_block(MGM128_CONTEXT *ctx, const u8 *data)
{
	union {u64 u[2]; u8 c[MGM128_BLOCK_SIZE]; } tmp;

	(*ctx->block)(ctx->z, tmp.c, ctx->key);
	mgm128_gf_mul_sum(ctx, tmp.u, data);
	mgm128_inc(ctx->z, MGM128_BLOCK_SIZE / 2);
}

void CRYPTO_mgm128_init(MGM128_CONTEXT *ctx, void *key, block128_f block)
{
	memset(ctx,0,sizeof(*ctx));
	ctx->block = block;
	ctx->key   = key;
}

void CRYPTO_mgm128_setiv(MGM128_CONTEXT *ctx, const unsigned char *iv)
{
	memcpy(ctx->y, iv, MGM128_NONCE_LEN);
	memcpy(ctx->z, iv, MGM128_NONCE_LEN);

	ctx->y[0] &= 0x7f;
	ctx->z[0] |= 0x80;

	(*ctx->block)(ctx->y, ctx->y, ctx->key);
	(*ctx->block)(ctx->z, ctx->z, ctx->key);

	memset(ctx->sum, 0, MGM128_BLOCK_SIZE);
	memset(ctx->len, 0, MGM128_BLOCK_SIZE);
}

int CRYPTO_mgm128_aad(MGM128_CONTEXT *ctx, const unsigned char *aad,
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
			n = (n + 1) % MGM128_BLOCK_SIZE;
		}
		if (n == 0) {
			mgm128_hash_block(ctx, ctx->part);
		} else {
			ctx->a_remain = n;
			return 0;
		}
	}

	while (len >= MGM128_BLOCK_SIZE) {
		mgm128_hash_block(ctx, aad);
		aad += MGM128_BLOCK_SIZE;
		len -= MGM128_BLOCK_SIZE;
	}

	if (len)
		memcpy(ctx->part, aad, len);

	ctx->a_remain = len;
	return 0;
}

int CRYPTO_mgm128_encrypt(MGM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	unsigned int n;

	/* Handle AAD remainder */
	if (ctx->a_remain) {
		memset(ctx->part + ctx->a_remain, 0, MGM128_BLOCK_SIZE - ctx->a_remain);
		mgm128_hash_block(ctx, ctx->part);
		ctx->a_remain = 0;
	}

	ctx->len[1] += len * 8;

	n = ctx->d_remain;
	if (n) {
		while (n && len) {
			ctx->part[n] ^= *(in++);
			*(out++) = ctx->part[n];
			--len;
			n = (n + 1) % MGM128_BLOCK_SIZE;
		}
		if (n == 0) {
			mgm128_hash_block(ctx, ctx->part);
		} else {
			ctx->d_remain = n;
			return 0;
		}
	}

	while (len >= MGM128_BLOCK_SIZE) {
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm128_inc(ctx->y + MGM128_BLOCK_SIZE / 2, MGM128_BLOCK_SIZE / 2);
		for (n = 0; n < MGM128_BLOCK_SIZE; n++) {
			out[n] = ctx->part[n] ^ in[n];
		}
		mgm128_hash_block(ctx, out);
		in += MGM128_BLOCK_SIZE;
		out += MGM128_BLOCK_SIZE;
		len -= MGM128_BLOCK_SIZE;
	}

	if (len) {
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm128_inc(ctx->y + MGM128_BLOCK_SIZE / 2, MGM128_BLOCK_SIZE / 2);
		for (n = 0; n < len; n++) {
			ctx->part[n] ^= *(in++);
			*(out++) = ctx->part[n];
		}
	}

	ctx->d_remain = len;

	return 0;
}

int CRYPTO_mgm128_decrypt(MGM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len)
{
	unsigned int n;

	/* Handle AAD remainder */
	if (ctx->a_remain) {
		memset(ctx->part + ctx->a_remain, 0, MGM128_BLOCK_SIZE - ctx->a_remain);
		mgm128_hash_block(ctx, ctx->part);
		ctx->a_remain = 0;
	}

	ctx->len[1] += len * 8;

	n = ctx->d_remain;
	if (n) {
		while (n && len) {
			u8 tmp = *(in++);
			*(out++) = ctx->part[n] ^ tmp;
			ctx->part[n] = tmp;
			n = (n + 1) % MGM128_BLOCK_SIZE;
		}
		if (n == 0) {
			mgm128_hash_block(ctx, ctx->part);
		} else {
			ctx->d_remain = n;
			return 0;
		}
	}

	while (len >= MGM128_BLOCK_SIZE) {
		mgm128_hash_block(ctx, in);
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm128_inc(ctx->y + MGM128_BLOCK_SIZE / 2, MGM128_BLOCK_SIZE / 2);
		for (n = 0; n < MGM128_BLOCK_SIZE; n++) {
			out[n] = ctx->part[n] ^ in[n];
		}
		in += MGM128_BLOCK_SIZE;
		out += MGM128_BLOCK_SIZE;
		len -= MGM128_BLOCK_SIZE;
	}

	if (len) {
		(*ctx->block)(ctx->y, ctx->part, ctx->key);
		mgm128_inc(ctx->y + MGM128_BLOCK_SIZE / 2, MGM128_BLOCK_SIZE / 2);
		for (n = 0; n < len; n++) {
			u8 tmp = *(in++);
			*(out++) = ctx->part[n] ^ tmp;
			ctx->part[n] = tmp;
		}
	}

	ctx->d_remain = len;

	return 0;
}

int CRYPTO_mgm128_finish(MGM128_CONTEXT *ctx,const unsigned char *tag,
			size_t len)
{
	/* Handle AAD and data remainder */
	if (ctx->a_remain) {
		memset(ctx->part + ctx->a_remain, 0, MGM128_BLOCK_SIZE - ctx->a_remain);
		mgm128_hash_block(ctx, ctx->part);
	}

	if (ctx->d_remain) {
		memset(ctx->part + ctx->d_remain, 0, MGM128_BLOCK_SIZE - ctx->d_remain);
		mgm128_hash_block(ctx, ctx->part);
	}

#if BYTE_ORDER == LITTLE_ENDIAN
#ifndef BSWAP8
#define BSWAP8(u) (u64)GETU32((unsigned char *)&u) << 32|GETU32(((unsigned char *)&u) + 4)
#endif
	ctx->len[0] = BSWAP8(ctx->len[0]);
	ctx->len[1] = BSWAP8(ctx->len[1]);
#endif
	mgm128_hash_block(ctx, (unsigned char *)ctx->len);

	(*ctx->block)((unsigned char *)ctx->sum, (unsigned char *)ctx->sum, ctx->key);

	if (tag && len<=sizeof(ctx->sum))
		return memcmp(ctx->sum, tag, len);
	else
		return -1;
}

void CRYPTO_mgm128_tag(MGM128_CONTEXT *ctx, unsigned char *tag, size_t len)
{
	CRYPTO_mgm128_finish(ctx, NULL, 0);
	memcpy(tag, ctx->sum, len<=sizeof(ctx->sum)?len:sizeof(ctx->sum));
}
