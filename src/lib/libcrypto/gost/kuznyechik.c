/* $OpenBSD: kuznyechik.c,v 1.4 2017/01/29 17:49:23 beck Exp $ */
/*
 * Copyright (c) 2020 Dmitry Baryshkov <dbaryshkov@gmail.com>
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

#include <string.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/gost.h>

#include "gost_locl.h"
#include "kuztable.h"

static void
memxor(unsigned char *a, const unsigned char *b)
{
	unsigned int i;

	for (i = 0; i < KUZNYECHIK_BLOCK_SIZE; i++)
		a[i] ^= b[i];
}

static void
memxor3(unsigned char *a, const unsigned char *b, const unsigned char *c)
{
	unsigned int i;

	for (i = 0; i < KUZNYECHIK_BLOCK_SIZE; i++)
		a[i] = b[i] ^ c[i];
}

static void S(unsigned char *a, const unsigned char *b)
{
	a[0] = pi[b[0]];
	a[1] = pi[b[1]];
	a[2] = pi[b[2]];
	a[3] = pi[b[3]];
	a[4] = pi[b[4]];
	a[5] = pi[b[5]];
	a[6] = pi[b[6]];
	a[7] = pi[b[7]];
	a[8] = pi[b[8]];
	a[9] = pi[b[9]];
	a[10] = pi[b[10]];
	a[11] = pi[b[11]];
	a[12] = pi[b[12]];
	a[13] = pi[b[13]];
	a[14] = pi[b[14]];
	a[15] = pi[b[15]];
}

static void Sinv(unsigned char *a, const unsigned char *b)
{
	a[0] = pi_inv[b[0]];
	a[1] = pi_inv[b[1]];
	a[2] = pi_inv[b[2]];
	a[3] = pi_inv[b[3]];
	a[4] = pi_inv[b[4]];
	a[5] = pi_inv[b[5]];
	a[6] = pi_inv[b[6]];
	a[7] = pi_inv[b[7]];
	a[8] = pi_inv[b[8]];
	a[9] = pi_inv[b[9]];
	a[10] = pi_inv[b[10]];
	a[11] = pi_inv[b[11]];
	a[12] = pi_inv[b[12]];
	a[13] = pi_inv[b[13]];
	a[14] = pi_inv[b[14]];
	a[15] = pi_inv[b[15]];
}

static void Linv(unsigned char *b)
{
	unsigned char a[KUZNYECHIK_BLOCK_SIZE];

	memxor3(a, &kuz_table_inv[0][b[0] * 16],
			&kuz_table_inv[1][b[1] * 16]);
	memxor(a, &kuz_table_inv[2][b[2] * 16]);
	memxor(a, &kuz_table_inv[3][b[3] * 16]);
	memxor(a, &kuz_table_inv[4][b[4] * 16]);
	memxor(a, &kuz_table_inv[5][b[5] * 16]);
	memxor(a, &kuz_table_inv[6][b[6] * 16]);
	memxor(a, &kuz_table_inv[7][b[7] * 16]);
	memxor(a, &kuz_table_inv[8][b[8] * 16]);
	memxor(a, &kuz_table_inv[9][b[9] * 16]);
	memxor(a, &kuz_table_inv[10][b[10] * 16]);
	memxor(a, &kuz_table_inv[11][b[11] * 16]);
	memxor(a, &kuz_table_inv[12][b[12] * 16]);
	memxor(a, &kuz_table_inv[13][b[13] * 16]);
	memxor(a, &kuz_table_inv[14][b[14] * 16]);
	memxor(a, &kuz_table_inv[15][b[15] * 16]);
	memcpy(b, a, KUZNYECHIK_BLOCK_SIZE);
}

static void LSX(unsigned char *a, const unsigned char *b, const unsigned char *c)
{
	unsigned char t[16];

	memxor3(t, &kuz_table[0][(b[0] ^ c[0]) * 16],
			&kuz_table[1][(b[1] ^ c[1]) * 16]);
	memxor(t, &kuz_table[2][(b[2] ^ c[2]) * 16]);
	memxor(t, &kuz_table[3][(b[3] ^ c[3]) * 16]);
	memxor(t, &kuz_table[4][(b[4] ^ c[4]) * 16]);
	memxor(t, &kuz_table[5][(b[5] ^ c[5]) * 16]);
	memxor(t, &kuz_table[6][(b[6] ^ c[6]) * 16]);
	memxor(t, &kuz_table[7][(b[7] ^ c[7]) * 16]);
	memxor(t, &kuz_table[8][(b[8] ^ c[8]) * 16]);
	memxor(t, &kuz_table[9][(b[9] ^ c[9]) * 16]);
	memxor(t, &kuz_table[10][(b[10] ^ c[10]) * 16]);
	memxor(t, &kuz_table[11][(b[11] ^ c[11]) * 16]);
	memxor(t, &kuz_table[12][(b[12] ^ c[12]) * 16]);
	memxor(t, &kuz_table[13][(b[13] ^ c[13]) * 16]);
	memxor(t, &kuz_table[14][(b[14] ^ c[14]) * 16]);
	memxor3(a, t, &kuz_table[15][(b[15] ^ c[15]) * 16]);
}

static void XLiSi(unsigned char *a, const unsigned char *b, const unsigned char *c)
{
	unsigned char t[16];

	memxor3(t, &kuz_table_inv_LS[0][b[0] * 16],
			&kuz_table_inv_LS[1][b[1] * 16]);
	memxor(t, &kuz_table_inv_LS[2][b[2] * 16]);
	memxor(t, &kuz_table_inv_LS[3][b[3] * 16]);
	memxor(t, &kuz_table_inv_LS[4][b[4] * 16]);
	memxor(t, &kuz_table_inv_LS[5][b[5] * 16]);
	memxor(t, &kuz_table_inv_LS[6][b[6] * 16]);
	memxor(t, &kuz_table_inv_LS[7][b[7] * 16]);
	memxor(t, &kuz_table_inv_LS[8][b[8] * 16]);
	memxor(t, &kuz_table_inv_LS[9][b[9] * 16]);
	memxor(t, &kuz_table_inv_LS[10][b[10] * 16]);
	memxor(t, &kuz_table_inv_LS[11][b[11] * 16]);
	memxor(t, &kuz_table_inv_LS[12][b[12] * 16]);
	memxor(t, &kuz_table_inv_LS[13][b[13] * 16]);
	memxor(t, &kuz_table_inv_LS[14][b[14] * 16]);
	memxor(t, &kuz_table_inv_LS[15][b[15] * 16]);
	memxor3(a, t, c);
}

static void subkey(unsigned char *out, const unsigned char *key, unsigned i)
{
	unsigned char test[16];

	LSX(test, key+0, kuz_key_table[i + 0]);
	memxor3(out+16, test, key + 16);
	LSX(test, out+16, kuz_key_table[i + 1]);
	memxor3(out+0, test, key + 0);
	LSX(test, out+0, kuz_key_table[i + 2]);
	memxor(out+16, test);
	LSX(test, out+16, kuz_key_table[i + 3]);
	memxor(out+0, test);
	LSX(test, out+0, kuz_key_table[i + 4]);
	memxor(out+16, test);
	LSX(test, out+16, kuz_key_table[i + 5]);
	memxor(out+0, test);
	LSX(test, out+0, kuz_key_table[i + 6]);
	memxor(out+16, test);
	LSX(test, out+16, kuz_key_table[i + 7]);
	memxor(out+0, test);
}

static void
Kuznyechik_set_enc_key(KUZNYECHIK_KEY *ctx, const unsigned char *key)
{
	memcpy(ctx->key, key, 32);
	subkey(ctx->key + 32, ctx->key, 0);
	subkey(ctx->key + 64, ctx->key + 32, 8);
	subkey(ctx->key + 96, ctx->key + 64, 16);
	subkey(ctx->key + 128, ctx->key + 96, 24);
}

void
Kuznyechik_set_key(KUZNYECHIK_KEY *ctx, const unsigned char *key, int enc)
{
	unsigned int i;

	Kuznyechik_set_enc_key(ctx, key);

	if (!enc)
		for (i = 1; i < 10; i++)
			Linv(ctx->key + 16 * i);
}

void
Kuznyechik_encrypt(const unsigned char *src, unsigned char *dst,
	const KUZNYECHIK_KEY *ctx)
{
	unsigned char temp[KUZNYECHIK_BLOCK_SIZE];

	LSX(temp, ctx->key + 16 * 0, src);
	LSX(temp, ctx->key + 16 * 1, temp);
	LSX(temp, ctx->key + 16 * 2, temp);
	LSX(temp, ctx->key + 16 * 3, temp);
	LSX(temp, ctx->key + 16 * 4, temp);
	LSX(temp, ctx->key + 16 * 5, temp);
	LSX(temp, ctx->key + 16 * 6, temp);
	LSX(temp, ctx->key + 16 * 7, temp);
	LSX(temp, ctx->key + 16 * 8, temp);
	memxor3(dst, ctx->key + 16 * 9, temp);
}

void
Kuznyechik_decrypt(const unsigned char *src, unsigned char *dst,
		const KUZNYECHIK_KEY *ctx)
{
	unsigned char temp[KUZNYECHIK_BLOCK_SIZE];

	S(temp, src);
	XLiSi(temp, temp, ctx->key + 16 * 9);
	XLiSi(temp, temp, ctx->key + 16 * 8);
	XLiSi(temp, temp, ctx->key + 16 * 7);
	XLiSi(temp, temp, ctx->key + 16 * 6);
	XLiSi(temp, temp, ctx->key + 16 * 5);
	XLiSi(temp, temp, ctx->key + 16 * 4);
	XLiSi(temp, temp, ctx->key + 16 * 3);
	XLiSi(temp, temp, ctx->key + 16 * 2);
	XLiSi(temp, temp, ctx->key + 16 * 1);
	Sinv(dst, temp);
	memxor(dst, ctx->key + 16 * 0);
}
#endif
