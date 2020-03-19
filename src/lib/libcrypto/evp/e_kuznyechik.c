/* $OpenBSD: e_kuznyechik.c,v 1.4 2017/01/29 17:49:23 beck Exp $ */
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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/modes.h>
#include <openssl/gost.h>
#include "evp_locl.h"

typedef struct {
	KUZNYECHIK_KEY ks;
} EVP_KUZNYECHIK_CTX;

static int
kuznyechik_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
	EVP_KUZNYECHIK_CTX *c = ctx->cipher_data;
	int mode = ctx->cipher->flags & EVP_CIPH_MODE;

	/* Enforce setting encryption key for all modes which use encdrypt
	 * operation */
	if (mode != EVP_CIPH_ECB_MODE && mode != EVP_CIPH_CBC_MODE)
		enc = 1;

	Kuznyechik_set_key(&c->ks, key, enc);

	return 1;
}

static int
kuznyechik_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	switch (type) {
	case EVP_CTRL_PBE_PRF_NID:
		if (ptr != NULL) {
			*((int *)ptr) = NID_id_tc26_hmac_gost_3411_12_512;
			return 1;
		} else {
			return 0;
		}
	default:
		return -1;
	}
}

static void
Kuznyechik_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
		const KUZNYECHIK_KEY *key, unsigned char *ivec, const int enc)
{
	if (enc)
		CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
				(block128_f)Kuznyechik_encrypt);
	else
		CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
				(block128_f)Kuznyechik_decrypt);
}

static void
Kuznyechik_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t length,
		const KUZNYECHIK_KEY *key, unsigned char *ivec, int *num, const int enc)
{
	CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
			(block128_f)Kuznyechik_encrypt);
}

static void
Kuznyechik_ecb_encrypt(const unsigned char *in, unsigned char *out, const KUZNYECHIK_KEY *key,
		const int enc)
{
	if (enc)
		Kuznyechik_encrypt(in, out, key);
	else
		Kuznyechik_decrypt(in, out, key);
}

static void
Kuznyechik_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t length,
		const KUZNYECHIK_KEY *key, unsigned char *ivec, int *num)
{
	CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num,
			(block128_f)Kuznyechik_encrypt);
}

static int
kuznyechik_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
		size_t len)
{
	EVP_KUZNYECHIK_CTX *key = EVP_C_DATA(EVP_KUZNYECHIK_CTX, ctx);

	CRYPTO_ctr128_encrypt(in, out, len, &key->ks, ctx->iv, ctx->buf,
			&ctx->num, (block128_f)Kuznyechik_encrypt);
	return 1;
}

IMPLEMENT_BLOCK_CIPHER(kuznyechik, ks, Kuznyechik, EVP_KUZNYECHIK_CTX,
		NID_kuznyechik, 16, 32, 16, 128, 0, kuznyechik_init_key, NULL,
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		kuznyechik_ctl)

BLOCK_CIPHER_def1(kuznyechik, ctr, ctr, CTR, EVP_KUZNYECHIK_CTX,
		NID_kuznyechik, 1, 32, 8, 0,
		kuznyechik_init_key, NULL,
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		kuznyechik_ctl)

#endif
