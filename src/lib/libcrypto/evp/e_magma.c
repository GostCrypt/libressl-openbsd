/* $OpenBSD: e_magma.c,v 1.4 2017/01/29 17:49:23 beck Exp $ */
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
	MAGMA_KEY ks;
} EVP_MAGMA_CTX;

static int
magma_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
	EVP_MAGMA_CTX *c = ctx->cipher_data;

	Magma_set_key(&c->ks, key);

	return 1;
}

static int
magma_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	switch (type) {
	case EVP_CTRL_PBE_PRF_NID:
		if (ptr != NULL) {
			*((int *)ptr) = NID_id_tc26_hmac_gost_3411_12_256;
			return 1;
		} else {
			return 0;
		}
	default:
		return -1;
	}
}

static int
magma_acpkm_ctl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	EVP_MAGMA_CTX *key = EVP_C_DATA(EVP_MAGMA_CTX, ctx);

	switch (type) {
	case EVP_CTRL_GOST_SET_MESHING:
		key->ks.key_meshing = arg;
		return 1;
	case EVP_CTRL_INIT:
		/* deafult for tests */
		key->ks.key_meshing = 16;
		return 1;
	default:
		return magma_ctl(ctx, type, arg, ptr);
	}
}

static void
Magma_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
		const MAGMA_KEY *key, unsigned char *ivec, const int enc)
{
	if (enc)
		CRYPTO_cbc64_encrypt(in, out, len, key, ivec,
				(block64_f)Magma_encrypt);
	else
		CRYPTO_cbc64_decrypt(in, out, len, key, ivec,
				(block64_f)Magma_decrypt);
}

static void
Magma_cfb64_encrypt(const unsigned char *in, unsigned char *out, size_t length,
		const MAGMA_KEY *key, unsigned char *ivec, int *num, const int enc)
{
	CRYPTO_cfb64_encrypt(in, out, length, key, ivec, num, enc,
			(block64_f)Magma_encrypt);
}

static void
Magma_ecb_encrypt(const unsigned char *in, unsigned char *out, const MAGMA_KEY *key,
		const int enc)
{
	if (enc)
		Magma_encrypt(in, out, key);
	else
		Magma_decrypt(in, out, key);
}

static void
Magma_ofb64_encrypt(const unsigned char *in, unsigned char *out, size_t length,
		const MAGMA_KEY *key, unsigned char *ivec, int *num)
{
	CRYPTO_ofb64_encrypt(in, out, length, key, ivec, num,
			(block64_f)Magma_encrypt);
}

static int
magma_ctr_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
	if (iv)
		memset(ctx->iv + 4, 0, 4);

	if (!key)
		return 1;

	return magma_init_key(ctx, key, iv, enc);
}

static int
magma_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
		size_t len)
{
	EVP_MAGMA_CTX *key = EVP_C_DATA(EVP_MAGMA_CTX, ctx);

	CRYPTO_ctr64_encrypt(in, out, len, &key->ks, ctx->iv, ctx->buf,
			&ctx->num, (block64_f)Magma_encrypt);
	return 1;
}

static int
magma_ctr_acpkm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
		size_t len)
{
	EVP_MAGMA_CTX *key = EVP_C_DATA(EVP_MAGMA_CTX, ctx);

	CRYPTO_ctr64_encrypt(in, out, len, &key->ks, ctx->iv, ctx->buf,
			&ctx->num, (block64_f)Magma_acpkm_encrypt);
	return 1;
}

static int
magma_ctr_acpkm_set_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
	/* Also set meshing section size here.
	 * There is no other good place to enable meshing for CMS
	 */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GOST_SET_MESHING, 8 * 1024, 0);

	return gost3412_ctr_acpkm_set_asn1_params(ctx, params, EVP_CIPHER_CTX_iv_length(ctx));
}

static int
magma_ctr_acpkm_get_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params)
{
	/* Also set meshing section size here.
	 * There is no other good place to enable meshing for CMS
	 */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GOST_SET_MESHING, 8 * 1024, 0);

	return gost3412_ctr_acpkm_get_asn1_params(ctx, params, EVP_CIPHER_CTX_iv_length(ctx));
}

IMPLEMENT_BLOCK_CIPHER(magma, ks, Magma, EVP_MAGMA_CTX,
		NID_magma, 8, 32, 8, 64, 0, magma_init_key, NULL,
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		magma_ctl)

BLOCK_CIPHER_def1(magma, ctr, ctr, CTR, EVP_MAGMA_CTX,
		NID_magma, 1, 32, 4, EVP_CIPH_ALWAYS_CALL_INIT,
		magma_ctr_init_key, NULL,
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		magma_ctl)

#define NID_magma_ctr_acpkm NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm

BLOCK_CIPHER_def1(magma, ctr_acpkm, ctr_acpkm, CTR, EVP_MAGMA_CTX,
		NID_magma, 1, 32, 4, EVP_CIPH_CTRL_INIT | EVP_CIPH_ALWAYS_CALL_INIT,
		magma_ctr_init_key, NULL,
		magma_ctr_acpkm_set_asn1_params,
		magma_ctr_acpkm_get_asn1_params,
		magma_acpkm_ctl)

#endif
