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
#include "modes_lcl.h"

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

#define EVP_AEAD_MAGMA_MGM_TAG_LEN 16

typedef struct {
	MAGMA_KEY ks;		/* MAGMA key schedule to use */
	MGM64_CONTEXT mgm;
	int key_set;		/* Set if key initialised */
	int iv_set;		/* Set if an iv is set */
	int tag_len;
} EVP_MAGMA_MGM_CTX;

struct aead_magma_mgm_ctx {
	MAGMA_KEY ks;
	MGM64_CONTEXT mgm;
	unsigned char tag_len;
};

static void
magma_mgm_set_key(MAGMA_KEY *magma_key, MGM64_CONTEXT *mgm_ctx,
    const unsigned char *key, size_t key_len)
{
	Magma_set_key(magma_key, key);
	CRYPTO_mgm64_init(mgm_ctx, magma_key, (block64_f)Magma_encrypt);
}

static int
magma_mgm_cleanup(EVP_CIPHER_CTX *c)
{
	EVP_MAGMA_MGM_CTX *gctx = c->cipher_data;

	explicit_bzero(gctx, sizeof(*gctx));
	return 1;
}

static int
magma_mgm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	EVP_MAGMA_MGM_CTX *gctx = c->cipher_data;

	switch (type) {
	case EVP_CTRL_INIT:
		gctx->key_set = 0;
		gctx->iv_set = 0;
		gctx->tag_len = -1;
		return 1;

	case EVP_CTRL_MGM_SET_TAG:
		if (arg <= 0 || arg > 8 || c->encrypt)
			return 0;
		memcpy(c->buf, ptr, arg);
		gctx->tag_len = arg;
		return 1;

	case EVP_CTRL_MGM_GET_TAG:
		if (arg <= 0 || arg > 8 || !c->encrypt || gctx->tag_len < 0)
			return 0;
		memcpy(ptr, c->buf, arg);
		return 1;

	case EVP_CTRL_COPY:
	    {
		EVP_CIPHER_CTX *out = ptr;
		EVP_MAGMA_MGM_CTX *gctx_out = out->cipher_data;

		if (gctx->mgm.key) {
			if (gctx->mgm.key != &gctx->ks)
				return 0;
			gctx_out->mgm.key = &gctx_out->ks;
		}

		return 1;
	    }

	default:
		return -1;

	}
}

static int
magma_mgm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
	EVP_MAGMA_MGM_CTX *gctx = ctx->cipher_data;

	if (!iv && !key)
		return 1;
	if (key) {
		magma_mgm_set_key(&gctx->ks, &gctx->mgm, key, ctx->key_len);

		/* If we have an iv can set it directly, otherwise use
		 * saved IV.
		 */
		if (gctx->iv_set)
			iv = ctx->iv;
		if (iv) {
			CRYPTO_mgm64_setiv(&gctx->mgm, iv);
			gctx->iv_set = 1;
		}
		gctx->key_set = 1;
	} else {
		/* If key set use IV, otherwise copy */
		if (gctx->key_set)
			CRYPTO_mgm64_setiv(&gctx->mgm, iv);
		else
			memcpy(ctx->iv, iv, ctx->cipher->iv_len);
		gctx->iv_set = 1;
	}
	return 1;
}

static int
magma_mgm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, size_t len)
{
	EVP_MAGMA_MGM_CTX *gctx = ctx->cipher_data;

	/* If not set up, return error */
	if (!gctx->key_set)
		return -1;

	if (!gctx->iv_set)
		return -1;

	if (in) {
		if (out == NULL) {
			if (CRYPTO_mgm64_aad(&gctx->mgm, in, len))
				return -1;
		} else if (ctx->encrypt) {
			if (CRYPTO_mgm64_encrypt(&gctx->mgm, in, out, len))
				return -1;
		} else {
			if (CRYPTO_mgm64_decrypt(&gctx->mgm, in, out, len))
				return -1;
		}
		return len;
	} else {
		if (!ctx->encrypt) {
			if (gctx->tag_len < 0)
				return -1;
			if (CRYPTO_mgm64_finish(&gctx->mgm, ctx->buf, gctx->tag_len) != 0)
				return -1;
			gctx->iv_set = 0;
			return 0;
		}
		CRYPTO_mgm64_tag(&gctx->mgm, ctx->buf, 8);
		gctx->tag_len = 8;

		/* Don't reuse the IV */
		gctx->iv_set = 0;
		return 0;
	}

}

#define CUSTOM_FLAGS \
    ( EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV | \
      EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT | \
      EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY )

#define NID_magma_mgm NID_id_tc26_cipher_gostr3412_2015_magma_mgm

BLOCK_CIPHER_def1(magma, mgm, mgm, GCM, EVP_MAGMA_MGM_CTX,
		NID_magma, 1, 32, 8,
		EVP_CIPH_FLAG_AEAD_CIPHER|CUSTOM_FLAGS,
		magma_mgm_init_key, magma_mgm_cleanup,
		EVP_CIPHER_set_asn1_iv,
		EVP_CIPHER_get_asn1_iv,
		magma_mgm_ctrl)

static int
aead_magma_mgm_init(EVP_AEAD_CTX *ctx, const unsigned char *key, size_t key_len,
    size_t tag_len)
{
	struct aead_magma_mgm_ctx *mgm_ctx;
	const size_t key_bits = key_len * 8;

	/* EVP_AEAD_CTX_init should catch this. */
	if (key_bits != 256) {
		EVPerror(EVP_R_BAD_KEY_LENGTH);
		return 0;
	}

	if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH)
		tag_len = EVP_AEAD_MAGMA_MGM_TAG_LEN;

	if (tag_len > EVP_AEAD_MAGMA_MGM_TAG_LEN) {
		EVPerror(EVP_R_TAG_TOO_LARGE);
		return 0;
	}

	if ((mgm_ctx = calloc(1, sizeof(struct aead_magma_mgm_ctx))) == NULL)
		return 0;

	magma_mgm_set_key(&mgm_ctx->ks, &mgm_ctx->mgm, key, key_len);

	mgm_ctx->tag_len = tag_len;
	ctx->aead_state = mgm_ctx;

	return 1;
}

static void
aead_magma_mgm_cleanup(EVP_AEAD_CTX *ctx)
{
	struct aead_magma_mgm_ctx *mgm_ctx = ctx->aead_state;

	freezero(mgm_ctx, sizeof(*mgm_ctx));
}

static int
aead_magma_mgm_seal(const EVP_AEAD_CTX *ctx, unsigned char *out, size_t *out_len,
    size_t max_out_len, const unsigned char *nonce, size_t nonce_len,
    const unsigned char *in, size_t in_len, const unsigned char *ad,
    size_t ad_len)
{
	const struct aead_magma_mgm_ctx *mgm_ctx = ctx->aead_state;
	MGM64_CONTEXT mgm;
	size_t bulk = 0;

	if (max_out_len < in_len + mgm_ctx->tag_len) {
		EVPerror(EVP_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (nonce_len != MGM64_NONCE_LEN) {
		EVPerror(EVP_R_IV_TOO_LARGE);
		return 0;
	}

	memcpy(&mgm, &mgm_ctx->mgm, sizeof(mgm));
	CRYPTO_mgm64_setiv(&mgm, nonce);

	if (ad_len > 0 && CRYPTO_mgm64_aad(&mgm, ad, ad_len))
		return 0;

	if (CRYPTO_mgm64_encrypt(&mgm, in + bulk, out + bulk,
				in_len - bulk))
		return 0;

	CRYPTO_mgm64_tag(&mgm, out + in_len, mgm_ctx->tag_len);
	*out_len = in_len + mgm_ctx->tag_len;

	return 1;
}

static int
aead_magma_mgm_open(const EVP_AEAD_CTX *ctx, unsigned char *out, size_t *out_len,
    size_t max_out_len, const unsigned char *nonce, size_t nonce_len,
    const unsigned char *in, size_t in_len, const unsigned char *ad,
    size_t ad_len)
{
	const struct aead_magma_mgm_ctx *mgm_ctx = ctx->aead_state;
	unsigned char tag[EVP_AEAD_MAGMA_MGM_TAG_LEN];
	MGM64_CONTEXT mgm;
	size_t plaintext_len;
	size_t bulk = 0;

	if (in_len < mgm_ctx->tag_len) {
		EVPerror(EVP_R_BAD_DECRYPT);
		return 0;
	}

	plaintext_len = in_len - mgm_ctx->tag_len;

	if (max_out_len < plaintext_len) {
		EVPerror(EVP_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (nonce_len != MGM64_NONCE_LEN) {
		EVPerror(EVP_R_IV_TOO_LARGE);
		return 0;
	}

	memcpy(&mgm, &mgm_ctx->mgm, sizeof(mgm));
	CRYPTO_mgm64_setiv(&mgm, nonce);

	if (CRYPTO_mgm64_aad(&mgm, ad, ad_len))
		return 0;

	if (CRYPTO_mgm64_decrypt(&mgm, in + bulk, out + bulk,
				in_len - bulk - mgm_ctx->tag_len))
		return 0;

	CRYPTO_mgm64_tag(&mgm, tag, mgm_ctx->tag_len);
	if (timingsafe_memcmp(tag, in + plaintext_len, mgm_ctx->tag_len) != 0) {
		EVPerror(EVP_R_BAD_DECRYPT);
		return 0;
	}

	*out_len = plaintext_len;

	return 1;
}

static const EVP_AEAD aead_magma_mgm = {
	.key_len = 32,
	.nonce_len = 8,
	.overhead = EVP_AEAD_MAGMA_MGM_TAG_LEN,
	.max_tag_len = EVP_AEAD_MAGMA_MGM_TAG_LEN,

	.init = aead_magma_mgm_init,
	.cleanup = aead_magma_mgm_cleanup,
	.seal = aead_magma_mgm_seal,
	.open = aead_magma_mgm_open,
};

const EVP_AEAD *
EVP_aead_magma_mgm(void)
{
	return &aead_magma_mgm;
}
#endif
