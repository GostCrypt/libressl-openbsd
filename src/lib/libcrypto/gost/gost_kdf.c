/* $OpenBSD: gost_kdf.c,v 1.4 2017/01/29 17:49:23 beck Exp $ */
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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/gost.h>
#include <openssl/err.h>
#include <openssl/kdftree.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>

#include "gost_locl.h"

int
gost_kexp15(const EVP_CIPHER *ctr_cipher, const EVP_CIPHER *cmac_cipher,
       const unsigned char *key, unsigned int key_length,
       const unsigned char *key_mac,
       const unsigned char *key_enc,
       const unsigned char *iv,
       unsigned char *out, size_t *out_length)
{

	CMAC_CTX *cmac_ctx = CMAC_CTX_new();
	EVP_CIPHER_CTX ctx;
	unsigned char cmac[EVP_MAX_BLOCK_LENGTH];
	size_t cmac_length = sizeof(cmac);
	unsigned int len = *out_length;
	unsigned int tmp;

	if (CMAC_Init(cmac_ctx, key_mac, EVP_CIPHER_key_length(cmac_cipher), cmac_cipher, NULL) <= 0 ||
	    CMAC_Update(cmac_ctx, iv, ctr_cipher->iv_len) <= 0 ||
	    CMAC_Update(cmac_ctx, key, key_length) <= 0 ||
	    CMAC_Final(cmac_ctx, cmac, &cmac_length) <= 0) {
		CMAC_CTX_free(cmac_ctx);
		return 0;
	}

	CMAC_CTX_free(cmac_ctx);

	EVP_CIPHER_CTX_init(&ctx);
	if (!EVP_EncryptInit_ex(&ctx, ctr_cipher, NULL, key_enc, iv) ||
	    !EVP_CIPHER_CTX_set_padding(&ctx, 0) ||
	    !EVP_EncryptUpdate(&ctx, out, &len, key, key_length)) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}

	tmp = *out_length - len;
	if (!EVP_EncryptUpdate(&ctx, out + len, &tmp, cmac, cmac_length)) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}

	len += tmp;
	tmp = *out_length - len;
	if (!EVP_EncryptFinal_ex(&ctx, out + len, &tmp)) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	EVP_CIPHER_CTX_cleanup(&ctx);

	len += tmp;
	*out_length = len;

	return 1;
}

int
gost_kimp15(const EVP_CIPHER *ctr_cipher, const EVP_CIPHER *cmac_cipher,
       const unsigned char *sexp, unsigned int sexp_length,
       const unsigned char *key_mac,
       const unsigned char *key_enc,
       const unsigned char *iv,
       unsigned char *out, size_t *out_length)
{
	CMAC_CTX *cmac_ctx = CMAC_CTX_new();
	EVP_CIPHER_CTX ctx;
	unsigned char cmac[EVP_MAX_BLOCK_LENGTH];
	size_t cmac_length;
	unsigned char tmp[EVP_MAX_KEY_LENGTH + EVP_MAX_BLOCK_LENGTH];
	unsigned int len = sizeof(tmp);
	unsigned int len2;

	cmac_length = EVP_CIPHER_block_size(cmac_cipher);
	if (*out_length > EVP_MAX_KEY_LENGTH || sexp_length < cmac_length || sexp_length != 32 + cmac_length) {
		EVPerror(EVP_R_BAD_BLOCK_LENGTH);
		return 0;
	}

	EVP_CIPHER_CTX_init(&ctx);
	if (!EVP_DecryptInit_ex(&ctx, ctr_cipher, NULL, key_enc, iv) ||
	    !EVP_CIPHER_CTX_set_padding(&ctx, 0) ||
	    !EVP_DecryptUpdate(&ctx, tmp, &len, sexp, sexp_length)) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		GOSTerror(GOST_R_ERROR_COMPUTING_SHARED_KEY);
		return 0;
	}

	len2 = sizeof(tmp) - len;
	if (!EVP_DecryptFinal_ex(&ctx, tmp + len, &len2)) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		GOSTerror(GOST_R_ERROR_COMPUTING_SHARED_KEY);
		return 0;
	}
	EVP_CIPHER_CTX_cleanup(&ctx);
	len += len2;

	len2 = sexp_length - cmac_length;
	if (CMAC_Init(cmac_ctx, key_mac, EVP_CIPHER_key_length(cmac_cipher), cmac_cipher, NULL) <= 0 ||
	    CMAC_Update(cmac_ctx, iv, ctr_cipher->iv_len) <= 0 ||
	    CMAC_Update(cmac_ctx, tmp, sexp_length - cmac_length) <= 0 ||
	    CMAC_Final(cmac_ctx, cmac, &cmac_length) <= 0) {
		CMAC_CTX_free(cmac_ctx);
		GOSTerror(GOST_R_SIGNATURE_MISMATCH);
		return 0;
	}

	CMAC_CTX_free(cmac_ctx);

	if (timingsafe_memcmp(cmac, tmp + len2, cmac_length)) {
		GOSTerror(GOST_R_SIGNATURE_MISMATCH);
		return 0;
	}

	memcpy(out, tmp, len2);

	return 1;
}

int
gost_keg(EVP_PKEY *pub, EVP_PKEY *priv, int nid,
    const unsigned char *ukm, unsigned char *keg_out)
{
	if (nid == NID_id_tc26_gost3411_2012_512) {
		if (gost01_VKO_key(pub, priv, ukm, 16, 1, NID_id_tc26_gost3411_2012_512, keg_out) == 0) {
			GOSTerror(GOST_R_ERROR_COMPUTING_SHARED_KEY);
			return 0;
		}

		return 1;
	} else {
		unsigned char tmp[32];

		if (gost01_VKO_key(pub, priv, ukm, 16, 1, NID_id_tc26_gost3411_2012_256, tmp) == 0) {
			GOSTerror(GOST_R_ERROR_COMPUTING_SHARED_KEY);
			return 0;
		}

		return KDF_TREE(EVP_streebog256(), NULL,
				tmp, 32,
				"kdf tree", 8,
				ukm + 16, 8,
				1,
				keg_out, 64);
	}
}
#endif
