/* $OpenBSD: modes.h,v 1.3 2018/07/24 10:47:19 bcook Exp $ */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project. All rights reserved.
 *
 * Rights for redistribution and usage in source and binary
 * forms are granted according to the OpenSSL license.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*block128_f)(const unsigned char in[16],
			unsigned char out[16],
			const void *key);

typedef void (*cbc128_f)(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int enc);

typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
			size_t blocks, const void *key,
			const unsigned char ivec[16]);

typedef void (*ccm128_f)(const unsigned char *in, unsigned char *out,
			size_t blocks, const void *key,
			const unsigned char ivec[16],unsigned char cmac[16]);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);

void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, block128_f block);

void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], unsigned char ecount_buf[16],
			unsigned int *num, ctr128_f ctr);

void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int *num,
			block128_f block);

void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block128_f block);
void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
			size_t length, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block128_f block);
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
			size_t bits, const void *key,
			unsigned char ivec[16], int *num,
			int enc, block128_f block);

size_t CRYPTO_cts128_encrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_cts128_decrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);

size_t CRYPTO_nistcts128_encrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[16], cbc128_f cbc);

typedef struct gcm128_context GCM128_CONTEXT;

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx,void *key,block128_f block);
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
			size_t len);
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
			size_t len);
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len, ctr128_f stream);
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len, ctr128_f stream);
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx,const unsigned char *tag,
			size_t len);
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);

typedef struct ccm128_context CCM128_CONTEXT;

void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx,
	unsigned int M, unsigned int L, void *key,block128_f block);
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx,
	const unsigned char *nonce, size_t nlen, size_t mlen);
void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx,
	const unsigned char *aad, size_t alen);
int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out, size_t len);
int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out, size_t len);
int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out, size_t len,
	ccm128_f stream);
int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx,
	const unsigned char *inp, unsigned char *out, size_t len,
	ccm128_f stream);
size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, unsigned char *tag, size_t len);

typedef struct xts128_context XTS128_CONTEXT;

int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx, const unsigned char iv[16],
	const unsigned char *inp, unsigned char *out, size_t len, int enc);

typedef struct mgm128_context MGM128_CONTEXT;

void CRYPTO_mgm128_init(MGM128_CONTEXT *ctx,void *key,block128_f block);
void CRYPTO_mgm128_setiv(MGM128_CONTEXT *ctx, const unsigned char *iv);
int CRYPTO_mgm128_aad(MGM128_CONTEXT *ctx, const unsigned char *aad,
			size_t len);
int CRYPTO_mgm128_encrypt(MGM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
int CRYPTO_mgm128_decrypt(MGM128_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
int CRYPTO_mgm128_finish(MGM128_CONTEXT *ctx,const unsigned char *tag,
			size_t len);
void CRYPTO_mgm128_tag(MGM128_CONTEXT *ctx, unsigned char *tag, size_t len);

typedef void (*block64_f)(const unsigned char in[8],
			unsigned char out[8],
			const void *key);

void CRYPTO_cbc64_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[8], block64_f block);
void CRYPTO_cbc64_decrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[8], block64_f block);

void CRYPTO_ctr64_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[8], unsigned char ecount_buf[8],
			unsigned int *num, block64_f block);

void CRYPTO_ofb64_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[8], int *num,
			block64_f block);

void CRYPTO_cfb64_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[8], int *num,
			int enc, block64_f block);

typedef struct mgm64_context MGM64_CONTEXT;

void CRYPTO_mgm64_init(MGM64_CONTEXT *ctx,void *key,block64_f block);
void CRYPTO_mgm64_setiv(MGM64_CONTEXT *ctx, const unsigned char *iv);
int CRYPTO_mgm64_aad(MGM64_CONTEXT *ctx, const unsigned char *aad,
			size_t len);
int CRYPTO_mgm64_encrypt(MGM64_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
int CRYPTO_mgm64_decrypt(MGM64_CONTEXT *ctx,
			const unsigned char *in, unsigned char *out,
			size_t len);
int CRYPTO_mgm64_finish(MGM64_CONTEXT *ctx,const unsigned char *tag,
			size_t len);
void CRYPTO_mgm64_tag(MGM64_CONTEXT *ctx, unsigned char *tag, size_t len);

#ifdef __cplusplus
}
#endif
