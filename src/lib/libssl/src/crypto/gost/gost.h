/* $OpenBSD$ */
/*
 * Copyright (c) 2014 Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Copyright (c) 2005-2006 Cryptocom LTD
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#ifndef HEADER_GOST_H
#define HEADER_GOST_H

#include <openssl/opensslconf.h>

#ifdef OPENSSL_NO_GOST
#error GOST is disabled.
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gost2814789_key_st {
	unsigned int key[8];
	unsigned int k87[256],k65[256],k43[256],k21[256];
	unsigned int count;
	unsigned key_meshing : 1;
} GOST2814789_KEY;

int Gost2814789_set_sbox(GOST2814789_KEY *key, int nid);
int Gost2814789_set_key(GOST2814789_KEY *key,
		const unsigned char *userKey, const int bits);
void Gost2814789_ecb_encrypt(const unsigned char *in, unsigned char *out,
	GOST2814789_KEY *key, const int enc);
void Gost2814789_cfb64_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, GOST2814789_KEY *key,
	unsigned char *ivec, int *num, const int enc);
void Gost2814789_cnt_encrypt(const unsigned char *in, unsigned char *out,
	size_t length, GOST2814789_KEY *key,
	unsigned char *ivec, unsigned char *cnt_buf, int *num);

#define GOST2814789IMIT_LENGTH 4
#define GOST2814789IMIT_CBLOCK 8
#define GOST2814789IMIT_LONG unsigned int

typedef struct GOST2814789IMITstate_st {
	GOST2814789IMIT_LONG	Nl, Nh;
	unsigned char		data[GOST2814789IMIT_CBLOCK];
	unsigned int		num;

	GOST2814789_KEY		cipher;
	unsigned char		mac[GOST2814789IMIT_CBLOCK];
} GOST2814789IMIT_CTX;

/* Note, also removed second parameter and removed dctx->cipher setting */
int GOST2814789IMIT_Init(GOST2814789IMIT_CTX *c, int nid);
int GOST2814789IMIT_Update(GOST2814789IMIT_CTX *c, const void *data, size_t len);
int GOST2814789IMIT_Final(unsigned char *md, GOST2814789IMIT_CTX *c);
void GOST2814789IMIT_Transform(GOST2814789IMIT_CTX *c, const unsigned char *data);
unsigned char *GOST2814789IMIT(const unsigned char *d, size_t n,
		unsigned char *md, int nid,
		const unsigned char *key, const unsigned char *iv);

#ifdef  __cplusplus
}
#endif
#endif
