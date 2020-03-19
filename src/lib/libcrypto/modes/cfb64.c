/* $OpenBSD: cfb64.c,v 1.4 2015/02/10 09:46:30 miod Exp $ */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 *
 */

#include <openssl/crypto.h>
#include "modes_lcl.h"
#include <string.h>

#ifndef MODES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif

/* The input and output encrypted as though 64bit cfb mode is being
 * used.  The extra state information to record how much of the
 * 64bit block we have used is contained in *num;
 */
void CRYPTO_cfb64_encrypt(const unsigned char *in, unsigned char *out,
			size_t len, const void *key,
			unsigned char ivec[8], int *num,
			int enc, block64_f block)
{
    unsigned int n;
    size_t l = 0;

    n = *num;

    if (enc) {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
	if (8%sizeof(size_t) == 0) do {	/* always true actually */
		while (n && len) {
			*(out++) = ivec[n] ^= *(in++);
			--len;
			n = (n+1) % 8;
		}
#ifdef __STRICT_ALIGNMENT
		if (((size_t)in|(size_t)out|(size_t)ivec)%sizeof(size_t) != 0)
			break;
#endif
		while (len>=8) {
			(*block)(ivec, ivec, key);
			for (; n<8; n+=sizeof(size_t)) {
				*(size_t*)(out+n) =
				*(size_t*)(ivec+n) ^= *(size_t*)(in+n);
			}
			len -= 8;
			out += 8;
			in  += 8;
			n = 0;
		}
		if (len) {
			(*block)(ivec, ivec, key);
			while (len--) {
				out[n] = ivec[n] ^= in[n];
				++n;
			}
		}
		*num = n;
		return;
	} while (0);
	/* the rest would be commonly eliminated by x86* compiler */
#endif
	while (l<len) {
		if (n == 0) {
			(*block)(ivec, ivec, key);
		}
		out[l] = ivec[n] ^= in[l];
		++l;
		n = (n+1) % 8;
	}
	*num = n;
    } else {
#if !defined(OPENSSL_SMALL_FOOTPRINT)
	if (8%sizeof(size_t) == 0) do {	/* always true actually */
		while (n && len) {
			unsigned char c;
			*(out++) = ivec[n] ^ (c = *(in++)); ivec[n] = c;
			--len;
			n = (n+1) % 8;
 		}
#ifdef __STRICT_ALIGNMENT
		if (((size_t)in|(size_t)out|(size_t)ivec)%sizeof(size_t) != 0)
			break;
#endif
		while (len>=8) {
			(*block)(ivec, ivec, key);
			for (; n<8; n+=sizeof(size_t)) {
				size_t t = *(size_t*)(in+n);
				*(size_t*)(out+n) = *(size_t*)(ivec+n) ^ t;
				*(size_t*)(ivec+n) = t;
			}
			len -= 8;
			out += 8;
			in  += 8;
			n = 0;
		}
		if (len) {
			(*block)(ivec, ivec, key);
			while (len--) {
				unsigned char c;
				out[n] = ivec[n] ^ (c = in[n]); ivec[n] = c;
				++n;
			}
 		}
		*num = n;
		return;
	} while (0);
	/* the rest would be commonly eliminated by x86* compiler */
#endif
	while (l<len) {
		unsigned char c;
		if (n == 0) {
			(*block)(ivec, ivec, key);
		}
		out[l] = ivec[n] ^ (c = in[l]); ivec[n] = c;
		++l;
		n = (n+1) % 8;
	}
	*num=n;
    }
}
