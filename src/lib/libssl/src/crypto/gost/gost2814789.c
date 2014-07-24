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

#include <string.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/gost.h>

#include "gost_locl.h"

static inline unsigned int f(const GOST2814789_KEY *c, unsigned int x)
{
	return  c->k87[(x>>24) & 255] | c->k65[(x>>16) & 255]|
		c->k43[(x>> 8) & 255] | c->k21[(x    ) & 255];
}

void Gost2814789_encrypt(const unsigned char *in, unsigned char *out,
	const GOST2814789_KEY *key)
{
	unsigned int n1, n2; /* As named in the GOST */
	c2l(in, n1);
	c2l(in, n2);

	/* Instead of swapping halves, swap names each round */
	n2 ^= f(key, n1 + key->key[0]); n1 ^= f(key, n2 + key->key[1]);
	n2 ^= f(key, n1 + key->key[2]); n1 ^= f(key, n2 + key->key[3]);
	n2 ^= f(key, n1 + key->key[4]); n1 ^= f(key, n2 + key->key[5]);
	n2 ^= f(key, n1 + key->key[6]); n1 ^= f(key, n2 + key->key[7]);

	n2 ^= f(key, n1 + key->key[0]); n1 ^= f(key, n2 + key->key[1]);
	n2 ^= f(key, n1 + key->key[2]); n1 ^= f(key, n2 + key->key[3]);
	n2 ^= f(key, n1 + key->key[4]); n1 ^= f(key, n2 + key->key[5]);
	n2 ^= f(key, n1 + key->key[6]); n1 ^= f(key, n2 + key->key[7]);

	n2 ^= f(key, n1 + key->key[0]); n1 ^= f(key, n2 + key->key[1]);
	n2 ^= f(key, n1 + key->key[2]); n1 ^= f(key, n2 + key->key[3]);
	n2 ^= f(key, n1 + key->key[4]); n1 ^= f(key, n2 + key->key[5]);
	n2 ^= f(key, n1 + key->key[6]); n1 ^= f(key, n2 + key->key[7]);

	n2 ^= f(key, n1 + key->key[7]); n1 ^= f(key, n2 + key->key[6]);
	n2 ^= f(key, n1 + key->key[5]); n1 ^= f(key, n2 + key->key[4]);
	n2 ^= f(key, n1 + key->key[3]); n1 ^= f(key, n2 + key->key[2]);
	n2 ^= f(key, n1 + key->key[1]); n1 ^= f(key, n2 + key->key[0]);

	l2c(n2, out);
	l2c(n1, out);
}

void Gost2814789_decrypt(const unsigned char *in, unsigned char *out,
	const GOST2814789_KEY *key)
{
	unsigned int n1, n2; /* As named in the GOST */
	c2l(in, n1);
	c2l(in, n2);

	/* Instead of swapping halves, swap names each round */
	n2 ^= f(key, n1 + key->key[0]); n1 ^= f(key, n2 + key->key[1]);
	n2 ^= f(key, n1 + key->key[2]); n1 ^= f(key, n2 + key->key[3]);
	n2 ^= f(key, n1 + key->key[4]); n1 ^= f(key, n2 + key->key[5]);
	n2 ^= f(key, n1 + key->key[6]); n1 ^= f(key, n2 + key->key[7]);

	n2 ^= f(key, n1 + key->key[7]); n1 ^= f(key, n2 + key->key[6]);
	n2 ^= f(key, n1 + key->key[5]); n1 ^= f(key, n2 + key->key[4]);
	n2 ^= f(key, n1 + key->key[3]); n1 ^= f(key, n2 + key->key[2]);
	n2 ^= f(key, n1 + key->key[1]); n1 ^= f(key, n2 + key->key[0]);

	n2 ^= f(key, n1 + key->key[7]); n1 ^= f(key, n2 + key->key[6]);
	n2 ^= f(key, n1 + key->key[5]); n1 ^= f(key, n2 + key->key[4]);
	n2 ^= f(key, n1 + key->key[3]); n1 ^= f(key, n2 + key->key[2]);
	n2 ^= f(key, n1 + key->key[1]); n1 ^= f(key, n2 + key->key[0]);

	n2 ^= f(key, n1 + key->key[7]); n1 ^= f(key, n2 + key->key[6]);
	n2 ^= f(key, n1 + key->key[5]); n1 ^= f(key, n2 + key->key[4]);
	n2 ^= f(key, n1 + key->key[3]); n1 ^= f(key, n2 + key->key[2]);
	n2 ^= f(key, n1 + key->key[1]); n1 ^= f(key, n2 + key->key[0]);

	l2c(n2, out);
	l2c(n1, out);
}

static void Gost2814789_mac(const unsigned char *in,
		GOST2814789_KEY *key)
{
	unsigned int n1, n2; /* As named in the GOST */
	unsigned char *p;
	int i;

	for (i = 0; i < 8; i++)
		key->buf[i] ^= in[i];

	p = key->buf;
	c2l(p, n1);
	c2l(p, n2);

	/* Instead of swapping halves, swap names each round */
	n2 ^= f(key, n1 + key->key[0]); n1 ^= f(key, n2 + key->key[1]);
	n2 ^= f(key, n1 + key->key[2]); n1 ^= f(key, n2 + key->key[3]);
	n2 ^= f(key, n1 + key->key[4]); n1 ^= f(key, n2 + key->key[5]);
	n2 ^= f(key, n1 + key->key[6]); n1 ^= f(key, n2 + key->key[7]);

	n2 ^= f(key, n1 + key->key[0]); n1 ^= f(key, n2 + key->key[1]);
	n2 ^= f(key, n1 + key->key[2]); n1 ^= f(key, n2 + key->key[3]);
	n2 ^= f(key, n1 + key->key[4]); n1 ^= f(key, n2 + key->key[5]);
	n2 ^= f(key, n1 + key->key[6]); n1 ^= f(key, n2 + key->key[7]);

	p = key->buf;
	l2c(n1, p);
	l2c(n2, p);
}


void Gost2814789_ecb_encrypt(const unsigned char *in, unsigned char *out,
	GOST2814789_KEY *key, const int enc)
{
	if (key->key_meshing && key->count == 1024) {
		Gost2814789_cryptopro_key_mesh(key);
		key->count = 0;
	}

	if (enc)
		Gost2814789_encrypt(in, out, key);
	else
		Gost2814789_decrypt(in, out, key);
}

static inline void Gost2814789_encrypt_mesh(unsigned char *iv, GOST2814789_KEY *key)
{
	if (key->key_meshing && key->count == 1024) {
		Gost2814789_cryptopro_key_mesh(key);
		Gost2814789_encrypt(iv, iv, key);
		key->count = 0;
	}
	Gost2814789_encrypt(iv, iv, key);
	key->count += 8;
}

static inline void Gost2814789_mac_mesh(const unsigned char *data, GOST2814789_KEY *key)
{
	if (key->key_meshing && key->count == 1024) {
		Gost2814789_cryptopro_key_mesh(key);
		key->count = 0;
	}
	Gost2814789_mac(data, key);
	key->count += 8;
}

void Gost2814789_cfb64_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, GOST2814789_KEY *key,
	unsigned char *ivec, int *num, const int enc)
{
    unsigned int n;
    size_t l = 0;

    OPENSSL_assert(in && out && key && ivec && num);

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
			Gost2814789_encrypt_mesh(ivec, key);
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
			Gost2814789_encrypt_mesh(ivec, key);
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
			Gost2814789_encrypt_mesh(ivec, key);
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
			Gost2814789_encrypt_mesh(ivec, key);
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
			Gost2814789_encrypt_mesh(ivec, key);
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
			Gost2814789_encrypt_mesh(ivec, key);
		}
		out[l] = ivec[n] ^ (c = in[l]); ivec[n] = c;
		++l;
		n = (n+1) % 8;
	}
	*num=n;
    }
}

static inline void Gost2814789_cnt_next(unsigned char *ivec,
		unsigned char *out,
		GOST2814789_KEY *key)
{
	unsigned char *p = ivec, *p2 = ivec;
	unsigned int val, val2;

	if (key->count == 0)
		Gost2814789_encrypt(ivec, ivec, key);

	if (key->key_meshing && key->count == 1024) {
		Gost2814789_cryptopro_key_mesh(key);
		Gost2814789_encrypt(ivec, ivec, key);
		key->count = 0;
	}

	c2l(p, val);
	val2 = val + 0x01010101;
	l2c(val2, p2);

	c2l(p, val);
	val2 = val + 0x01010104;
	if (val > val2) /* overflow */
		val2++;
	l2c(val2, p2);

	Gost2814789_encrypt(ivec, out, key);
	key->count += 8;
}

void Gost2814789_cnt_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, GOST2814789_KEY *key,
	unsigned char *ivec, unsigned char *cnt_buf, int *num)
{
	unsigned int n;
	size_t l=0;

	OPENSSL_assert(in && out && key && cnt_buf && num);

	n = *num;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
	if (8%sizeof(size_t) == 0) do { /* always true actually */
		while (n && len) {
			*(out++) = *(in++) ^ cnt_buf[n];
			--len;
			n = (n+1) % 8;
		}

#ifdef __STRICT_ALIGNMENT
		if (((size_t)in|(size_t)out|(size_t)ivec)%sizeof(size_t) != 0)
			break;
#endif
		while (len>=8) {
			Gost2814789_cnt_next(ivec, cnt_buf, key);
			for (; n<8; n+=sizeof(size_t))
				*(size_t *)(out+n) =
				*(size_t *)(in+n) ^ *(size_t *)(cnt_buf+n);
			len -= 8;
			out += 8;
			in  += 8;
			n = 0;
		}
		if (len) {
			Gost2814789_cnt_next(ivec, cnt_buf, key);
			while (len--) {
				out[n] = in[n] ^ cnt_buf[n];
				++n;
			}
		}
		*num = n;
		return;
	} while(0);
	/* the rest would be commonly eliminated by x86* compiler */
#endif
	while (l<len) {
		if (n==0)
			Gost2814789_cnt_next(ivec, cnt_buf, key);
		out[l] = in[l] ^ cnt_buf[n];
		++l;
		n = (n+1) % 8;
	}

	*num=n;
}
