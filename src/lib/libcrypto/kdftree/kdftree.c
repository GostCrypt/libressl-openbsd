/* $OpenBSD: tlstree.h,v 1.4 2019/11/21 20:02:20 tim Exp $ */
/* Copyright (c) 2020, Dmitry Baryshkov
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

#include <openssl/kdftree.h>
#include <openssl/hmac.h>
#include "kdftree_locl.h"

#include <string.h>

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>>16)&0xff),	\
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff),	\
			 *((c)++)=(unsigned char)(((l)    )&0xff))

int
kdf_tree_block(HMAC_CTX *ctx,
		const unsigned char *i, unsigned int i_length,
		const unsigned char *label, unsigned int label_length,
		const unsigned char *seed, unsigned int seed_length,
		const unsigned char *l, unsigned int l_length,
		unsigned char *out, unsigned int *length)
{
	/* i label 0x00 seed l */
	static const unsigned char data[1] = { 0x00 };

	if (!HMAC_Init_ex(ctx, NULL, 0, NULL, NULL) ||
	    !HMAC_Update(ctx, i, i_length) ||
	    !HMAC_Update(ctx, label, label_length) ||
	    !HMAC_Update(ctx, data, 1) ||
	    !HMAC_Update(ctx, seed, seed_length) ||
	    !HMAC_Update(ctx, l, l_length))
		return 0;

	return HMAC_Final(ctx, out, length);
}

int KDF_TREE(const EVP_MD *md, ENGINE *impl,
		const unsigned char *key, unsigned int key_length,
		const unsigned char *label, unsigned int label_length,
		const unsigned char *seed, unsigned int seed_length,
		size_t r,
		unsigned char *out, unsigned int length)
{
	HMAC_CTX ctx;
	unsigned int i;
	unsigned char i_block[4], l_block[8];
	unsigned int l_length, l_off;
	unsigned char *p;
	int md_size = EVP_MD_size(md);

	HMAC_CTX_init(&ctx);

	if (!HMAC_Init_ex(&ctx, key, key_length, md, impl))
		return 0;

	p = l_block;
	/* bitlength */
	l2c(length >> 29, p);
	l2c(length * 8, p);

	/* Calculate how many bytes will it take */
	for (l_off = 0; l_off < 8; l_off++)
		if (l_block[l_off] != 0)
			break;

	l_length = 8 - l_off;
	for (i = 1; length >= md_size; i++) {
		unsigned int block = md_size;
		p = i_block;
		l2c(i, p);
		if (!kdf_tree_block(&ctx,
				i_block + 4 - r, r,
				label, label_length,
				seed, seed_length,
				l_block + l_off, l_length,
				out, &block)) {
			HMAC_CTX_cleanup(&ctx);
			return 0;
		}
		out += block;
		length -= block;
	}
	if (length > 0) {
		unsigned char tmp[EVP_MAX_MD_SIZE];
		unsigned int block = length;

		p = i_block;
		l2c(i, p);
		if (!kdf_tree_block(&ctx,
				i_block + 4 - r, r,
				label, label_length,
				seed, seed_length,
				l_block + l_off, l_length,
				tmp, &block)) {
			HMAC_CTX_cleanup(&ctx);
			return 0;
		}
		memcpy(out, tmp, length);
	}
	HMAC_CTX_cleanup(&ctx);

	return 1;
}

int KDF_TREE_SIMPLE(const EVP_MD *md, ENGINE *impl,
		const unsigned char *key, unsigned int key_length,
		const unsigned char *label, unsigned int label_length,
		const unsigned char *seed, unsigned int seed_length,
		unsigned char *out)
{
	HMAC_CTX ctx;
	static unsigned char data1[1] = { 0x01 };
	unsigned char data2[2];
	int d2_length;
	int md_size = EVP_MD_size(md);
	int ret = 1;

	/* bitlength */
	if (md_size >= 32) {
		data2[0] = md_size / 32;
		data2[1] = (md_size * 8) & 0xff;
		d2_length = 2;
	} else {
		data2[0] = (md_size * 8) & 0xff;
		d2_length = 1;
	}

	HMAC_CTX_init(&ctx);

	if (!HMAC_Init_ex(&ctx, key, key_length, md, impl) ||
	    !kdf_tree_block(&ctx,
			data1, 1,
			label, label_length,
			seed, seed_length,
			data2, d2_length,
			out, &md_size))
		ret = 0;

	HMAC_CTX_cleanup(&ctx);

	return ret;
}
