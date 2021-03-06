/* $OpenBSD: kdftree_locl.h,v 1.4 2019/11/21 20:02:20 tim Exp $ */
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

#ifndef OPENSSL_HEADER_KDFTREE_LOCL_H
#define OPENSSL_HEADER_KDFTREE_LOCL_H

#include <openssl/hmac.h>

int kdf_tree_block(HMAC_CTX *ctx,
		const unsigned char *i, unsigned int i_length,
		const unsigned char *label, unsigned int label_length,
		const unsigned char *seed, unsigned int seed_length,
		const unsigned char *l, unsigned int l_length,
		unsigned char *out, unsigned int *length);

#endif  /* OPENSSL_HEADER_KDFTREE_LOCL_H */
