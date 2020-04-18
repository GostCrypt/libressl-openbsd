/* $OpenBSD: kdftree.h,v 1.4 2019/11/21 20:02:20 tim Exp $ */
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

#ifndef OPENSSL_HEADER_KDFTREE_H
#define OPENSSL_HEADER_KDFTREE_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <openssl/evp.h>

/* See RFC 7836 Sections 4.4 */
int KDF_TREE(const EVP_MD *md, ENGINE *impl,
		const unsigned char *key, unsigned int key_length,
		const unsigned char *label, unsigned int label_length,
		const unsigned char *seed, unsigned int seed_length,
		size_t r,
		unsigned char *out, unsigned int length);

/* KDF function from RFC 7836 Section 4.5. Fast equivalent of KDF_TREE with r=1 and L=EVP_MD_size(md) */
int KDF_TREE_SIMPLE(const EVP_MD *md, ENGINE *impl,
		const unsigned char *key, unsigned int key_length,
		const unsigned char *label, unsigned int label_length,
		const unsigned char *seed, unsigned int seed_length,
		unsigned char *out);

/* TLSTREE is an external re-keying function (see
 * draft-smyshlyaev-tls12-gost-suites Section 8 for the definition, RFC 8645
 * Section 5.2.2 for the discussion of the approach. */

/* Opaque */
typedef struct TLSTREE_CTX_st TLSTREE_CTX;

typedef struct tlstree_const_st {
	uint64_t c1, c2, c3;
} TLSTREE_CONST;

TLSTREE_CTX *TLSTREE_CTX_new(void);
void TLSTREE_CTX_free(TLSTREE_CTX *ctx);

int TLSTREE_Init(TLSTREE_CTX *ctx,
		const TLSTREE_CONST *tlsconst,
		const EVP_MD *md, ENGINE *impl,
		const unsigned char *key,
		int key_length);
int TLSTREE_GET(TLSTREE_CTX *ctx,
		unsigned char *seq,
		unsigned char *out);

#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_KDFTREE_H */
