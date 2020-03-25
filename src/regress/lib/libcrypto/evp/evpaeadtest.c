/*	$OpenBSD: evptest.c,v 1.9 2020/01/26 02:46:26 tb Exp $	*/
/* Written by Ben Laurie, 2001 */
/*
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/conf.h>

static void
hexdump(FILE *f, const char *title, const unsigned char *s, int l)
{
	int n = 0;

	fprintf(f, "%s",title);
	for (; n < l; ++n) {
		if ((n % 16) == 0)
			fprintf(f, "\n%04x",n);
		fprintf(f, " %02x",s[n]);
	}
	fprintf(f, "\n");
}

static int
convert(unsigned char *s)
{
	unsigned char *d;

	for (d = s; *s; s += 2,++d) {
		unsigned int n;

		if (!s[1]) {
			fprintf(stderr, "Odd number of hex digits!\n");
			exit(4);
		}
		if (sscanf((char *)s, "%2x", &n) != 1) {
			fprintf(stderr, "Invalid hex value at %s\n", s);
			exit(4);
		}

		*d = (unsigned char)n;
	}
	return s - d;
}

static char *
sstrsep(char **string, const char *delim)
{
	char isdelim[256];
	char *token = *string;

	if (**string == 0)
		return NULL;

	memset(isdelim, 0, 256);
	isdelim[0] = 1;

	while (*delim) {
		isdelim[(unsigned char)(*delim)] = 1;
		delim++;
	}

	while (!isdelim[(unsigned char)(**string)]) {
		(*string)++;
	}

	if (**string) {
		**string = 0;
		(*string)++;
	}

	return token;
}

static unsigned char *
ustrsep(char **p, const char *sep)
{
	return (unsigned char *)sstrsep(p, sep);
}

static int
test1_exit(int ec)
{
	exit(ec);
	return(0);		/* To keep some compilers quiet */
}

static int
test_cipher(const char *cipher, const unsigned char *key, int kn,
    const unsigned char *iv, int in,
    const unsigned char *aad, int an,
    const unsigned char *plaintext, int pn,
    const unsigned char *ciphertext, int cn,
    const unsigned char *tag, int tn,
    int encdec)
{
	EVP_CIPHER_CTX ctx;
	unsigned char out[4096];
	const unsigned char *eiv;
	int outl, outl2;

	const EVP_CIPHER *c;

	c = EVP_get_cipherbyname(cipher);
	if (!c)
		return 0;

	printf("Testing cipher %s%s\n", EVP_CIPHER_name(c),
	    (encdec == 1 ? "(encrypt)" : (encdec == 0 ? "(decrypt)" : "(encrypt/decrypt)")));
	hexdump(stdout, "Key",key,kn);
	hexdump(stdout, "IV",iv,in);
	hexdump(stdout, "AAD",aad,an);
	hexdump(stdout, "Plaintext",plaintext,pn);
	hexdump(stdout, "Ciphertext",ciphertext,cn);
	hexdump(stdout, "Tag",tag,tn);

	if (kn != c->key_len) {
		fprintf(stderr, "Key length doesn't match, got %d expected %lu\n",kn,
		    (unsigned long)c->key_len);
		test1_exit(1);
	}
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CIPHER_CTX_set_flags(&ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
	if (encdec != 0) {
		eiv = iv;
		if (EVP_CIPHER_mode(c) == EVP_CIPH_WRAP_MODE && in == 0)
			eiv = NULL;
		if (!EVP_EncryptInit_ex(&ctx, c, NULL, key, eiv)) {
			fprintf(stderr, "EncryptInit failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(2);
		}
		EVP_CIPHER_CTX_set_padding(&ctx, 0);

		if (!EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
			fprintf(stderr, "Encrypt failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(3);
		}
		if (!EVP_EncryptUpdate(&ctx, out, &outl, plaintext, pn)) {
			fprintf(stderr, "Encrypt failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(4);
		}
		if (!EVP_EncryptFinal_ex(&ctx, out + outl, &outl2)) {
			fprintf(stderr, "EncryptFinal failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(5);
		}

		if (outl + outl2 != cn) {
			fprintf(stderr, "Ciphertext length mismatch got %d expected %d\n",
			    outl + outl2, cn);
			test1_exit(6);
		}

		if (memcmp(out, ciphertext, cn)) {
			fprintf(stderr, "Ciphertext mismatch\n");
			hexdump(stderr, "Got",out,cn);
			hexdump(stderr, "Expected",ciphertext,cn);
			test1_exit(7);
		}

		if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, tn, out)) {
			fprintf(stderr, "GET_TAG failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(8);
		}

		if (memcmp(out, tag, tn)) {
			fprintf(stderr, "Ciphertext mismatch\n");
			hexdump(stderr, "Got",out,tn);
			hexdump(stderr, "Expected",tag,cn);
			test1_exit(9);
		}

	}

	if (encdec <= 0) {
		eiv = iv;
		if (EVP_CIPHER_mode(c) == EVP_CIPH_WRAP_MODE && in == 0)
			eiv = NULL;
		if (!EVP_DecryptInit_ex(&ctx, c,NULL, key, eiv)) {
			fprintf(stderr, "DecryptInit failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(10);
		}
		EVP_CIPHER_CTX_set_padding(&ctx, 0);

		if (!EVP_DecryptUpdate(&ctx, NULL, &outl, aad, an)) {
			fprintf(stderr, "Encrypt failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(10);
		}
		if (!EVP_DecryptUpdate(&ctx, out, &outl, ciphertext, cn)) {
			fprintf(stderr, "Decrypt failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(12);
		}

		if(!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, tn, (void *)tag)) {
			fprintf(stderr, "SET_TAG failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(13);
		}

		if (!EVP_DecryptFinal_ex(&ctx, out + outl, &outl2)) {
			fprintf(stderr, "DecryptFinal failed\n");
			ERR_print_errors_fp(stderr);
			test1_exit(14);
		}

		if (outl + outl2 != pn) {
			fprintf(stderr, "Plaintext length mismatch got %d expected %d\n",
			    outl + outl2, pn);
			test1_exit(15);
		}

		if (memcmp(out, plaintext, pn)) {
			fprintf(stderr, "Plaintext mismatch\n");
			hexdump(stderr, "Got",out,pn);
			hexdump(stderr, "Expected",plaintext,pn);
			test1_exit(16);
		}
	}

	EVP_CIPHER_CTX_cleanup(&ctx);

	printf("\n");

	return 1;
}

int
main(int argc, char **argv)
{
	const char *szTestFile;
	FILE *f;

	if (argc != 2) {
		fprintf(stderr, "%s <test file>\n",argv[0]);
		exit(1);
	}

	szTestFile = argv[1];

	f=fopen(szTestFile, "r");
	if (!f) {
		perror(szTestFile);
		exit(2);
	}

	/* Load up the software EVP_CIPHER and EVP_MD definitions */
	OpenSSL_add_all_ciphers();
#ifndef OPENSSL_NO_ENGINE
	/* Load all compiled-in ENGINEs */
	ENGINE_load_builtin_engines();
#endif
#if 0
	OPENSSL_config();
#endif
#ifndef OPENSSL_NO_ENGINE
    /* Register all available ENGINE implementations of ciphers and digests.
     * This could perhaps be changed to "ENGINE_register_all_complete()"? */
	ENGINE_register_all_ciphers();
    /* If we add command-line options, this statement should be switchable.
     * It'll prevent ENGINEs being ENGINE_init()ialised for cipher/digest use if
     * they weren't already initialised. */
	/* ENGINE_set_cipher_flags(ENGINE_CIPHER_FLAG_NOINIT); */
#endif

	for (;;) {
		char line[8 * 1024];
		char *p;
		char *cipher;
		unsigned char *iv, *key, *plaintext, *ciphertext, *aad, *tag;
		int encdec;
		int kn, in, pn, cn, an, tn;

		if (!fgets((char *)line, sizeof line, f))
			break;
		if (line[0] == '#' || line[0] == '\n')
			continue;
		p = line;
		cipher=sstrsep(&p, ":");
		key=ustrsep(&p, ":");
		iv=ustrsep(&p, ":");
		aad=ustrsep(&p, ":");
		plaintext=ustrsep(&p, ":");
		ciphertext=ustrsep(&p, ":");
		tag=ustrsep(&p, ":");
		if (p[-1] == '\n') {
			p[-1] = '\0';
			encdec = -1;
		} else {
			encdec = atoi(sstrsep(&p, "\n"));
		}

		kn = convert(key);
		in = convert(iv);
		an = convert(aad);
		pn = convert(plaintext);
		cn = convert(ciphertext);
		tn = convert(tag);

		if (!test_cipher(cipher, key, kn, iv, in, aad, an, plaintext, pn, ciphertext, cn, tag, tn, encdec)) {
#ifdef OPENSSL_NO_GOST
			if (strstr(cipher, "magma") == cipher ||
			    strstr(cipher, "kuznyechik") == cipher) {
				fprintf(stdout, "Cipher disabled, skipping %s\n", cipher);
				continue;
			}
#endif
			fprintf(stderr, "Can't find %s\n",cipher);
			exit(3);
		}
	}
	fclose(f);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
	CRYPTO_mem_leaks_fp(stderr);

	return 0;
}
