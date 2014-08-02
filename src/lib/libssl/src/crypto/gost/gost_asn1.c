/**********************************************************************
 *                          gost_keytrans.c                           *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under the same license as OpenSSL *
 *                                                                    *
 *   ASN1 structure definition for GOST key transport                 *
 *          Requires OpenSSL 0.9.9 for compilation                    *
 **********************************************************************/

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_GOST
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/gost.h>

#include "gost_locl.h"

ASN1_NDEF_SEQUENCE(GOST_CIPHER_PARAMS) = {
	ASN1_SIMPLE(GOST_CIPHER_PARAMS, iv, ASN1_OCTET_STRING),
	ASN1_SIMPLE(GOST_CIPHER_PARAMS, enc_param_set, ASN1_OBJECT),
} ASN1_NDEF_SEQUENCE_END(GOST_CIPHER_PARAMS)
IMPLEMENT_ASN1_FUNCTIONS(GOST_CIPHER_PARAMS)

#endif
