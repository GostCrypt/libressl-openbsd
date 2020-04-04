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
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/gost.h>
#include <openssl/err.h>

#include "gost_locl.h"
#include "gost_asn1.h"

static const ASN1_TEMPLATE MASKED_GOST_KEY_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(MASKED_GOST_KEY, masked_priv_key),
		.field_name = "masked_priv_key",
		.item = &ASN1_OCTET_STRING_it,
	},
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(MASKED_GOST_KEY, public_key),
		.field_name = "public_key",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM MASKED_GOST_KEY_it = {
	.itype = ASN1_ITYPE_NDEF_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = MASKED_GOST_KEY_seq_tt,
	.tcount = sizeof(MASKED_GOST_KEY_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(MASKED_GOST_KEY),
	.sname = "MASKED_GOST_KEY",
};

MASKED_GOST_KEY *
d2i_MASKED_GOST_KEY(MASKED_GOST_KEY **a, const unsigned char **in, long len)
{
	return (MASKED_GOST_KEY *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &MASKED_GOST_KEY_it);
}

int
i2d_MASKED_GOST_KEY(MASKED_GOST_KEY *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &MASKED_GOST_KEY_it);
}

MASKED_GOST_KEY *
MASKED_GOST_KEY_new(void)
{
	return (MASKED_GOST_KEY *)ASN1_item_new(&MASKED_GOST_KEY_it);
}

void
MASKED_GOST_KEY_free(MASKED_GOST_KEY *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &MASKED_GOST_KEY_it);
}

static const ASN1_TEMPLATE GOST_KEY_TRANSPORT_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_KEY_TRANSPORT, key_info),
		.field_name = "key_info",
		.item = &GOST_KEY_INFO_it,
	},
	{
		.flags = ASN1_TFLG_IMPLICIT,
		.tag = 0,
		.offset = offsetof(GOST_KEY_TRANSPORT, key_agreement_info),
		.field_name = "key_agreement_info",
		.item = &GOST_KEY_AGREEMENT_INFO_it,
	},
};

const ASN1_ITEM GOST_KEY_TRANSPORT_it = {
	.itype = ASN1_ITYPE_NDEF_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = GOST_KEY_TRANSPORT_seq_tt,
	.tcount = sizeof(GOST_KEY_TRANSPORT_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(GOST_KEY_TRANSPORT),
	.sname = "GOST_KEY_TRANSPORT",
};

GOST_KEY_TRANSPORT *
d2i_GOST_KEY_TRANSPORT(GOST_KEY_TRANSPORT **a, const unsigned char **in, long len)
{
	return (GOST_KEY_TRANSPORT *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &GOST_KEY_TRANSPORT_it);
}

int
i2d_GOST_KEY_TRANSPORT(GOST_KEY_TRANSPORT *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &GOST_KEY_TRANSPORT_it);
}

GOST_KEY_TRANSPORT *
GOST_KEY_TRANSPORT_new(void)
{
	return (GOST_KEY_TRANSPORT *)ASN1_item_new(&GOST_KEY_TRANSPORT_it);
}

void
GOST_KEY_TRANSPORT_free(GOST_KEY_TRANSPORT *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &GOST_KEY_TRANSPORT_it);
}

static const ASN1_TEMPLATE GOST_KEY_INFO_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_KEY_INFO, encrypted_key),
		.field_name = "encrypted_key",
		.item = &ASN1_OCTET_STRING_it,
	},
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_KEY_INFO, imit),
		.field_name = "imit",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM GOST_KEY_INFO_it = {
	.itype = ASN1_ITYPE_NDEF_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = GOST_KEY_INFO_seq_tt,
	.tcount = sizeof(GOST_KEY_INFO_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(GOST_KEY_INFO),
	.sname = "GOST_KEY_INFO",
};

GOST_KEY_INFO *
d2i_GOST_KEY_INFO(GOST_KEY_INFO **a, const unsigned char **in, long len)
{
	return (GOST_KEY_INFO *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &GOST_KEY_INFO_it);
}

int
i2d_GOST_KEY_INFO(GOST_KEY_INFO *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &GOST_KEY_INFO_it);
}

GOST_KEY_INFO *
GOST_KEY_INFO_new(void)
{
	return (GOST_KEY_INFO *)ASN1_item_new(&GOST_KEY_INFO_it);
}

void
GOST_KEY_INFO_free(GOST_KEY_INFO *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &GOST_KEY_INFO_it);
}

static const ASN1_TEMPLATE GOST_KEY_AGREEMENT_INFO_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_KEY_AGREEMENT_INFO, cipher),
		.field_name = "cipher",
		.item = &ASN1_OBJECT_it,
	},
	{
		.flags = ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
		.tag = 0,
		.offset = offsetof(GOST_KEY_AGREEMENT_INFO, ephem_key),
		.field_name = "ephem_key",
		.item = &X509_PUBKEY_it,
	},
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_KEY_AGREEMENT_INFO, eph_iv),
		.field_name = "eph_iv",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM GOST_KEY_AGREEMENT_INFO_it = {
	.itype = ASN1_ITYPE_NDEF_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = GOST_KEY_AGREEMENT_INFO_seq_tt,
	.tcount = sizeof(GOST_KEY_AGREEMENT_INFO_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(GOST_KEY_AGREEMENT_INFO),
	.sname = "GOST_KEY_AGREEMENT_INFO",
};

GOST_KEY_AGREEMENT_INFO *
d2i_GOST_KEY_AGREEMENT_INFO(GOST_KEY_AGREEMENT_INFO **a, const unsigned char **in, long len)
{
	return (GOST_KEY_AGREEMENT_INFO *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &GOST_KEY_AGREEMENT_INFO_it);
}

int
i2d_GOST_KEY_AGREEMENT_INFO(GOST_KEY_AGREEMENT_INFO *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &GOST_KEY_AGREEMENT_INFO_it);
}

GOST_KEY_AGREEMENT_INFO *
GOST_KEY_AGREEMENT_INFO_new(void)
{
	return (GOST_KEY_AGREEMENT_INFO *)ASN1_item_new(&GOST_KEY_AGREEMENT_INFO_it);
}

void
GOST_KEY_AGREEMENT_INFO_free(GOST_KEY_AGREEMENT_INFO *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &GOST_KEY_AGREEMENT_INFO_it);
}


static const ASN1_TEMPLATE GOST_KEY_PARAMS_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_KEY_PARAMS, key_params),
		.field_name = "key_params",
		.item = &ASN1_OBJECT_it,
	},
	{
		.flags = ASN1_TFLG_OPTIONAL,
		.tag = 0,
		.offset = offsetof(GOST_KEY_PARAMS, hash_params),
		.field_name = "hash_params",
		.item = &ASN1_OBJECT_it,
	},
	{
		.flags = ASN1_TFLG_OPTIONAL,
		.tag = 0,
		.offset = offsetof(GOST_KEY_PARAMS, cipher_params),
		.field_name = "cipher_params",
		.item = &ASN1_OBJECT_it,
	},
};

const ASN1_ITEM GOST_KEY_PARAMS_it = {
	.itype = ASN1_ITYPE_NDEF_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = GOST_KEY_PARAMS_seq_tt,
	.tcount = sizeof(GOST_KEY_PARAMS_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(GOST_KEY_PARAMS),
	.sname = "GOST_KEY_PARAMS",
};

GOST_KEY_PARAMS *
d2i_GOST_KEY_PARAMS(GOST_KEY_PARAMS **a, const unsigned char **in, long len)
{
	return (GOST_KEY_PARAMS *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &GOST_KEY_PARAMS_it);
}

int
i2d_GOST_KEY_PARAMS(GOST_KEY_PARAMS *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &GOST_KEY_PARAMS_it);
}

GOST_KEY_PARAMS *
GOST_KEY_PARAMS_new(void)
{
	return (GOST_KEY_PARAMS *)ASN1_item_new(&GOST_KEY_PARAMS_it);
}

void
GOST_KEY_PARAMS_free(GOST_KEY_PARAMS *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &GOST_KEY_PARAMS_it);
}

static const ASN1_TEMPLATE GOST_CIPHER_PARAMS_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_CIPHER_PARAMS, iv),
		.field_name = "iv",
		.item = &ASN1_OCTET_STRING_it,
	},
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST_CIPHER_PARAMS, enc_param_set),
		.field_name = "enc_param_set",
		.item = &ASN1_OBJECT_it,
	},
};

const ASN1_ITEM GOST_CIPHER_PARAMS_it = {
	.itype = ASN1_ITYPE_NDEF_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = GOST_CIPHER_PARAMS_seq_tt,
	.tcount = sizeof(GOST_CIPHER_PARAMS_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(GOST_CIPHER_PARAMS),
	.sname = "GOST_CIPHER_PARAMS",
};

GOST_CIPHER_PARAMS *
d2i_GOST_CIPHER_PARAMS(GOST_CIPHER_PARAMS **a, const unsigned char **in, long len)
{
	return (GOST_CIPHER_PARAMS *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &GOST_CIPHER_PARAMS_it);
}

int
i2d_GOST_CIPHER_PARAMS(GOST_CIPHER_PARAMS *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &GOST_CIPHER_PARAMS_it);
}

GOST_CIPHER_PARAMS *
GOST_CIPHER_PARAMS_new(void)
{
	return (GOST_CIPHER_PARAMS *)ASN1_item_new(&GOST_CIPHER_PARAMS_it);
}

void
GOST_CIPHER_PARAMS_free(GOST_CIPHER_PARAMS *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &GOST_CIPHER_PARAMS_it);
}

static const ASN1_TEMPLATE GOST3412_ENCRYPTION_PARAMS_seq_tt[] = {
	{
		.flags = 0,
		.tag = 0,
		.offset = offsetof(GOST3412_ENCRYPTION_PARAMS, iv),
		.field_name = "iv",
		.item = &ASN1_OCTET_STRING_it,
	},
};

const ASN1_ITEM GOST3412_ENCRYPTION_PARAMS_it = {
	.itype = ASN1_ITYPE_NDEF_SEQUENCE,
	.utype = V_ASN1_SEQUENCE,
	.templates = GOST3412_ENCRYPTION_PARAMS_seq_tt,
	.tcount = sizeof(GOST3412_ENCRYPTION_PARAMS_seq_tt) / sizeof(ASN1_TEMPLATE),
	.funcs = NULL,
	.size = sizeof(GOST3412_ENCRYPTION_PARAMS),
	.sname = "GOST3412_ENCRYPTION_PARAMS",
};

GOST3412_ENCRYPTION_PARAMS *
d2i_GOST3412_ENCRYPTION_PARAMS(GOST3412_ENCRYPTION_PARAMS **a, const unsigned char **in, long len)
{
	return (GOST3412_ENCRYPTION_PARAMS *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
	    &GOST3412_ENCRYPTION_PARAMS_it);
}

int
i2d_GOST3412_ENCRYPTION_PARAMS(GOST3412_ENCRYPTION_PARAMS *a, unsigned char **out)
{
	return ASN1_item_i2d((ASN1_VALUE *)a, out, &GOST3412_ENCRYPTION_PARAMS_it);
}

GOST3412_ENCRYPTION_PARAMS *
GOST3412_ENCRYPTION_PARAMS_new(void)
{
	return (GOST3412_ENCRYPTION_PARAMS *)ASN1_item_new(&GOST3412_ENCRYPTION_PARAMS_it);
}

void
GOST3412_ENCRYPTION_PARAMS_free(GOST3412_ENCRYPTION_PARAMS *a)
{
	ASN1_item_free((ASN1_VALUE *)a, &GOST3412_ENCRYPTION_PARAMS_it);
}

int
gost3412_ctr_acpkm_set_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params, unsigned int il)
{
	int len = 0;
	unsigned char *buf = NULL;
	unsigned char *p = NULL;
	GOST3412_ENCRYPTION_PARAMS *gcp = NULL;
	ASN1_OCTET_STRING *os = NULL;

	if (params == NULL)
		return 0;

	gcp = GOST3412_ENCRYPTION_PARAMS_new();
	if (ASN1_OCTET_STRING_set(gcp->iv, NULL, il + 8) == 0) {
		GOST3412_ENCRYPTION_PARAMS_free(gcp);
		GOSTerror(ERR_R_ASN1_LIB);
		return 0;
	}

	memcpy(gcp->iv->data, ctx->iv, il);
	memcpy(gcp->iv->data + il, ctx->oiv, 8);

	len = i2d_GOST3412_ENCRYPTION_PARAMS(gcp, NULL);
	p = buf = malloc(len);
	if (buf == NULL) {
		GOST3412_ENCRYPTION_PARAMS_free(gcp);
		GOSTerror(ERR_R_MALLOC_FAILURE);
		return 0;
	}
	i2d_GOST3412_ENCRYPTION_PARAMS(gcp, &p);
	GOST3412_ENCRYPTION_PARAMS_free(gcp);

	os = ASN1_OCTET_STRING_new();
	if (os == NULL) {
		free(buf);
		GOSTerror(ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (ASN1_OCTET_STRING_set(os, buf, len) == 0) {
		ASN1_OCTET_STRING_free(os);
		free(buf);
		GOSTerror(ERR_R_ASN1_LIB);
		return 0;
	}
	free(buf);

	ASN1_TYPE_set(params, V_ASN1_SEQUENCE, os);

	return 1;
}

int
gost3412_ctr_acpkm_get_asn1_params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *params, unsigned int il)
{
	int len;
	GOST3412_ENCRYPTION_PARAMS *gcp = NULL;
	unsigned char *p;

	if (ASN1_TYPE_get(params) != V_ASN1_SEQUENCE)
		return -1;

	p = params->value.sequence->data;

	gcp = d2i_GOST3412_ENCRYPTION_PARAMS(NULL, (const unsigned char **)&p,
	    params->value.sequence->length);

	len = gcp->iv->length;
	if (len != il + 8 || len > sizeof(ctx->iv)) {
		GOST3412_ENCRYPTION_PARAMS_free(gcp);
		GOSTerror(GOST_R_INVALID_IV_LENGTH);
		return -1;
	}

	memcpy(ctx->iv, gcp->iv->data, il);
	memset(ctx->iv + il, 0, EVP_MAX_IV_LENGTH - il);
	memcpy(ctx->oiv, gcp->iv->data + il, 8);

	GOST3412_ENCRYPTION_PARAMS_free(gcp);

	return 1;
}

#endif
