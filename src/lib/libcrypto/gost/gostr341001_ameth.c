/* $OpenBSD: gostr341001_ameth.c,v 1.16 2020/06/05 17:17:22 jsing Exp $ */
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
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#ifndef OPENSSL_NO_CMS
#include <openssl/cms.h>
#endif
#include <openssl/gost.h>


#include "asn1_locl.h"
#include "gost_locl.h"
#include "gost_asn1.h"

static void
pkey_free_gost01(EVP_PKEY *key)
{
	GOST_KEY_free(key->pkey.gost);
}

/*
 * Parses GOST algorithm parameters from X509_ALGOR and
 * modifies pkey setting NID and parameters
 */
static int
decode_gost01_algor_params(EVP_PKEY *pkey, const unsigned char **p, int len)
{
	int param_nid = NID_undef, digest_nid = NID_undef;
	GOST_KEY_PARAMS *gkp = NULL;
	EC_GROUP *group;
	GOST_KEY *ec;

	gkp = d2i_GOST_KEY_PARAMS(NULL, p, len);
	if (gkp == NULL) {
		GOSTerror(GOST_R_BAD_PKEY_PARAMETERS_FORMAT);
		return 0;
	}
	param_nid = OBJ_obj2nid(gkp->key_params);
	if (gkp->hash_params)
		digest_nid = OBJ_obj2nid(gkp->hash_params);
	else {
		switch (param_nid) {
			case NID_id_tc26_gost_3410_12_256_paramSetA:
			case NID_id_tc26_gost_3410_12_256_paramSetB:
			case NID_id_tc26_gost_3410_12_256_paramSetC:
			case NID_id_tc26_gost_3410_12_256_paramSetD:
				digest_nid = NID_id_tc26_gost3411_2012_256;
				break;
			case NID_id_tc26_gost_3410_12_512_paramSetTest:
			case NID_id_tc26_gost_3410_12_512_paramSetA:
			case NID_id_tc26_gost_3410_12_512_paramSetB:
			case NID_id_tc26_gost_3410_12_512_paramSetC:
				digest_nid = NID_id_tc26_gost3411_2012_512;
				break;
			default:
				digest_nid = NID_undef;
		}
	}
	GOST_KEY_PARAMS_free(gkp);

	if (digest_nid == NID_undef) {
		GOSTerror(GOST_R_BAD_PKEY_PARAMETERS_FORMAT);
		return 0;
	}

	ec = pkey->pkey.gost;
	if (ec == NULL) {
		ec = GOST_KEY_new();
		if (ec == NULL) {
			GOSTerror(ERR_R_MALLOC_FAILURE);
			return 0;
		}
		if (EVP_PKEY_assign_GOST(pkey, ec) == 0)
			return 0;
	}

	group = EC_GROUP_new_by_curve_name(param_nid);
	if (group == NULL) {
		GOSTerror(EC_R_EC_GROUP_NEW_BY_NAME_FAILURE);
		return 0;
	}
	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	if (GOST_KEY_set_group(ec, group) == 0) {
		EC_GROUP_free(group);
		return 0;
	}
	EC_GROUP_free(group);
	if (GOST_KEY_set_digest(ec, digest_nid) == 0)
		return 0;
	return 1;
}

static ASN1_STRING *
encode_gost01_algor_params(const EVP_PKEY *key)
{
	ASN1_STRING *params = ASN1_STRING_new();
	GOST_KEY_PARAMS *gkp = GOST_KEY_PARAMS_new();
	int pkey_param_nid = NID_undef;

	if (params == NULL || gkp == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		ASN1_STRING_free(params);
		params = NULL;
		goto err;
	}

	pkey_param_nid =
	    EC_GROUP_get_curve_name(GOST_KEY_get0_group(key->pkey.gost));
	gkp->key_params = OBJ_nid2obj(pkey_param_nid);
	switch (pkey_param_nid) {
	case NID_id_GostR3410_2001_TestParamSet:
	case NID_id_GostR3410_2001_CryptoPro_A_ParamSet:
	case NID_id_GostR3410_2001_CryptoPro_B_ParamSet:
	case NID_id_GostR3410_2001_CryptoPro_C_ParamSet:
	case NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet:
	case NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet:
	case NID_id_tc26_gost_3410_12_512_paramSetA:
	case NID_id_tc26_gost_3410_12_512_paramSetB:
		gkp->hash_params = OBJ_nid2obj(GOST_KEY_get_digest(key->pkey.gost));
		break;
	default:
		gkp->hash_params = NULL;
		break;
	}
	/*gkp->cipher_params = OBJ_nid2obj(cipher_param_nid); */
	params->length = i2d_GOST_KEY_PARAMS(gkp, &params->data);
	if (params->length <= 0) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		ASN1_STRING_free(params);
		params = NULL;
		goto err;
	}
	params->type = V_ASN1_SEQUENCE;
err:
	GOST_KEY_PARAMS_free(gkp);
	return params;
}

static ASN1_STRING *
encode_gost01_kexp_params(EVP_PKEY *pkey)
{
	int digest = GOST_KEY_get_digest(pkey->pkey.gost);
	ASN1_STRING *params = ASN1_STRING_new();
	X509_ALGOR p;

	if (params == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	switch (digest) {
	case NID_id_tc26_gost3411_2012_256:
		p.algorithm = OBJ_nid2obj(NID_id_tc26_agreement_gost_3410_12_256);
		break;
	case NID_id_tc26_gost3411_2012_512:
		p.algorithm = OBJ_nid2obj(NID_id_tc26_agreement_gost_3410_12_512);
		break;
	default:
		GOSTerror(ERR_R_INTERNAL_ERROR);
		break;
	}
	p.parameter = NULL;

	params->length = i2d_X509_ALGOR(&p, &params->data);
	params->type = V_ASN1_SEQUENCE;

	return params;
err:
	ASN1_STRING_free(params);
	params = NULL;
	return NULL;
}

static int
pub_cmp_gost01(const EVP_PKEY *a, const EVP_PKEY *b)
{
	const GOST_KEY *ea = a->pkey.gost;
	const GOST_KEY *eb = b->pkey.gost;
	const EC_POINT *ka, *kb;
	int ret = 0;

	if (ea == NULL || eb == NULL)
		return 0;
	ka = GOST_KEY_get0_public_key(ea);
	kb = GOST_KEY_get0_public_key(eb);
	if (ka == NULL || kb == NULL)
		return 0;
	ret = (0 == EC_POINT_cmp(GOST_KEY_get0_group(ea), ka, kb, NULL));
	return ret;
}

static int
pkey_size_gost01(const EVP_PKEY *pk)
{
	if (GOST_KEY_get_digest(pk->pkey.gost) == NID_id_tc26_gost3411_2012_512)
		return 128;
	return 64;
}

static int
pkey_bits_gost01(const EVP_PKEY *pk)
{
	if (GOST_KEY_get_digest(pk->pkey.gost) == NID_id_tc26_gost3411_2012_512)
		return 512;
	return 256;
}

static int
pub_decode_gost01_int(EVP_PKEY *pk, X509_ALGOR *palg, const unsigned char *pubkey_buf, int pub_len)
{
	const ASN1_OBJECT *poid;
	const unsigned char *p;
	BIGNUM *X, *Y;
	ASN1_OCTET_STRING *octet = NULL;
	int len;
	int ret;
	int ptype = V_ASN1_UNDEF;
	ASN1_STRING *pval = NULL;
	int nid;

	X509_ALGOR_get0(&poid, &ptype, (const void **)&pval, palg);
	nid = OBJ_obj2nid(poid);
	if (nid != NID_id_GostR3410_2001 &&
	    nid != NID_id_tc26_gost3410_2012_256 &&
	    nid != NID_id_tc26_gost3410_2012_512)
		return 0;
	if (ptype != V_ASN1_SEQUENCE) {
		GOSTerror(GOST_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}
	p = pval->data;
	if (decode_gost01_algor_params(pk, &p, pval->length) == 0) {
		GOSTerror(GOST_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}

	octet = d2i_ASN1_OCTET_STRING(NULL, &pubkey_buf, pub_len);
	if (octet == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		return 0;
	}
	len = octet->length / 2;

	X = GOST_le2bn(octet->data, len, NULL);
	Y = GOST_le2bn(octet->data + len, len, NULL);

	ASN1_OCTET_STRING_free(octet);

	ret = GOST_KEY_set_public_key_affine_coordinates(pk->pkey.gost, X, Y);
	if (ret == 0)
		GOSTerror(ERR_R_EC_LIB);

	BN_free(X);
	BN_free(Y);

	return ret;
}

static int
pub_decode_gost01(EVP_PKEY *pk, X509_PUBKEY *pub)
{
	X509_ALGOR *palg = NULL;
	const unsigned char *pubkey_buf = NULL;
	int pub_len;

	if (X509_PUBKEY_get0_param(NULL, &pubkey_buf, &pub_len, &palg, pub) == 0)
		return 0;
	(void)EVP_PKEY_assign_GOST(pk, NULL);

	return pub_decode_gost01_int(pk, palg, pubkey_buf, pub_len);
}

static int
pub_encode_gost01_int(const EVP_PKEY *pk, ASN1_OBJECT **palgobj, ASN1_STRING **pparams, unsigned char **pbuf, int *plen)
{
	ASN1_OBJECT *algobj = NULL;
	ASN1_OCTET_STRING *octet = NULL;
	ASN1_STRING *params = NULL;
	unsigned char *buf = NULL, *sptr;
	int key_size, ret = 0;
	const EC_POINT *pub_key;
	BIGNUM *X = NULL, *Y = NULL;
	const GOST_KEY *ec = pk->pkey.gost;

	*palgobj = NULL;
	*pparams = NULL;
	*pbuf = NULL;
	*plen = 0;

	algobj = OBJ_nid2obj(GostR3410_get_pk_digest(GOST_KEY_get_digest(ec)));
	if (algobj == NULL)
		return 0;

	if (pk->save_parameters) {
		params = encode_gost01_algor_params(pk);
		if (params == NULL)
			goto err;
	}

	key_size = GOST_KEY_get_size(ec);

	pub_key = GOST_KEY_get0_public_key(ec);
	if (pub_key == NULL) {
		GOSTerror(GOST_R_PUBLIC_KEY_UNDEFINED);
		goto err;
	}

	octet = ASN1_OCTET_STRING_new();
	if (octet == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	ret = ASN1_STRING_set(octet, NULL, 2 * key_size);
	if (ret == 0) {
		GOSTerror(ERR_R_INTERNAL_ERROR);
		goto err;
	}

	sptr = ASN1_STRING_data(octet);

	X = BN_new();
	Y = BN_new();
	if (X == NULL || Y == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (EC_POINT_get_affine_coordinates_GFp(GOST_KEY_get0_group(ec),
	    pub_key, X, Y, NULL) == 0) {
		GOSTerror(ERR_R_EC_LIB);
		goto err;
	}

	GOST_bn2le(X, sptr, key_size);
	GOST_bn2le(Y, sptr + key_size, key_size);

	ret = i2d_ASN1_OCTET_STRING(octet, &buf);
	if (ret < 0)
		goto err;

	*palgobj = algobj;
	*pparams = params;
	*pbuf = buf;
	*plen = ret;

	return 1;

err:
	BN_free(Y);
	BN_free(X);
	ASN1_BIT_STRING_free(octet);
	ASN1_STRING_free(params);
	ASN1_OBJECT_free(algobj);
	return 0;
}

static int
pub_encode_gost01(X509_PUBKEY *pub, const EVP_PKEY *pk)
{
	ASN1_OBJECT *algobj = NULL;
	ASN1_STRING *params = NULL;
	unsigned char *buf = NULL;
	int len;

	if (pub_encode_gost01_int(pk, &algobj, &params, &buf, &len) <= 0)
		return 0;

	if (X509_PUBKEY_set0_param(pub, algobj, V_ASN1_SEQUENCE, params, buf, len) == 1)
		return 1;

	free(buf);
	ASN1_STRING_free(params);
	ASN1_OBJECT_free(algobj);

	return 0;
}

static int
param_print_gost01(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
	int param_nid =
	    EC_GROUP_get_curve_name(GOST_KEY_get0_group(pkey->pkey.gost));

	if (BIO_indent(out, indent, 128) == 0)
		return 0;
	BIO_printf(out, "Parameter set: %s\n", OBJ_nid2ln(param_nid));
	if (BIO_indent(out, indent, 128) == 0)
		return 0;
	BIO_printf(out, "Digest Algorithm: %s\n",
	    OBJ_nid2ln(GOST_KEY_get_digest(pkey->pkey.gost)));
	return 1;
}

static int
pub_print_gost01(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *X, *Y;
	const EC_POINT *pubkey;
	const EC_GROUP *group;

	if (ctx == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		return 0;
	}
	BN_CTX_start(ctx);
	if ((X = BN_CTX_get(ctx)) == NULL)
		goto err;
	if ((Y = BN_CTX_get(ctx)) == NULL)
		goto err;
	pubkey = GOST_KEY_get0_public_key(pkey->pkey.gost);
	group = GOST_KEY_get0_group(pkey->pkey.gost);
	if (EC_POINT_get_affine_coordinates_GFp(group, pubkey, X, Y,
	    ctx) == 0) {
		GOSTerror(ERR_R_EC_LIB);
		goto err;
	}
	if (BIO_indent(out, indent, 128) == 0)
		goto err;
	BIO_printf(out, "Public key:\n");
	if (BIO_indent(out, indent + 3, 128) == 0)
		goto err;
	BIO_printf(out, "X:");
	BN_print(out, X);
	BIO_printf(out, "\n");
	BIO_indent(out, indent + 3, 128);
	BIO_printf(out, "Y:");
	BN_print(out, Y);
	BIO_printf(out, "\n");

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return param_print_gost01(out, pkey, indent, pctx);

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return 0;
}

static int
priv_print_gost01(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx)
{
	const BIGNUM *key;

	if (BIO_indent(out, indent, 128) == 0)
		return 0;
	BIO_printf(out, "Private key: ");
	key = GOST_KEY_get0_private_key(pkey->pkey.gost);
	if (key == NULL)
		BIO_printf(out, "<undefined)");
	else
		BN_print(out, key);
	BIO_printf(out, "\n");

	return pub_print_gost01(out, pkey, indent, pctx);
}

static BIGNUM *unmask_priv_key(EVP_PKEY *pk,
		const unsigned char *buf, int len, int num_masks)
{
	BIGNUM *pknum_masked = NULL, *q, *mask;
	const GOST_KEY *key_ptr = pk->pkey.gost;
	const EC_GROUP *group = GOST_KEY_get0_group(key_ptr);
	const unsigned char *p = buf + num_masks * len;
	BN_CTX *ctx;

	pknum_masked = GOST_le2bn(buf, len, NULL);
	if (!pknum_masked) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	if (num_masks == 0)
		return pknum_masked;

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	BN_CTX_start(ctx);

	q = BN_CTX_get(ctx);
	if (!q) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	mask = BN_CTX_get(ctx);
	if (!mask) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (EC_GROUP_get_order(group, q, NULL) <= 0) {
		GOSTerror(ERR_R_EC_LIB);
		goto err;
	}

	for (; p != buf; p -= len) {
		if (GOST_le2bn(p, len, mask) == NULL ||
		    !BN_mod_mul(pknum_masked, pknum_masked, mask, q, ctx)) {
			GOSTerror(ERR_R_BN_LIB);
			goto err;
		}
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return pknum_masked;

err:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	BN_free(pknum_masked);
	return NULL;
}

static int
priv_decode_gost01(EVP_PKEY *pk, const PKCS8_PRIV_KEY_INFO *p8inf)
{
	const unsigned char *pkey_buf = NULL, *p = NULL;
	int priv_len = 0;
	BIGNUM *pk_num = NULL;
	int ret = 0;
	const X509_ALGOR *palg = NULL;
	const ASN1_OBJECT *palg_obj = NULL;
	ASN1_INTEGER *priv_key = NULL;
	GOST_KEY *ec;
	int ptype = V_ASN1_UNDEF;
	ASN1_STRING *pval = NULL;
	int expected_key_len;

	if (PKCS8_pkey_get0(&palg_obj, &pkey_buf, &priv_len, &palg, p8inf) == 0) {
		GOSTerror(GOST_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}
	(void)EVP_PKEY_assign_GOST(pk, NULL);
	X509_ALGOR_get0(NULL, &ptype, (const void **)&pval, palg);
	if (ptype != V_ASN1_SEQUENCE) {
		GOSTerror(GOST_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}
	p = pval->data;
	if (decode_gost01_algor_params(pk, &p, pval->length) == 0) {
		GOSTerror(GOST_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}
	p = pkey_buf;

	expected_key_len = (pkey_bits_gost01(pk) + 7) / 8;
	if (expected_key_len == 0) {
		EVPerror(EVP_R_DECODE_ERROR);
		return 0;
	} else if (priv_len % expected_key_len == 0) {
		/* Key is not wrapped but masked */
		pk_num = unmask_priv_key(pk, pkey_buf, expected_key_len,
				priv_len / expected_key_len - 1);
	} else if (V_ASN1_OCTET_STRING == *p) {
		/* New format - Little endian octet string */
		ASN1_OCTET_STRING *s =
		    d2i_ASN1_OCTET_STRING(NULL, &p, priv_len);

		if (s == NULL) {
			EVPerror(EVP_R_DECODE_ERROR);
			ASN1_STRING_free(s);
			return 0;
		}

		pk_num = GOST_le2bn(s->data, s->length, NULL);
		ASN1_STRING_free(s);
	} else if ((V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED) == *p) {
		/* New format - Structure with masked private and separate public key */
		MASKED_GOST_KEY *s =
		    d2i_MASKED_GOST_KEY(NULL, &p, priv_len);

		if (s == NULL ||
		    !s->masked_priv_key ||
		    s->masked_priv_key->length % expected_key_len != 0) {
			EVPerror(EVP_R_DECODE_ERROR);
			MASKED_GOST_KEY_free(s);
			return 0;
		}

		pk_num = unmask_priv_key(pk, s->masked_priv_key->data,
					 expected_key_len,
					 s->masked_priv_key->length / expected_key_len - 1);
		MASKED_GOST_KEY_free(s);
	} else if (V_ASN1_INTEGER == *p) {
		priv_key = d2i_ASN1_INTEGER(NULL, &p, priv_len);
		if (priv_key == NULL) {
			EVPerror(EVP_R_DECODE_ERROR);
			return 0;
		}
		pk_num = ASN1_INTEGER_to_BN(priv_key, NULL);
		ASN1_INTEGER_free(priv_key);
	} else {
		EVPerror(EVP_R_DECODE_ERROR);
		return 0;
	}

	if (pk_num == NULL) {
		EVPerror(EVP_R_DECODE_ERROR);
		return 0;
	}

	ec = pk->pkey.gost;
	if (ec == NULL) {
		ec = GOST_KEY_new();
		if (ec == NULL) {
			BN_free(pk_num);
			return 0;
		}
		if (EVP_PKEY_assign_GOST(pk, ec) == 0) {
			BN_free(pk_num);
			GOST_KEY_free(ec);
			return 0;
		}
	}
	if (GOST_KEY_set_private_key(ec, pk_num) == 0) {
		BN_free(pk_num);
		return 0;
	}
	ret = 0;
	if (EVP_PKEY_missing_parameters(pk) == 0)
		ret = gost2001_compute_public(ec) != 0;
	BN_free(pk_num);

	return ret;
}

static int
priv_encode_gost01(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk)
{
	ASN1_OBJECT *algobj =
	    OBJ_nid2obj(GostR3410_get_pk_digest(GOST_KEY_get_digest(pk->pkey.gost)));
	ASN1_STRING *params = encode_gost01_algor_params(pk);
	unsigned char *priv_buf = NULL;
	int priv_len;
	ASN1_INTEGER *asn1key = NULL;

	if (params == NULL)
		return 0;

	asn1key = BN_to_ASN1_INTEGER(GOST_KEY_get0_private_key(pk->pkey.gost),
	    NULL);
	if (asn1key == NULL) {
		ASN1_STRING_free(params);
		return 0;
	}
	priv_len = i2d_ASN1_INTEGER(asn1key, &priv_buf);
	ASN1_INTEGER_free(asn1key);
	return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params, priv_buf,
	    priv_len);
}

static int
param_encode_gost01(const EVP_PKEY *pkey, unsigned char **pder)
{
	ASN1_STRING *params = encode_gost01_algor_params(pkey);
	int len;

	if (params == NULL)
		return 0;
	len = params->length;
	if (pder != NULL)
		memcpy(*pder, params->data, params->length);
	ASN1_STRING_free(params);
	return len;
}

static int
param_decode_gost01(EVP_PKEY *pkey, const unsigned char **pder, int derlen)
{
	ASN1_OBJECT *obj = NULL;
	int nid;
	GOST_KEY *ec;
	EC_GROUP *group;
	int ret;

	/* New format */
	if ((V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED) == **pder)
		return decode_gost01_algor_params(pkey, pder, derlen);

	/* Compatibility */
	if (d2i_ASN1_OBJECT(&obj, pder, derlen) == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		return 0;
	}
	nid = OBJ_obj2nid(obj);
	ASN1_OBJECT_free(obj);

	ec = GOST_KEY_new();
	if (ec == NULL) {
		GOSTerror(ERR_R_MALLOC_FAILURE);
		return 0;
	}
	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		ECerror(EC_R_EC_GROUP_NEW_BY_NAME_FAILURE);
		GOST_KEY_free(ec);
		return 0;
	}

	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	if (GOST_KEY_set_group(ec, group) == 0) {
		GOSTerror(ERR_R_EC_LIB);
		EC_GROUP_free(group);
		GOST_KEY_free(ec);
		return 0;
	}
	EC_GROUP_free(group);
	if (GOST_KEY_set_digest(ec,
	    NID_id_GostR3411_94_CryptoProParamSet) == 0) {
		GOSTerror(GOST_R_INVALID_DIGEST_TYPE);
		GOST_KEY_free(ec);
		return 0;
	}
	ret = EVP_PKEY_assign_GOST(pkey, ec);
	if (ret == 0)
		GOST_KEY_free(ec);
	return ret;
}

static int
param_missing_gost01(const EVP_PKEY *pk)
{
	const GOST_KEY *ec = pk->pkey.gost;

	if (ec == NULL)
		return 1;
	if (GOST_KEY_get0_group(ec) == NULL)
		return 1;
	if (GOST_KEY_get_digest(ec) == NID_undef)
		return 1;
	return 0;
}

static int
param_copy_gost01(EVP_PKEY *to, const EVP_PKEY *from)
{
	GOST_KEY *eto = to->pkey.gost;
	const GOST_KEY *efrom = from->pkey.gost;
	int ret = 1;

	if (EVP_PKEY_base_id(from) != EVP_PKEY_base_id(to)) {
		GOSTerror(GOST_R_INCOMPATIBLE_ALGORITHMS);
		return 0;
	}
	if (efrom == NULL) {
		GOSTerror(GOST_R_KEY_PARAMETERS_MISSING);
		return 0;
	}
	if (eto == NULL) {
		eto = GOST_KEY_new();
		if (eto == NULL) {
			GOSTerror(ERR_R_MALLOC_FAILURE);
			return 0;
		}
		if (EVP_PKEY_assign(to, EVP_PKEY_base_id(from), eto) == 0) {
			GOST_KEY_free(eto);
			return 0;
		}
	}
	GOST_KEY_set_group(eto, GOST_KEY_get0_group(efrom));
	GOST_KEY_set_digest(eto, GOST_KEY_get_digest(efrom));
	if (GOST_KEY_get0_private_key(eto) != NULL)
		ret = gost2001_compute_public(eto);

	return ret;
}

static int
param_cmp_gost01(const EVP_PKEY *a, const EVP_PKEY *b)
{
	if (EC_GROUP_get_curve_name(GOST_KEY_get0_group(a->pkey.gost)) !=
	    EC_GROUP_get_curve_name(GOST_KEY_get0_group(b->pkey.gost)))
		return 0;

	if (GOST_KEY_get_digest(a->pkey.gost) !=
	    GOST_KEY_get_digest(b->pkey.gost))
		return 0;

	return 1;
}

int gost01_smime_decrypt(EVP_PKEY_CTX *pctx, X509_ALGOR *alg)
{
	int nid = OBJ_obj2nid(alg->algorithm);
	int format;

	switch (nid) {
	case NID_id_GostR3410_2001:
		/* Nothing to do */
		return 1;
	case NID_id_tc26_wrap_gostr3412_2015_magma_kexp15:
		format = GOST_ENC_FORMAT_PSKEY_MAGMA;
		break;
	case NID_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15:
		format = GOST_ENC_FORMAT_PSKEY_KUZNYECHIK;
		break;
	default:
		GOSTerror(GOST_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}
	if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DECRYPT,
			      EVP_PKEY_CTRL_GOST_ENC_FORMAT,
			      format, NULL) <= 0) {
		GOSTerror(ERR_R_INTERNAL_ERROR);
		return 0;
	}

	return 1;
}

int gost01_smime_encrypt(EVP_PKEY_CTX *ctx, X509_ALGOR *alg, int enc_nid)
{
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	int digest, nid, format;
	ASN1_STRING *params;

	switch (enc_nid) {
	case NID_id_Gost28147_89:
		format = GOST_ENC_FORMAT_4490;
		nid = NID_id_GostR3410_2001;
		break;
	case NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm:
	case NID_id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac:
		format = GOST_ENC_FORMAT_PSKEY_MAGMA;
		nid = NID_id_tc26_wrap_gostr3412_2015_magma_kexp15;
		break;
	case NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm:
	case NID_id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac:
		format = GOST_ENC_FORMAT_PSKEY_KUZNYECHIK;
		nid = NID_id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15;
		break;
	default:
		return 0;
	}

	if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_ENCRYPT,
				EVP_PKEY_CTRL_GOST_ENC_FORMAT, format,
				NULL) != 1)
		return 0;

	if (EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_ENCRYPT,
				EVP_PKEY_CTRL_GOST_GET_DIGEST, 0,
				&digest) != 1)
		return 0;

	switch (digest) {
	case NID_id_GostR3411_94_CryptoProParamSet:
		if ((params = encode_gost01_algor_params(pkey)) == NULL)
			return -1;
		break;

	case NID_id_tc26_gost3411_2012_256:
	case NID_id_tc26_gost3411_2012_512:
		if ((params = encode_gost01_kexp_params(pkey)) == NULL)
			return -1;
		break;

	default:
		return 0;
	}
	return X509_ALGOR_set0(alg, OBJ_nid2obj(nid), V_ASN1_SEQUENCE, params);
}

#ifndef OPENSSL_NO_CMS
static int
gost01_cms_set_peerkey(EVP_PKEY_CTX *pctx, X509_ALGOR *alg,
    ASN1_BIT_STRING *pubkey)
{
	int rv = 0;
	EVP_PKEY *pkpeer = NULL;
	int ret;

	pkpeer = EVP_PKEY_new();
	if (pkpeer == NULL)
		return 0;
	(void)EVP_PKEY_assign_GOST(pkpeer, NULL);

	ret = pub_decode_gost01_int(pkpeer, alg, pubkey->data, pubkey->length);
	if (ret <= 0)
		goto err;

	if (EVP_PKEY_derive_set_peer(pctx, pkpeer) > 0)
		rv = 1;
 err:

	EVP_PKEY_free(pkpeer);
	return rv;
}

static int
gost01_cms_decrypt_kari(EVP_PKEY_CTX *pctx, CMS_RecipientInfo *ri)
{
	EVP_CIPHER_CTX *kekctx;
	X509_ALGOR *alg;
	ASN1_OCTET_STRING *ukm;
	const EVP_CIPHER *kekcipher;

	if (!CMS_RecipientInfo_kari_get0_alg(ri, &alg, &ukm))
		return 0;

	if (ukm == NULL)
		return 0;

	if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
				EVP_PKEY_CTRL_SET_IV, ukm->length, ukm->data) < 0)
		return 0;

	if (!EVP_PKEY_CTX_get0_peerkey(pctx)) {
		ASN1_BIT_STRING *pubkey;
		X509_ALGOR *pkalg;

		if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &pkalg, &pubkey,
					NULL, NULL, NULL))
			return 0;
		if (!pkalg || !pubkey) {
			GOSTerror(GOST_R_NO_ORIGINATOR_CERTIFICATE);
			return 0;
		}
		if (!gost01_cms_set_peerkey(pctx, pkalg, pubkey)) {
			GOSTerror(GOST_R_INCOMPATIBLE_PEER_KEY);
			return 0;
		}
	}

	if (alg->parameter->type != V_ASN1_SEQUENCE)
		return 0;

	kekctx = CMS_RecipientInfo_kari_get0_ctx(ri);
	if (!kekctx)
		return 0;

	kekcipher = EVP_get_cipherbyobj(alg->algorithm);
	if (!kekcipher || EVP_CIPHER_mode(kekcipher) != EVP_CIPH_WRAP_MODE)
		return 0;
	if (!EVP_EncryptInit_ex(kekctx, kekcipher, NULL, NULL, ukm->data))
		return 0;

	if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
				EVP_PKEY_CTRL_GOST_DERIVE_FORMAT,
				GOST_DERIVE_FORMAT_KEG, NULL) <= 0) {
		GOSTerror(ERR_R_INTERNAL_ERROR);
		return 0;
	}

	return 1;
}

static int
gost01_cms_decrypt(CMS_RecipientInfo *ri)
{
	EVP_PKEY_CTX *pkctx;
	X509_ALGOR *cmsalg;

	pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
	if (pkctx == NULL)
		return 0;
	switch (CMS_RecipientInfo_type(ri)) {
	case CMS_RECIPINFO_TRANS:
		if (!CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &cmsalg))
			return 0;
		return gost01_smime_decrypt(pkctx, cmsalg);
	case CMS_RECIPINFO_AGREE:
		return gost01_cms_decrypt_kari(pkctx, ri);
	default:
		GOSTerror(ERR_R_INTERNAL_ERROR);
		return 0;
	}
}

static int
gost01_cms_encrypt_kari(CMS_RecipientInfo *ri)
{
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *pkey;
	EVP_CIPHER_CTX *ctx;
	X509_ALGOR *talg, *wrap_alg = NULL;
	ASN1_BIT_STRING *pubkey;
	int wrap_nid;
	unsigned char iv[32];
	ASN1_STRING *params;

	pctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
	if (!pctx)
		return 0;

	/* Get ephemeral key */
	pkey = EVP_PKEY_CTX_get0_pkey(pctx);
	if (pkey == NULL)
		return 0;

	if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
				EVP_PKEY_CTRL_GOST_DERIVE_FORMAT,
				GOST_DERIVE_FORMAT_KEG, NULL) <= 0) {
		GOSTerror(ERR_R_INTERNAL_ERROR);
		return 0;
	}

	if (!CMS_RecipientInfo_kari_get0_orig_id(ri, &talg, &pubkey,
	    NULL, NULL, NULL))
		goto err;

	/* Ephemeral key */
	if (talg) {
		const ASN1_OBJECT *aoid = NULL;

		X509_ALGOR_get0(&aoid, NULL, NULL, talg);

		/* Is everything uninitialised? */
		if (aoid == OBJ_nid2obj(NID_undef)) {
			ASN1_OBJECT *algobj = NULL;
			ASN1_STRING *params = NULL;
			unsigned char *buf = NULL;
			int len;

			if (pub_encode_gost01_int(pkey, &algobj, &params, &buf, &len) <= 0)
				return 0;

			X509_ALGOR_set0(talg, algobj, V_ASN1_SEQUENCE, params);
			ASN1_STRING_set0(pubkey, buf, len);
		}
	}

	/* Get wrap NID */
	ctx = CMS_RecipientInfo_kari_get0_ctx(ri);
	wrap_nid = EVP_CIPHER_CTX_type(ctx);

	/* Package wrap algorithm in an AlgorithmIdentifier */

	if (!CMS_RecipientInfo_kari_get0_alg(ri, &wrap_alg, NULL))
		goto err;
	if (wrap_alg == NULL)
		goto err;
	if ((params = encode_gost01_kexp_params(pkey)) == NULL)
		goto err;
	X509_ALGOR_set0(wrap_alg, OBJ_nid2obj(wrap_nid), V_ASN1_SEQUENCE, params);

	arc4random_buf(iv, sizeof(iv));
	if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
	    EVP_PKEY_CTRL_SET_IV, sizeof(iv), iv) < 0)
		goto err;

	if (!EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1))
		goto err;

	if (!CMS_RecipientInfo_kari_set0_ukm(ri, iv, sizeof(iv)))
		goto err;

	return 1;
err:
	return 0;
}

static int
gost01_cms_encrypt(CMS_RecipientInfo *ri)
{
	switch (CMS_RecipientInfo_type(ri)) {
	case CMS_RECIPINFO_TRANS:
		/* do nothing, handled in pmeth */
		return 1;
	case CMS_RECIPINFO_AGREE:
		return gost01_cms_encrypt_kari(ri);
	default:
		return 0;
	}
}

#endif

static int
pkey_ctrl_gost01(EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
	X509_ALGOR *alg1 = NULL, *alg2 = NULL;
	int digest = GOST_KEY_get_digest(pkey->pkey.gost);

	switch (op) {
#ifndef OPENSSL_NO_CMS
	case ASN1_PKEY_CTRL_CMS_SIGN:
		if (arg1 == 0)
			CMS_SignerInfo_get0_algs(arg2, NULL, NULL,
					&alg1, &alg2);
		break;
	case ASN1_PKEY_CTRL_CMS_ENVELOPE:
		if (arg1 == 0)
			return gost01_cms_encrypt(arg2);
		else if (arg1 == 1)
			return gost01_cms_decrypt(arg2);
		break;
	case ASN1_PKEY_CTRL_CMS_RI_TYPE:
		if (arg2 != NULL)
			*(int *)arg2 = CMS_RECIPINFO_TRANS; /* default */
		break;
	case ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED:
		if (arg2 != NULL)
			*(int *)arg2 = (arg1 == CMS_RECIPINFO_TRANS || arg1 == CMS_RECIPINFO_AGREE);
		break;
#endif
	case ASN1_PKEY_CTRL_PKCS7_SIGN:
		if (arg1 == 0)
			PKCS7_SIGNER_INFO_get0_algs(arg2, NULL, &alg1, &alg2);
		break;
	case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
		return 1;
	case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
		*(int *)arg2 = GostR3410_get_md_digest(digest);
		return 2;

	default:
		return -2;
	}

	if (alg1)
		X509_ALGOR_set0(alg1, OBJ_nid2obj(GostR3410_get_md_digest(digest)), V_ASN1_NULL, 0);
	if (alg2)
		X509_ALGOR_set0(alg2, OBJ_nid2obj(GostR3410_get_pk_digest(digest)), V_ASN1_NULL, 0);

	return 1;
}

const EVP_PKEY_ASN1_METHOD gostr01_asn1_meths[] = {
	{
		.pkey_id = EVP_PKEY_GOSTR01,
		.pkey_base_id = EVP_PKEY_GOSTR01,
		.pkey_flags = ASN1_PKEY_SIGPARAM_NULL,

		.pem_str = "GOST2001",
		.info = "GOST R 34.10-2001",

		.pkey_free = pkey_free_gost01,
		.pkey_ctrl = pkey_ctrl_gost01,

		.priv_decode = priv_decode_gost01,
		.priv_encode = priv_encode_gost01,
		.priv_print = priv_print_gost01,

		.param_decode = param_decode_gost01,
		.param_encode = param_encode_gost01,
		.param_missing = param_missing_gost01,
		.param_copy = param_copy_gost01,
		.param_cmp = param_cmp_gost01,
		.param_print = param_print_gost01,

		.pub_decode = pub_decode_gost01,
		.pub_encode = pub_encode_gost01,
		.pub_cmp = pub_cmp_gost01,
		.pub_print = pub_print_gost01,
		.pkey_size = pkey_size_gost01,
		.pkey_bits = pkey_bits_gost01,
	},
	{
		.pkey_id = EVP_PKEY_GOSTR12_256,
		.pkey_base_id = EVP_PKEY_GOSTR01,
		.pkey_flags = ASN1_PKEY_ALIAS
	},
	{
		.pkey_id = EVP_PKEY_GOSTR12_512,
		.pkey_base_id = EVP_PKEY_GOSTR01,
		.pkey_flags = ASN1_PKEY_ALIAS
	},
};

#endif
