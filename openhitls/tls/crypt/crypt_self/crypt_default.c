/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_TLS_CALLBACK_CRYPT

#include <string.h>
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "crypt_algid.h"
#include "hitls_crypt_type.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "hitls_error.h"
#include "hitls_build.h"

#include "crypt_default.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "config_type.h"
#include "hitls_crypt.h"

#ifndef HITLS_CRYPTO_EAL
#error "Missing definition of HITLS_CRYPTO_EAL"
#endif

int32_t CRYPT_DEFAULT_RandomBytes(uint8_t *buf, uint32_t len)
{
#ifdef HITLS_CRYPTO_DRBG
    return CRYPT_EAL_Randbytes(buf, len);
#else
    (void)buf;
    (void)len;
    return CRYPT_EAL_ALG_NOT_SUPPORT;
#endif
}

uint32_t CRYPT_DEFAULT_HMAC_Size(HITLS_HashAlgo hashAlgo)
{
    return CRYPT_DEFAULT_DigestSize(hashAlgo);
}

#ifdef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
HITLS_HMAC_Ctx *CRYPT_DEFAULT_HMAC_Init(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t len)
{
    return HITLS_CRYPT_HMAC_Init(NULL, NULL, hashAlgo, key, len);
}

int32_t CRYPT_DEFAULT_HMAC_ReInit(HITLS_HMAC_Ctx *ctx)
{
    return HITLS_CRYPT_HMAC_ReInit(ctx);
}

void CRYPT_DEFAULT_HMAC_Free(HITLS_HMAC_Ctx *ctx)
{
    HITLS_CRYPT_HMAC_Free(ctx);
}

int32_t CRYPT_DEFAULT_HMAC_Update(HITLS_HMAC_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    return HITLS_CRYPT_HMAC_Update(ctx, data, len);
}

int32_t CRYPT_DEFAULT_HMAC_Final(HITLS_HMAC_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return HITLS_CRYPT_HMAC_Final(ctx, out, len);
}
#endif /* HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES */


int32_t CRYPT_DEFAULT_HMAC(HITLS_HashAlgo hashAlgo, const uint8_t *key, uint32_t keyLen,
    const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    return HITLS_CRYPT_HMAC(NULL, NULL, hashAlgo, key, keyLen, in, inLen, out, outLen);
}

uint32_t CRYPT_DEFAULT_DigestSize(HITLS_HashAlgo hashAlgo)
{
    return HITLS_CRYPT_DigestSize(hashAlgo);
}

HITLS_HASH_Ctx *CRYPT_DEFAULT_DigestInit(HITLS_HashAlgo hashAlgo)
{
    return HITLS_CRYPT_DigestInit(NULL, NULL, hashAlgo);
}

HITLS_HASH_Ctx *CRYPT_DEFAULT_DigestCopy(HITLS_HASH_Ctx *ctx)
{
    return HITLS_CRYPT_DigestCopy(ctx);
}

void CRYPT_DEFAULT_DigestFree(HITLS_HASH_Ctx *ctx)
{
    HITLS_CRYPT_DigestFree(ctx);
}

int32_t CRYPT_DEFAULT_DigestUpdate(HITLS_HASH_Ctx *ctx, const uint8_t *data, uint32_t len)
{
    return HITLS_CRYPT_DigestUpdate(ctx, data, len);
}

int32_t CRYPT_DEFAULT_DigestFinal(HITLS_HASH_Ctx *ctx, uint8_t *out, uint32_t *len)
{
    return HITLS_CRYPT_DigestFinal(ctx, out, len);
}

int32_t CRYPT_DEFAULT_Digest(HITLS_HashAlgo hashAlgo, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    return HITLS_CRYPT_Digest(NULL, NULL, hashAlgo, in, inLen, out, outLen);
}

int32_t CRYPT_DEFAULT_Encrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    return HITLS_CRYPT_Encrypt(NULL, NULL, cipher, in, inLen, out, outLen);
}


int32_t CRYPT_DEFAULT_Decrypt(const HITLS_CipherParameters *cipher, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    return HITLS_CRYPT_Decrypt(NULL, NULL, cipher, in, inLen, out, outLen);
}

void CRYPT_DEFAULT_CipherFree(HITLS_Cipher_Ctx *ctx)
{
    HITLS_CRYPT_CipherFree(ctx);
}

HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateEcdhKey(const HITLS_ECParameters *curveParams)
{
    return HITLS_CRYPT_GenerateEcdhKey(NULL, NULL, NULL, curveParams);
}

#ifdef HITLS_TLS_CONFIG_MANUAL_DH
HITLS_CRYPT_Key *CRYPT_DEFAULT_DupKey(HITLS_CRYPT_Key *key)
{
    return HITLS_CRYPT_DupKey(key);
}
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */

void CRYPT_DEFAULT_FreeKey(HITLS_CRYPT_Key *key)
{
    HITLS_CRYPT_FreeKey(key);
}

int32_t CRYPT_DEFAULT_GetPubKey(HITLS_CRYPT_Key *key, uint8_t *pubKeyBuf, uint32_t bufLen, uint32_t *pubKeyLen)
{
    return HITLS_CRYPT_GetPubKey(key, pubKeyBuf, bufLen, pubKeyLen);
}

#ifdef HITLS_TLS_PROTO_TLCP11
int32_t CRYPT_DEFAULT_CalcSM2SharedSecret(HITLS_Sm2GenShareKeyParameters *sm2Params, uint8_t *sharedSecret,
    uint32_t *sharedSecretLen)
{
    return HITLS_CRYPT_CalcSM2SharedSecret(NULL, NULL, sm2Params, sharedSecret, sharedSecretLen);
}
#endif /* HITLS_TLS_PROTO_TLCP11 */

int32_t CRYPT_DEFAULT_DhCalcSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    return HITLS_CRYPT_DhCalcSharedSecret(NULL, NULL, key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);
}

int32_t CRYPT_DEFAULT_EcdhCalcSharedSecret(HITLS_CRYPT_Key *key, uint8_t *peerPubkey, uint32_t pubKeyLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    return HITLS_CRYPT_EcdhCalcSharedSecret(NULL, NULL, key, peerPubkey, pubKeyLen, sharedSecret, sharedSecretLen);
}

#ifdef HITLS_TLS_SUITE_KX_DHE

HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateDhKeyBySecbits(int32_t secbits)
{
    return HITLS_CRYPT_GenerateDhKeyBySecbits(NULL, NULL, NULL, secbits);
}

HITLS_CRYPT_Key *CRYPT_DEFAULT_GenerateDhKeyByParameters(uint8_t *p, uint16_t pLen, uint8_t *g, uint16_t gLen)
{
    return HITLS_CRYPT_GenerateDhKeyByParameters(NULL, NULL, p, pLen, g, gLen);
}

int32_t CRYPT_DEFAULT_GetDhParameters(HITLS_CRYPT_Key *key, uint8_t *p, uint16_t *pLen, uint8_t *g, uint16_t *gLen)
{
    return HITLS_CRYPT_GetDhParameters(key, p, pLen, g, gLen);
}
#endif /* HITLS_TLS_SUITE_KX_DHE */

int32_t CRYPT_DEFAULT_HkdfExtract(const HITLS_CRYPT_HkdfExtractInput *input, uint8_t *prk, uint32_t *prkLen)
{
    return HITLS_CRYPT_HkdfExtract(NULL, NULL, input, prk, prkLen);
}

int32_t CRYPT_DEFAULT_HkdfExpand(const HITLS_CRYPT_HkdfExpandInput *input, uint8_t *okm, uint32_t okmLen)
{
    return HITLS_CRYPT_HkdfExpand(NULL, NULL, input, okm, okmLen);
}

#ifdef HITLS_TLS_FEATURE_KEM
int32_t CRYPT_DEFAULT_KemEncapsulate(HITLS_KemEncapsulateParams *params)
{
    return HITLS_CRYPT_KemEncapsulate(NULL, NULL, NULL, params);
}

int32_t CRYPT_DEFAULT_KemDecapsulate(HITLS_CRYPT_Key *key, const uint8_t *ciphertext, uint32_t ciphertextLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    return HITLS_CRYPT_KemDecapsulate(key, ciphertext, ciphertextLen, sharedSecret, sharedSecretLen);
}
#endif /* HITLS_TLS_FEATURE_KEM */

#endif /* HITLS_TLS_CALLBACK_CRYPT */
