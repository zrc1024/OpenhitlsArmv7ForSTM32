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
#if defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER)
#include <stdio.h>
#include <string.h>
#include "crypt_types.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "hitls_crypt_type.h"
#include "crypt_algid.h"
#include "crypt_eal_pkey.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "hitls_pki_cert.h"

static int32_t SetPkeySignParam(CRYPT_EAL_PkeyCtx *ctx, HITLS_SignAlgo signAlgo, int32_t mdAlgId)
{
    if (signAlgo == HITLS_SIGN_RSA_PKCS1_V15) {
        int32_t pad = mdAlgId;
        return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pad, sizeof(pad));
    } else if (signAlgo == HITLS_SIGN_RSA_PSS) {
        int32_t saltLen = CRYPT_RSA_SALTLEN_TYPE_HASHLEN;
        BSL_Param pssParam[4] = {
            {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
            {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdAlgId, sizeof(mdAlgId), 0},
            {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
            BSL_PARAM_END};
        return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0);
    } else if (signAlgo == HITLS_SIGN_SM2) {
        /* The default user id as specified in GM/T 0009-2012 */
        char sm2DefaultUserid[] = "1234567812345678";
        return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_SM2_USER_ID, sm2DefaultUserid, strlen(sm2DefaultUserid));
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_X509_Adapt_CreateSign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
{
    (void)ctx;
    if (SetPkeySignParam(key, signAlgo, hashAlgo) != HITLS_SUCCESS) {
        return HITLS_CERT_SELF_ADAPT_ERR;
    }
    return CRYPT_EAL_PkeySign(key, (CRYPT_MD_AlgId)hashAlgo, data, dataLen, sign, signLen);
}

int32_t HITLS_X509_Adapt_VerifySign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
{
    (void)ctx;
    if (SetPkeySignParam(key, signAlgo, hashAlgo) != HITLS_SUCCESS) {
        return HITLS_CERT_SELF_ADAPT_ERR;
    }
    return CRYPT_EAL_PkeyVerify(key, (CRYPT_MD_AlgId)hashAlgo, data, dataLen, sign, signLen);
}

#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
static int32_t CertSetRsaEncryptionScheme(CRYPT_EAL_PkeyCtx *ctx)
{
    int32_t pad = CRYPT_MD_SHA256;
    return CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_RSA_RSAES_PKCSV15, &pad, sizeof(pad));
}

/* only support rsa pkcs1.5 */
int32_t HITLS_X509_Adapt_Encrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    if (CRYPT_EAL_PkeyGetId(key) == CRYPT_PKEY_RSA && CertSetRsaEncryptionScheme(key) != HITLS_SUCCESS) {
        return HITLS_CERT_SELF_ADAPT_ERR;
    }

    return CRYPT_EAL_PkeyEncrypt(key, in, inLen, out, outLen);
}


int32_t HITLS_X509_Adapt_Decrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    if (CRYPT_EAL_PkeyGetId(key) == CRYPT_PKEY_RSA && CertSetRsaEncryptionScheme(key) != HITLS_SUCCESS) {
        return HITLS_CERT_SELF_ADAPT_ERR;
    }

    return CRYPT_EAL_PkeyDecrypt(key, in, inLen, out, outLen);
}
#endif

int32_t HITLS_X509_Adapt_CheckPrivateKey(const HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key)
{
    (void)config;
    CRYPT_EAL_PkeyCtx *ealPubKey = NULL;
    CRYPT_EAL_PkeyCtx *ealPrivKey = (CRYPT_EAL_PkeyCtx *)key;
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_GET_PUBKEY, &ealPubKey, 0);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_EAL_PkeyPairCheck(ealPubKey, ealPrivKey);
    CRYPT_EAL_PkeyFreeCtx(ealPubKey);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}
#endif /* defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER) */
