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
#ifdef HITLS_CRYPTO_CURVE25519

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "curve25519_local.h"
#include "crypt_util_rand.h"
#include "crypt_types.h"
#include "eal_md_local.h"
#include "crypt_params_key.h"

#ifdef HITLS_CRYPTO_X25519
CRYPT_CURVE25519_Ctx *CRYPT_X25519_NewCtx(void)
{
    CRYPT_CURVE25519_Ctx *ctx = NULL;
    ctx = (CRYPT_CURVE25519_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_CURVE25519_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_CURVE25519_Ctx), 0, sizeof(CRYPT_CURVE25519_Ctx));

    ctx->keyType = CURVE25519_NOKEY;
    ctx->hashMethod = NULL;
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_CURVE25519_Ctx *CRYPT_X25519_NewCtxEx(void *libCtx)
{
    CRYPT_CURVE25519_Ctx *ctx = CRYPT_X25519_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}
#endif

#ifdef HITLS_CRYPTO_ED25519
CRYPT_CURVE25519_Ctx *CRYPT_ED25519_NewCtx(void)
{
    CRYPT_CURVE25519_Ctx *ctx = NULL;
    ctx = (CRYPT_CURVE25519_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_CURVE25519_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_CURVE25519_Ctx), 0, sizeof(CRYPT_CURVE25519_Ctx));

    ctx->hashMethod = EAL_MdFindMethod(CRYPT_MD_SHA512);
    if (ctx->hashMethod == NULL) {
        CRYPT_CURVE25519_FreeCtx(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return NULL;
    }
    ctx->keyType = CURVE25519_NOKEY;
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_CURVE25519_Ctx *CRYPT_ED25519_NewCtxEx(void *libCtx)
{
    CRYPT_CURVE25519_Ctx *ctx = CRYPT_ED25519_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}
#endif

CRYPT_CURVE25519_Ctx *CRYPT_CURVE25519_DupCtx(CRYPT_CURVE25519_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    CRYPT_CURVE25519_Ctx *newCtx = NULL;
    newCtx = (CRYPT_CURVE25519_Ctx *)BSL_SAL_Malloc(sizeof(CRYPT_CURVE25519_Ctx));
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    (void)memcpy_s(newCtx, sizeof(CRYPT_CURVE25519_Ctx), ctx, sizeof(CRYPT_CURVE25519_Ctx));
    BSL_SAL_ReferencesInit(&(newCtx->references));
    return newCtx;
}

static int32_t CRYPT_CURVE25519_GetLen(CRYPT_CURVE25519_Ctx *ctx, GetLenFunc func, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *(int32_t *)val = func(ctx);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_CURVE25519_GetKeyLen(const CRYPT_CURVE25519_Ctx *pkey)
{
    (void)pkey;
    return CRYPT_CURVE25519_KEYLEN;
}

int32_t CRYPT_CURVE25519_Ctrl(CRYPT_CURVE25519_Ctx *pkey, int32_t opt, void *val, uint32_t len)
{
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_BITS:
            return CRYPT_CURVE25519_GetLen(pkey, (GetLenFunc)CRYPT_CURVE25519_GetBits, val, len);
#ifdef HITLS_CRYPTO_ED25519
        case CRYPT_CTRL_GET_SIGNLEN:
            return CRYPT_CURVE25519_GetLen(pkey, (GetLenFunc)CRYPT_CURVE25519_GetSignLen, val, len);
#endif
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_CURVE25519_GetLen(pkey, (GetLenFunc)CRYPT_CURVE25519_GetSecBits, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
        case CRYPT_CTRL_GET_PRVKEY_LEN:
        case CRYPT_CTRL_GET_SHARED_KEY_LEN:
            return GetUintCtrl(pkey, val, len, (GetUintCallBack)CRYPT_CURVE25519_GetKeyLen);
        case CRYPT_CTRL_UP_REFERENCES:
            if (val == NULL || len != (uint32_t)sizeof(int)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            return BSL_SAL_AtomicUpReferences(&(pkey->references), (int *)val);
#ifdef HITLS_CRYPTO_X25519
        case CRYPT_CTRL_GEN_X25519_PUBLICKEY:
            if ((pkey->keyType & CURVE25519_PUBKEY) != 0) {
                return CRYPT_SUCCESS;
            }
            if ((pkey->keyType & CURVE25519_PRVKEY) == 0) {
                BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_PRVKEY);
                return CRYPT_CURVE25519_NO_PRVKEY;
            }
            CRYPT_X25519_PublicFromPrivate(pkey->prvKey, pkey->pubKey);
            pkey->keyType |= CURVE25519_PUBKEY;
            return CRYPT_SUCCESS;
#endif
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_CURVE25519_UNSUPPORTED_CTRL_OPTION;
}

void CRYPT_CURVE25519_FreeCtx(CRYPT_CURVE25519_Ctx *pkey)
{
    if (pkey == NULL) {
        return;
    }
    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(pkey->references), &ret);
    if (ret > 0) {
        return;
    }
    BSL_SAL_ReferencesFree(&(pkey->references));
    BSL_SAL_CleanseData((void *)(pkey), sizeof(CRYPT_CURVE25519_Ctx));
    BSL_SAL_FREE(pkey);
}

int32_t CRYPT_CURVE25519_SetPubKey(CRYPT_CURVE25519_Ctx *pkey, const BSL_Param *para)
{
    if (pkey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // assume that the two scenarios will not coexist.
    const BSL_Param *pub = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_CURVE25519_PUBKEY);
    if (pub == NULL) {
        pub = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    }
    
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->valueLen != CRYPT_CURVE25519_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_KEYLEN_ERROR);
        return CRYPT_CURVE25519_KEYLEN_ERROR;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(pkey->pubKey, CRYPT_CURVE25519_KEYLEN, pub->value, pub->valueLen);
    pkey->keyType |= CURVE25519_PUBKEY;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE25519_SetPrvKey(CRYPT_CURVE25519_Ctx *pkey, const BSL_Param *para)
{
    if (pkey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_CURVE25519_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->valueLen != CRYPT_CURVE25519_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_KEYLEN_ERROR);
        return CRYPT_CURVE25519_KEYLEN_ERROR;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(pkey->prvKey, CRYPT_CURVE25519_KEYLEN, prv->value, prv->valueLen);
    pkey->keyType |= CURVE25519_PRVKEY;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE25519_GetPubKey(const CRYPT_CURVE25519_Ctx *pkey, BSL_Param *para)
{
    if (pkey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // assume that the two scenarios will not coexist.
    BSL_Param *pub = BSL_PARAM_FindParam(para, CRYPT_PARAM_CURVE25519_PUBKEY);
    if (pub == NULL) {
        pub = BSL_PARAM_FindParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    }
    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->valueLen < CRYPT_CURVE25519_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_KEYLEN_ERROR);
        return CRYPT_CURVE25519_KEYLEN_ERROR;
    }

    if ((pkey->keyType & CURVE25519_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_PUBKEY);
        return CRYPT_CURVE25519_NO_PUBKEY;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(pub->value, pub->valueLen, pkey->pubKey, CRYPT_CURVE25519_KEYLEN);

    pub->useLen = CRYPT_CURVE25519_KEYLEN;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE25519_GetPrvKey(const CRYPT_CURVE25519_Ctx *pkey, BSL_Param *para)
{
    if (pkey == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(para, CRYPT_PARAM_CURVE25519_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->valueLen < CRYPT_CURVE25519_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_KEYLEN_ERROR);
        return CRYPT_CURVE25519_KEYLEN_ERROR;
    }

    if ((pkey->keyType & CURVE25519_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_PRVKEY);
        return CRYPT_CURVE25519_NO_PRVKEY;
    }

    /* The keyLen has been checked and does not have the overlong problem.
       The pkey memory is dynamically allocated and does not overlap with the pubkey memory. */
    /* There is no failure case for memcpy_s. */
    (void)memcpy_s(prv->value, prv->valueLen, pkey->prvKey, CRYPT_CURVE25519_KEYLEN);

    prv->useLen = CRYPT_CURVE25519_KEYLEN;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE25519_GetBits(const CRYPT_CURVE25519_Ctx *pkey)
{
    (void)pkey;
    return CRYPT_CURVE25519_KEYLEN * 8; // bits = 8 * bytes
}

#ifdef HITLS_CRYPTO_ED25519
static int32_t PrvKeyHash(const uint8_t *prvKey, uint32_t prvKeyLen, uint8_t *prvKeyHash, uint32_t prvHashLen,
    const EAL_MdMethod *hashMethod)
{
    void *mdCtx = NULL;
    int32_t ret;
    uint32_t hashLen = prvHashLen;

    mdCtx = hashMethod->newCtx();
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = hashMethod->init(mdCtx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->update(mdCtx, prvKey, prvKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->final(mdCtx, prvKeyHash, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

EXIT:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t GetRHash(uint8_t r[CRYPT_CURVE25519_SIGNLEN], const uint8_t prefix[CRYPT_CURVE25519_KEYLEN],
    const uint8_t *msg, uint32_t msgLen, const EAL_MdMethod *hashMethod)
{
    void *mdCtx = NULL;
    int32_t ret;
    uint32_t hashLen = CRYPT_CURVE25519_SIGNLEN;

    mdCtx = hashMethod->newCtx();
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = hashMethod->init(mdCtx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->update(mdCtx, prefix, CRYPT_CURVE25519_KEYLEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->update(mdCtx, msg, msgLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->final(mdCtx, r, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

EXIT:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t GetKHash(uint8_t k[CRYPT_CURVE25519_SIGNLEN], const uint8_t r[CRYPT_CURVE25519_KEYLEN],
    const uint8_t pubKey[CRYPT_CURVE25519_KEYLEN], const uint8_t *msg, uint32_t msgLen,
    const EAL_MdMethod *hashMethod)
{
    void *mdCtx = NULL;
    uint32_t hashLen = CRYPT_CURVE25519_SIGNLEN;

    mdCtx = hashMethod->newCtx();
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = hashMethod->init(mdCtx, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->update(mdCtx, r, CRYPT_CURVE25519_KEYLEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->update(mdCtx, pubKey, CRYPT_CURVE25519_KEYLEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->update(mdCtx, msg, msgLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = hashMethod->final(mdCtx, k, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

EXIT:
    hashMethod->freeCtx(mdCtx);
    return ret;
}

static int32_t SignInputCheck(const CRYPT_CURVE25519_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, const uint32_t *signLen)
{
    if (pkey == NULL || (msg == NULL && msgLen != 0) || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((pkey->keyType & CURVE25519_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_PRVKEY);
        return CRYPT_CURVE25519_NO_PRVKEY;
    }
    if (*signLen < CRYPT_CURVE25519_SIGNLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_SIGNLEN_ERROR);
        return CRYPT_CURVE25519_SIGNLEN_ERROR;
    }
    if (pkey->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_HASH_METHOD);
        return CRYPT_CURVE25519_NO_HASH_METHOD;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE25519_Sign(CRYPT_CURVE25519_Ctx *pkey, int32_t algId, const uint8_t *msg,
    uint32_t msgLen, uint8_t *sign, uint32_t *signLen)
{
    (void)algId;
    uint8_t prvKeyHash[CRYPT_CURVE25519_SIGNLEN];
    uint8_t r[CRYPT_CURVE25519_SIGNLEN];
    uint8_t k[CRYPT_CURVE25519_SIGNLEN];
    uint8_t outSign[CRYPT_CURVE25519_SIGNLEN];
    GeE geTmp;

    int32_t ret = SignInputCheck(pkey, msg, msgLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ret = PrvKeyHash(pkey->prvKey, CRYPT_CURVE25519_KEYLEN, prvKeyHash, CRYPT_CURVE25519_SIGNLEN, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    prvKeyHash[0] &= 0xf8;
    // on block 31, clear the highest bit
    prvKeyHash[31] &= 0x7f;
    // on block 31, set second highest bit to 1
    prvKeyHash[31] |= 0x40;

    // if ctx has no public key, generate public key and store it in ctx
    if ((pkey->keyType & CURVE25519_PUBKEY) == 0) {
        ScalarMultiBase(&geTmp, prvKeyHash);
        PointEncoding(&geTmp, pkey->pubKey, CRYPT_CURVE25519_KEYLEN);
        pkey->keyType |= CURVE25519_PUBKEY;
    }

    ret = GetRHash(r, prvKeyHash + CRYPT_CURVE25519_KEYLEN, msg, msgLen, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ModuloL(r);
    ScalarMultiBase(&geTmp, r);
    PointEncoding(&geTmp, outSign, CRYPT_CURVE25519_SIGNLEN);

    ret = GetKHash(k, outSign, pkey->pubKey, msg, msgLen, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    ModuloL(k);
    ScalarMulAdd(outSign + CRYPT_CURVE25519_KEYLEN, k, prvKeyHash, r);

    // The value of *signLen has been checked in SignInputCheck to ensure that
    // the value is greater than or equal to CRYPT_CURVE25519_SIGNLEN.
    // The sign memory is input from outside the function. The outSign memory is allocated within the function.
    // Memory overlap does not exist. There is no failure case for memcpy_s.
    (void)memcpy_s(sign, *signLen, outSign, CRYPT_CURVE25519_SIGNLEN);
    *signLen = CRYPT_CURVE25519_SIGNLEN;

EXIT:
    BSL_SAL_CleanseData(prvKeyHash, sizeof(prvKeyHash));
    BSL_SAL_CleanseData(r, sizeof(r));
    BSL_SAL_CleanseData(k, sizeof(k));
    return ret;
}

int32_t CRYPT_CURVE25519_GetSignLen(const CRYPT_CURVE25519_Ctx *pkey)
{
    (void)pkey;
    return CRYPT_CURVE25519_SIGNLEN;
}

static int32_t VerifyInputCheck(const CRYPT_CURVE25519_Ctx *pkey, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, uint32_t signLen)
{
    if (pkey == NULL || (msg == NULL && msgLen != 0) || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((pkey->keyType & CURVE25519_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_PUBKEY);
        return CRYPT_CURVE25519_NO_PUBKEY;
    }
    if (signLen != CRYPT_CURVE25519_SIGNLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_SIGNLEN_ERROR);
        return CRYPT_CURVE25519_SIGNLEN_ERROR;
    }
    if (pkey->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_HASH_METHOD);
        return CRYPT_CURVE25519_NO_HASH_METHOD;
    }
    return CRYPT_SUCCESS;
}

/* check 0 <= s < l, l = 2^252 + 27742317777372353535851937790883648493 */
static bool VerifyCheckSValid(const uint8_t s[CRYPT_CURVE25519_KEYLEN])
{
    const uint8_t l[CRYPT_CURVE25519_KEYLEN] = {
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };

    int32_t i;
    // start from highest block 31
    for (i = 31; i >= 0; i--) {
        if (s[i] > l[i]) {
            return false;
        } else if (s[i] < l[i]) {
            return true;
        }
    }
    // s = l is invalid
    return false;
}

int32_t CRYPT_CURVE25519_Verify(const CRYPT_CURVE25519_Ctx *pkey, int32_t algId, const uint8_t *msg,
    uint32_t msgLen, const uint8_t *sign, uint32_t signLen)
{
    if (algId != CRYPT_MD_SHA512) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    GeE geA, sG;
    uint8_t kHash[CRYPT_CURVE25519_SIGNLEN];
    uint8_t localR[CRYPT_CURVE25519_KEYLEN];

    const uint8_t *r = NULL;
    const uint8_t *s = NULL;
    int32_t ret = VerifyInputCheck(pkey, msg, msgLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // r is first half of sign, length 32
    r = sign;
    // s is second half of the sign, length 32
    s = sign + 32;

    if (!VerifyCheckSValid(s)) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_VERIFY_FAIL);
        ret = CRYPT_CURVE25519_VERIFY_FAIL;
        return ret;
    }

    if (PointDecoding(&geA, pkey->pubKey) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_VERIFY_FAIL);
        ret = CRYPT_CURVE25519_INVALID_PUBKEY;
        return ret;
    }

    ret = GetKHash(kHash, r, pkey->pubKey, msg, msgLen, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CURVE25519_FP_NEGATE(geA.x, geA.x);
    CURVE25519_FP_NEGATE(geA.t, geA.t);

    ModuloL(kHash);
    KAMulPlusMulBase(&sG, kHash, &geA, s);
    PointEncoding(&sG, localR, CRYPT_CURVE25519_KEYLEN);

    if (memcmp(localR, r, CRYPT_CURVE25519_KEYLEN) != 0) {
        ret = CRYPT_CURVE25519_VERIFY_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_ED25519_GenKey(CRYPT_CURVE25519_Ctx *pkey)
{
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // SHA512 digest size is 64, no other hash has 64 md size
    if (pkey->hashMethod == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_HASH_METHOD);
        return CRYPT_CURVE25519_NO_HASH_METHOD;
    }
    int32_t ret;
    uint8_t prvKey[CRYPT_CURVE25519_KEYLEN];
    uint8_t prvKeyHash[CRYPT_CURVE25519_SIGNLEN];
    GeE tmp;

    ret = CRYPT_RandEx(pkey->libCtx, prvKey, sizeof(prvKey));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = PrvKeyHash(prvKey, CRYPT_CURVE25519_KEYLEN, prvKeyHash, CRYPT_CURVE25519_SIGNLEN, pkey->hashMethod);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }

    prvKeyHash[0] &= 0xf8;
    // on block 31, clear the highest bit
    prvKeyHash[31] &= 0x7f;
    // on block 31, set second highest bit to 1
    prvKeyHash[31] |= 0x40;

    ScalarMultiBase(&tmp, prvKeyHash);
    PointEncoding(&tmp, pkey->pubKey, CRYPT_CURVE25519_KEYLEN);

    // The pkey is not empty. The length of the prvKey is CRYPT_CURVE25519_KEYLEN,
    // which is the same as the length of local prvKey.
    // The pkey->prvKey memory is input outside the function. The local prvKey memory is allocated within the function.
    // Memory overlap does not exist. No failure case exists for memcpy_s.
    (void)memcpy_s(pkey->prvKey, CRYPT_CURVE25519_KEYLEN, prvKey, CRYPT_CURVE25519_KEYLEN);
    pkey->keyType = CURVE25519_PRVKEY | CURVE25519_PUBKEY;

EXIT:
    BSL_SAL_CleanseData(prvKey, sizeof(prvKey));
    BSL_SAL_CleanseData(prvKeyHash, sizeof(prvKeyHash));
    return ret;
}
#endif /* HITLS_CRYPTO_ED25519 */

#ifdef HITLS_CRYPTO_X25519
/* Calculate the shared key based on the local private key and peer public key
 * Shared12 = prv1 * Pub2 = prv1 * (prv2 * G) = prv1 * prv2 * G
 */
int32_t CRYPT_CURVE25519_ComputeSharedKey(CRYPT_CURVE25519_Ctx *prvKey, CRYPT_CURVE25519_Ctx *pubKey,
    uint8_t *sharedKey, uint32_t *shareKeyLen)
{
    if (prvKey == NULL || pubKey == NULL || sharedKey == NULL || shareKeyLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (*shareKeyLen < CRYPT_CURVE25519_KEYLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_KEYLEN_ERROR);
        return CRYPT_CURVE25519_KEYLEN_ERROR;
    }
    if ((prvKey->keyType & CURVE25519_PRVKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_PRVKEY);
        return CRYPT_CURVE25519_NO_PRVKEY;
    }
    if ((pubKey->keyType & CURVE25519_PUBKEY) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_NO_PUBKEY);
        return CRYPT_CURVE25519_NO_PUBKEY;
    }

    uint32_t tmpLen = *shareKeyLen;
    ScalarMultiPoint(sharedKey, prvKey->prvKey, pubKey->pubKey);

    int32_t i;
    uint8_t checkValid = 0;
    for (i = 0; i < CRYPT_CURVE25519_KEYLEN; i++) {
        checkValid |= sharedKey[i];
    }
    if (checkValid == 0) {
        *shareKeyLen = tmpLen;
        BSL_ERR_PUSH_ERROR(CRYPT_CURVE25519_KEY_COMPUTE_FAILED);
        return CRYPT_CURVE25519_KEY_COMPUTE_FAILED;
    } else {
        *shareKeyLen = CRYPT_CURVE25519_KEYLEN;
        return CRYPT_SUCCESS;
    }
}

/**
 * @brief   x25519 Calculate the public key based on the private key.
 *
 * @param privateKey [IN] Private key
 * @param publicKey [OUT] Public key
 *
 */
void CRYPT_X25519_PublicFromPrivate(const uint8_t privateKey[CRYPT_CURVE25519_KEYLEN],
    uint8_t publicKey[CRYPT_CURVE25519_KEYLEN])
{
    uint8_t privateCopy[CRYPT_CURVE25519_KEYLEN];
    GeE out;
    Fp25 zPlusY, zMinusY, zMinusYInvert;

    (void)memcpy_s(privateCopy, sizeof(privateCopy), privateKey, sizeof(privateCopy));

    privateCopy[0] &= 0xf8;      /* decodeScalar25519(k): k_list[0] &= 0xf8 */
    privateCopy[31] &= 0x7f;     /* decodeScalar25519(k): k_list[31] &= 0x7f */
    privateCopy[31] |= 0x40;      /* decodeScalar25519(k): k_list[31] |= 0x40 */

    ScalarMultiBase(&out, privateCopy);

    CURVE25519_FP_ADD(zPlusY, out.z, out.y);
    CURVE25519_FP_SUB(zMinusY, out.z, out.y);
    FpInvert(zMinusYInvert, zMinusY);
    FpMul(zPlusY, zPlusY, zMinusYInvert);
    PolynomialToData(publicKey, zPlusY);

    /* cleanup tmp private key */
    BSL_SAL_CleanseData(privateCopy, sizeof(privateCopy));
}

int32_t CRYPT_X25519_GenKey(CRYPT_CURVE25519_Ctx *pkey)
{
    if (pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CRYPT_RandEx(pkey->libCtx, pkey->prvKey, sizeof(pkey->prvKey));
    if (ret != CRYPT_SUCCESS) {
        pkey->keyType = 0;
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    CRYPT_X25519_PublicFromPrivate(pkey->prvKey, pkey->pubKey);

    pkey->keyType = CURVE25519_PRVKEY | CURVE25519_PUBKEY;

    return CRYPT_SUCCESS;
}
#endif /* HITLS_CRYPTO_X25519 */

int32_t CRYPT_CURVE25519_Cmp(const CRYPT_CURVE25519_Ctx *a, const CRYPT_CURVE25519_Ctx *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    RETURN_RET_IF((a->keyType & CURVE25519_PUBKEY) == 0 || (b->keyType & CURVE25519_PUBKEY) == 0,
                  CRYPT_CURVE25519_NO_PUBKEY);

    RETURN_RET_IF(memcmp(a->pubKey, b->pubKey, CRYPT_CURVE25519_KEYLEN) != 0, CRYPT_CURVE25519_PUBKEY_NOT_EQUAL);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_CURVE25519_GetSecBits(const CRYPT_CURVE25519_Ctx *ctx)
{
    (void) ctx;
    return 128;
}

#ifdef HITLS_CRYPTO_PROVIDER

int32_t CRYPT_CURVE25519_Import(CRYPT_CURVE25519_Ctx *ctx, const BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = CRYPT_SUCCESS;
    const BSL_Param *prv = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_CURVE25519_PRVKEY);
    const BSL_Param *pub = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_CURVE25519_PUBKEY);

    if (prv != NULL) {
        ret = CRYPT_CURVE25519_SetPrvKey(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    if (pub != NULL) {
        ret = CRYPT_CURVE25519_SetPubKey(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return ret;
}

int32_t CRYPT_CURVE25519_Export(const CRYPT_CURVE25519_Ctx *ctx, BSL_Param *params)
{
    if (ctx == NULL || params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t index = 0;
    uint32_t keyBytes = CRYPT_CURVE25519_KEYLEN;
    CRYPT_EAL_ProcessFuncCb processCb = NULL;
    void *args = NULL;
    BSL_Param ed25519Params[3] = {0}; // 3: pub key + priv key + end marker
    int32_t ret = CRYPT_GetPkeyProcessParams(params, &processCb, &args);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    uint8_t *buffer = BSL_SAL_Calloc(1, keyBytes * 2); // For public + private key
    if (buffer == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if ((ctx->keyType & CURVE25519_PUBKEY) != 0) {
        (void)BSL_PARAM_InitValue(&ed25519Params[index], CRYPT_PARAM_CURVE25519_PUBKEY, BSL_PARAM_TYPE_OCTETS,
            buffer, keyBytes);
        ret = CRYPT_CURVE25519_GetPubKey(ctx, ed25519Params);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ed25519Params[index].valueLen = ed25519Params[index].useLen;
        index++;
    }
    if ((ctx->keyType & CURVE25519_PRVKEY) != 0) {
        (void)BSL_PARAM_InitValue(&ed25519Params[index], CRYPT_PARAM_CURVE25519_PRVKEY, BSL_PARAM_TYPE_OCTETS,
            buffer + keyBytes, keyBytes);
        ret = CRYPT_CURVE25519_GetPrvKey(ctx, ed25519Params);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(buffer);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        ed25519Params[index].valueLen = ed25519Params[index].useLen;
        index++;
    }
    ret = processCb(ed25519Params, args);
    BSL_SAL_Free(buffer);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

#endif // HITLS_CRYPTO_PROVIDER

#endif /* HITLS_CRYPTO_CURVE25519 */
