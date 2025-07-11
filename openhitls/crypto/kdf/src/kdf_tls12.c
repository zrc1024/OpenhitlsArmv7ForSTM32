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
#ifdef HITLS_CRYPTO_KDFTLS12

#include <stdint.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "crypt_local_types.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_kdf_tls12.h"
#include "eal_mac_local.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#define KDFTLS12_MAX_BLOCKSIZE 64

static const uint32_t KDFTLS12_ID_LIST[] = {
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
};

struct CryptKdfTls12Ctx {
    CRYPT_MAC_AlgId macId;
    const EAL_MacMethod *macMeth;
    void *macCtx;
    uint8_t *key;
    uint32_t keyLen;
    uint8_t *label;
    uint32_t labelLen;
    uint8_t *seed;
    uint32_t seedLen;
};

bool CRYPT_KDFTLS12_IsValidAlgId(CRYPT_MAC_AlgId id)
{
    return ParamIdIsValid(id, KDFTLS12_ID_LIST, sizeof(KDFTLS12_ID_LIST) / sizeof(KDFTLS12_ID_LIST[0]));
}

int32_t KDF_Hmac(const EAL_MacMethod *macMeth, void *macCtx, uint8_t *data, uint32_t *len)
{
    macMeth->reinit(macCtx);
    int32_t ret = macMeth->update(macCtx, data, *len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return macMeth->final(macCtx, data, len);
}

// algorithm implementation see https://datatracker.ietf.org/doc/pdf/rfc5246.pdf, chapter 5, p_hash function
int32_t KDF_PHASH(CRYPT_KDFTLS12_Ctx *ctx, uint8_t *out, uint32_t len)
{
    int32_t ret = CRYPT_SUCCESS;
    const EAL_MacMethod *macMeth = ctx->macMeth;
    uint32_t totalLen = 0;
    uint8_t nextIn[KDFTLS12_MAX_BLOCKSIZE];
    uint32_t nextInLen = KDFTLS12_MAX_BLOCKSIZE;
    uint8_t outTmp[KDFTLS12_MAX_BLOCKSIZE];
    uint32_t outTmpLen = KDFTLS12_MAX_BLOCKSIZE;

    void *macCtx = macMeth->newCtx(ctx->macId);
    if (macCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->macCtx = macCtx;

    while (len > totalLen) {
        if (totalLen == 0) {
            GOTO_ERR_IF(macMeth->init(ctx->macCtx, ctx->key, ctx->keyLen, NULL), ret);
            GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->label, ctx->labelLen), ret);
            GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->seed, ctx->seedLen), ret);
            GOTO_ERR_IF(macMeth->final(ctx->macCtx, nextIn, &nextInLen), ret);
        } else {
            GOTO_ERR_IF(KDF_Hmac(macMeth, ctx->macCtx, nextIn, &nextInLen), ret);
        }

        macMeth->reinit(ctx->macCtx);
        GOTO_ERR_IF(macMeth->update(ctx->macCtx, nextIn, nextInLen), ret);
        GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->label, ctx->labelLen), ret);
        GOTO_ERR_IF(macMeth->update(ctx->macCtx, ctx->seed, ctx->seedLen), ret);
        GOTO_ERR_IF(macMeth->final(ctx->macCtx, outTmp, &outTmpLen), ret);

        uint32_t cpyLen = outTmpLen > (len - totalLen) ? (len - totalLen) : outTmpLen;
        (void)memcpy_s(out + totalLen, len - totalLen, outTmp, cpyLen);
        totalLen += cpyLen;
    }

ERR:
    macMeth->deinit(ctx->macCtx);
    macMeth->freeCtx(ctx->macCtx);
    ctx->macCtx = NULL;
    return ret;
}

CRYPT_KDFTLS12_Ctx* CRYPT_KDFTLS12_NewCtx(void)
{
    CRYPT_KDFTLS12_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_KDFTLS12_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    return ctx;
}

int32_t CRYPT_KDFTLS12_SetMacMethod(CRYPT_KDFTLS12_Ctx *ctx, const CRYPT_MAC_AlgId id)
{
    EAL_MacMethLookup method;
    if (!CRYPT_KDFTLS12_IsValidAlgId(id)) {
        BSL_ERR_PUSH_ERROR(CRYPT_KDFTLS12_PARAM_ERROR);
        return CRYPT_KDFTLS12_PARAM_ERROR;
    }
    int32_t ret = EAL_MacFindMethod(id, &method);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_METH_NULL_NUMBER);
        return CRYPT_EAL_ERR_METH_NULL_NUMBER;
    }
    ctx->macMeth = method.macMethod;
    ctx->macId = id;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_KDFTLS12_SetKey(CRYPT_KDFTLS12_Ctx *ctx, const uint8_t *key, uint32_t keyLen)
{
    if (key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);

    ctx->key = BSL_SAL_Dump(key, keyLen);
    if (ctx->key == NULL && keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->keyLen = keyLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_KDFTLS12_SetLabel(CRYPT_KDFTLS12_Ctx *ctx, const uint8_t *label, uint32_t labelLen)
{
    if (label == NULL && labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->label, ctx->labelLen);

    ctx->label = BSL_SAL_Dump(label, labelLen);
    if (ctx->label == NULL && labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->labelLen = labelLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_KDFTLS12_SetSeed(CRYPT_KDFTLS12_Ctx *ctx, const uint8_t *seed, uint32_t seedLen)
{
    if (seed == NULL && seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    BSL_SAL_ClearFree((void *)ctx->seed, ctx->seedLen);

    ctx->seed = BSL_SAL_Dump(seed, seedLen);
    if (ctx->seed == NULL && seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ctx->seedLen = seedLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_KDFTLS12_SetParam(CRYPT_KDFTLS12_Ctx *ctx, const BSL_Param *param)
{
    uint32_t val = 0;
    uint32_t len = 0;
    const BSL_Param *temp = NULL;
    int32_t ret = CRYPT_PBKDF2_PARAM_ERROR;
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_MAC_ID)) != NULL) {
        len = sizeof(val);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_KDF_MAC_ID,
            BSL_PARAM_TYPE_UINT32, &val, &len), ret);
        GOTO_ERR_IF(CRYPT_KDFTLS12_SetMacMethod(ctx, val), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_KEY)) != NULL) {
        GOTO_ERR_IF(CRYPT_KDFTLS12_SetKey(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_LABEL)) != NULL) {
        GOTO_ERR_IF(CRYPT_KDFTLS12_SetLabel(ctx, temp->value, temp->valueLen), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_KDF_SEED)) != NULL) {
        GOTO_ERR_IF(CRYPT_KDFTLS12_SetSeed(ctx, temp->value, temp->valueLen), ret);
    }
ERR:
    return ret;
}

int32_t CRYPT_KDFTLS12_Derive(CRYPT_KDFTLS12_Ctx *ctx, uint8_t *out, uint32_t len)
{
    if (ctx->macMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->key == NULL && ctx->keyLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->label == NULL && ctx->labelLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->seed == NULL && ctx->seedLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((out == NULL) || (len == 0)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return KDF_PHASH(ctx, out, len);
}

int32_t CRYPT_KDFTLS12_Deinit(CRYPT_KDFTLS12_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);
    BSL_SAL_ClearFree((void *)ctx->label, ctx->labelLen);
    BSL_SAL_ClearFree((void *)ctx->seed, ctx->seedLen);
    (void)memset_s(ctx, sizeof(CRYPT_KDFTLS12_Ctx), 0, sizeof(CRYPT_KDFTLS12_Ctx));
    return CRYPT_SUCCESS;
}

void CRYPT_KDFTLS12_FreeCtx(CRYPT_KDFTLS12_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_ClearFree((void *)ctx->key, ctx->keyLen);
    BSL_SAL_ClearFree((void *)ctx->label, ctx->labelLen);
    BSL_SAL_ClearFree((void *)ctx->seed, ctx->seedLen);
    BSL_SAL_Free(ctx);
}

#endif // HITLS_CRYPTO_KDFTLS12
