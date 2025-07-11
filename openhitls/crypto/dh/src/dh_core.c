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
#ifdef HITLS_CRYPTO_DH

#include "crypt_errno.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_bn.h"
#include "crypt_utils.h"
#include "crypt_dh.h"
#include "dh_local.h"
#include "sal_atomic.h"
#include "crypt_local_types.h"
#include "crypt_params_key.h"

CRYPT_DH_Ctx *CRYPT_DH_NewCtx(void)
{
    CRYPT_DH_Ctx *ctx = BSL_SAL_Malloc(sizeof(CRYPT_DH_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_DH_Ctx), 0, sizeof(CRYPT_DH_Ctx));
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

CRYPT_DH_Ctx *CRYPT_DH_NewCtxEx(void *libCtx)
{
    CRYPT_DH_Ctx *ctx = CRYPT_DH_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

static CRYPT_DH_Para *ParaMemGet(uint32_t bits)
{
    CRYPT_DH_Para *para = BSL_SAL_Calloc(1u, sizeof(CRYPT_DH_Para));
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    para->p = BN_Create(bits);
    para->g = BN_Create(bits);
    para->id = CRYPT_PKEY_PARAID_MAX;
    if (para->p == NULL || para->g == NULL) {
        CRYPT_DH_FreePara(para);
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        return NULL;
    }
    return para;
}

static int32_t ValidateParamLength(const BSL_Param *param, uint32_t maxLen)
{
    if (param == NULL || param->value == NULL || param->valueLen > maxLen || param->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    return CRYPT_SUCCESS;
}

static int32_t GetDhParam(const BSL_Param *params, int32_t paramId, uint32_t maxLen,
    const uint8_t **value, uint32_t *valueLen)
{
    const BSL_Param *param = BSL_PARAM_FindConstParam(params, paramId);
    int32_t ret = ValidateParamLength(param, maxLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *value = param->value;
    *valueLen = param->valueLen;
    return CRYPT_SUCCESS;
}

static int32_t InitDhPara(CRYPT_DH_Para *para, const uint8_t *p, uint32_t pLen,
    const uint8_t *g, uint32_t gLen)
{
    int32_t ret = BN_Bin2Bn(para->p, p, pLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = BN_Bin2Bn(para->g, g, gLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t InitDhParaQ(CRYPT_DH_Para *para, const uint8_t *q, uint32_t qLen, uint32_t modBits)
{
    if (q == NULL) {
        return CRYPT_SUCCESS;
    }

    para->q = BN_Create(modBits);
    if (para->q == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        return CRYPT_DH_CREATE_PARA_FAIL;
    }

    int32_t ret = BN_Bin2Bn(para->q, q, qLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

CRYPT_DH_Para *CRYPT_DH_NewPara(const BSL_Param *params)
{
    if (params == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }

    const uint8_t *p = NULL;
    uint32_t pLen = 0;
    int32_t ret = GetDhParam(params, CRYPT_PARAM_DH_P, BN_BITS_TO_BYTES(DH_MAX_PBITS), &p, &pLen);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }

    const uint8_t *g = NULL;
    uint32_t gLen = 0;
    ret = GetDhParam(params, CRYPT_PARAM_DH_G, pLen, &g, &gLen);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }

    const uint8_t *q = NULL;
    uint32_t qLen = 0;
    const BSL_Param *qParam = BSL_PARAM_FindConstParam(params, CRYPT_PARAM_DH_Q);
    if (qParam != NULL) {
        if (qParam->value == NULL && qParam->valueLen != 0) {
            return NULL;
        }
        if (qParam->value != NULL) {
            ret = ValidateParamLength(qParam, pLen);
            if (ret != CRYPT_SUCCESS) {
                return NULL;
            }
            q = qParam->value;
            qLen = qParam->valueLen;
        }
    }

    uint32_t modBits = BN_BYTES_TO_BITS(pLen);
    CRYPT_DH_Para *para = ParaMemGet(modBits);
    if (para == NULL) {
        return NULL;
    }

    ret = InitDhPara(para, p, pLen, g, gLen);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    ret = InitDhParaQ(para, q, qLen, modBits);
    if (ret != CRYPT_SUCCESS) {
        goto ERR;
    }

    para->id = CRYPT_PKEY_PARAID_MAX;
    return para;

ERR:
    CRYPT_DH_FreePara(para);
    return NULL;
}

void CRYPT_DH_FreePara(CRYPT_DH_Para *dhPara)
{
    if (dhPara == NULL) {
        return;
    }
    BN_Destroy(dhPara->p);
    BN_Destroy(dhPara->q);
    BN_Destroy(dhPara->g);
    BSL_SAL_FREE(dhPara);
}

void CRYPT_DH_FreeCtx(CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int val = 0;
    BSL_SAL_AtomicDownReferences(&(ctx->references), &val);
    if (val > 0) {
        return;
    }
    CRYPT_DH_FreePara(ctx->para);
    BN_Destroy(ctx->x);
    BN_Destroy(ctx->y);
    BSL_SAL_ReferencesFree(&(ctx->references));
    BSL_SAL_FREE(ctx);
}

static int32_t ParaQCheck(BN_BigNum *q, BN_BigNum *r)
{
    // 1. Determine the length.
    if (BN_Bits(q) < DH_MIN_QBITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // 2. Parity and even judgment
    if (BN_GetBit(q, 0) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // 3. Compare q and r.
    if (BN_Cmp(q, r) >= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }

    // 4. Check the pq multiple relationship.
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Div(NULL, r, r, q, opt);
    BN_OptimizerDestroy(opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    // (p - 1) % q == 0
    if (!BN_IsZero(r)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    return CRYPT_SUCCESS;
}

static int32_t ParaDataCheck(const CRYPT_DH_Para *para)
{
    int32_t ret;
    const BN_BigNum *p = para->p;
    const BN_BigNum *g = para->g;
    // 1. Determine the length.
    uint32_t pBits = BN_Bits(p);
    if (pBits < DH_MIN_PBITS || pBits > DH_MAX_PBITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // 2. P parity and g value judgment
    // p is an odd number
    if (BN_GetBit(p, 0) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    // g != 0 && g != 1
    if (BN_IsZero(g) || BN_IsOne(g)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }

    BN_BigNum *r = BN_Create(pBits + 1);
    if (r == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // r = p - 1
    ret = BN_SubLimb(r, p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // g < p - 1
    if (BN_Cmp(g, r) >= 0) {
        ret = CRYPT_DH_PARA_ERROR;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    if (para->q != NULL) {
        ret = ParaQCheck(para->q, r);
    }
EXIT:
    BN_Destroy(r);
    return ret;
}

static CRYPT_DH_Para *ParaDup(const CRYPT_DH_Para *para)
{
    CRYPT_DH_Para *ret = BSL_SAL_Malloc(sizeof(CRYPT_DH_Para));
    if (ret == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ret->p = BN_Dup(para->p);
    ret->q = BN_Dup(para->q);
    ret->g = BN_Dup(para->g);
    ret->id = para->id;
    if (ret->p == NULL || ret->g == NULL) {
        CRYPT_DH_FreePara(ret);
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        return NULL;
    }
    if (para->q != NULL && ret->q == NULL) {
        CRYPT_DH_FreePara(ret);
        BSL_ERR_PUSH_ERROR(CRYPT_DH_CREATE_PARA_FAIL);
        return NULL;
    }
    return ret;
}

CRYPT_DH_Ctx *CRYPT_DH_DupCtx(CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_DH_Ctx *newKeyCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_DH_Ctx));
    if (newKeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    // If x, y and para is not empty, copy the value.
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->x, ctx->x, BN_Dup(ctx->x), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->y, ctx->y, BN_Dup(ctx->y), CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF_SRC_NOT_NULL(newKeyCtx->para, ctx->para, ParaDup(ctx->para), CRYPT_MEM_ALLOC_FAIL);
    BSL_SAL_ReferencesInit(&(newKeyCtx->references));
    return newKeyCtx;

ERR:
    CRYPT_DH_FreeCtx(newKeyCtx);
    return NULL;
}

int32_t CRYPT_DH_SetParaEx(CRYPT_DH_Ctx *ctx, CRYPT_DH_Para *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = ParaDataCheck(para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_Destroy(ctx->x);
    BN_Destroy(ctx->y);
    CRYPT_DH_FreePara(ctx->para);
    ctx->x = NULL;
    ctx->y = NULL;
    ctx->para = para;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_SetPara(CRYPT_DH_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_DH_Para *dhPara = CRYPT_DH_NewPara(para);
    if (dhPara == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    int32_t ret = ParaDataCheck(dhPara);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DH_FreePara(dhPara);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BN_Destroy(ctx->x);
    BN_Destroy(ctx->y);
    CRYPT_DH_FreePara(ctx->para);
    ctx->x = NULL;
    ctx->y = NULL;
    ctx->para = dhPara;
    return CRYPT_SUCCESS;
}

static int32_t GetDhParamP(const CRYPT_DH_Para *para, BSL_Param *param)
{
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_DH_P);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }

    temp->useLen = temp->valueLen;
    int32_t ret = BN_Bn2Bin(para->p, temp->value, &temp->useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t GetDhParamQ(const CRYPT_DH_Para *para, BSL_Param *param)
{
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_DH_Q);
    if (temp == NULL) {
        return CRYPT_SUCCESS;
    }

    if (para->q == NULL) {
        temp->useLen = 0;
        return CRYPT_SUCCESS;
    }

    temp->useLen = temp->valueLen;
    int32_t ret = BN_Bn2Bin(para->q, temp->value, &temp->useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

static int32_t GetDhParamG(const CRYPT_DH_Para *para, BSL_Param *param)
{
    BSL_Param *temp = BSL_PARAM_FindParam(param, CRYPT_PARAM_DH_G);
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }

    temp->useLen = temp->valueLen;
    int32_t ret = BN_Bn2Bin(para->g, temp->value, &temp->useLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

int32_t CRYPT_DH_GetPara(const CRYPT_DH_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }

    int32_t ret = GetDhParamP(ctx->para, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = GetDhParamQ(ctx->para, param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return GetDhParamG(ctx->para, param);
}

static int32_t PubCheck(const BN_BigNum *y, const BN_BigNum *minP)
{
    // y != 0, y != 1
    if (BN_IsZero(y) || BN_IsOne(y)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    // y < p - 1
    if (BN_Cmp(y, minP) >= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    return CRYPT_SUCCESS;
}

// Get p-2 or q-1
static int32_t GetXLimb(BN_BigNum *xLimb, const BN_BigNum *p, const BN_BigNum *q)
{
    if (q != NULL) {
        // xLimb = q - 1
        return BN_SubLimb(xLimb, q, 1);
    }
    // xLimb = p - 2
    return BN_SubLimb(xLimb, p, 2);
}

static void RefreshCtx(CRYPT_DH_Ctx *dhCtx, BN_BigNum *x, BN_BigNum *y, int32_t ret)
{
    if (ret == CRYPT_SUCCESS) {
        BN_Destroy(dhCtx->x);
        BN_Destroy(dhCtx->y);
        dhCtx->x = x;
        dhCtx->y = y;
    } else {
        BN_Destroy(x);
        BN_Destroy(y);
    }
}

/* SP800-56Ar3 5.6.1.1.4 Key-Pair Generation by Testing Candidates */
static int32_t DH_GenSp80056ATestCandidates(CRYPT_DH_Ctx *ctx)
{
    int32_t ret;
    uint32_t bits = BN_Bits(ctx->para->p);
    uint32_t qbits = BN_Bits(ctx->para->q);
    /* If s is not the maximum security strength that can be support by (p, q, g), then return an error. */
    uint32_t s = (uint32_t)CRYPT_DH_GetSecBits(ctx);
    if (bits == 0 || qbits == 0 || s == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    /* 2*s <= n <= len(q), set n = 2*s */
    uint32_t n = 2 * s;
    BN_BigNum *x = BN_Create(bits);
    BN_BigNum *y = BN_Create(bits);
    BN_BigNum *twoPowN = BN_Create(n);
    BN_Mont *mont = BN_MontCreate(ctx->para->p);
    BN_BigNum *m = ctx->para->q;
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (x == NULL || y == NULL || mont == NULL || opt == NULL || twoPowN == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    ret = BN_SetLimb(twoPowN, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Lshift(twoPowN, twoPowN, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    /* Set M = min(2^N, q), the minimum of 2^N and q. */
    if (BN_Cmp(twoPowN, m) < 0) {
        m = twoPowN;
    }
    for (int32_t cnt = 0; cnt < CRYPT_DH_TRY_CNT_MAX; cnt++) {
        /* c in the interval [0, 2N - 1] */
        ret = BN_RandRangeEx(ctx->libCtx, x, twoPowN);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        /* x = c + 1 */
        ret = BN_AddLimb(x, x, 1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto ERR;
        }
        /* If c > M - 2, (i.e. c + 1 >= M) continue */
        if (BN_Cmp(x, m) >= 0) {
            continue;
        }
        ret = BN_MontExpConsttime(y, ctx->para->g, x, mont, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
        }
        goto ERR; // The function exits successfully.
    }
    ret = CRYPT_DH_RAND_GENERATE_ERROR;
    BSL_ERR_PUSH_ERROR(ret);
ERR:
    RefreshCtx(ctx, x, y, ret);
    BN_Destroy(twoPowN);
    BN_MontDestroy(mont);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t DH_GenSp80056ASafePrime(CRYPT_DH_Ctx *ctx)
{
    int32_t ret;
    uint32_t bits = BN_Bits(ctx->para->p);
    BN_BigNum *x = BN_Create(bits);
    BN_BigNum *y = BN_Create(bits);
    BN_BigNum *minP = BN_Create(bits);
    BN_BigNum *xLimb = BN_Create(bits);
    BN_Mont *mont = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (x == NULL || y == NULL || minP == NULL || xLimb == NULL || mont == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SubLimb(minP, ctx->para->p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = GetXLimb(xLimb, ctx->para->p, ctx->para->q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    for (int32_t cnt = 0; cnt < CRYPT_DH_TRY_CNT_MAX; cnt++) {
        /*  Generate private key x for [1, q-1] or [1, p-2] */
        ret = BN_RandRangeEx(ctx->libCtx, x, xLimb);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        ret = BN_AddLimb(x, x, 1);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        /* Calculate the public key y. */
        ret = BN_MontExpConsttime(y, ctx->para->g, x, mont, opt);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            goto EXIT;
        }
        /* Check whether the public key meets the requirements. If not, try to generate the key again. */
        // y != 0, y != 1, y < p - 1
        if (BN_IsZero(y) || BN_IsOne(y) || BN_Cmp(y, minP) >= 0) {
            continue;
        }
        goto EXIT; // The function exits successfully.
    }
    ret = CRYPT_DH_RAND_GENERATE_ERROR;
    BSL_ERR_PUSH_ERROR(ret);
EXIT:
    RefreshCtx(ctx, x, y, ret);
    BN_Destroy(minP);
    BN_Destroy(xLimb);
    BN_MontDestroy(mont);
    BN_OptimizerDestroy(opt);
    return ret;
}

int32_t CRYPT_DH_Gen(CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    int32_t s = CRYPT_DH_GetSecBits(ctx);
    if (ctx->para->q != NULL && s != 0) {
        return DH_GenSp80056ATestCandidates(ctx);
    }
    return DH_GenSp80056ASafePrime(ctx);
}

static int32_t ComputeShareKeyInputCheck(const CRYPT_DH_Ctx *ctx, const CRYPT_DH_Ctx *pubKey,
    const uint8_t *shareKey, const uint32_t *shareKeyLen)
{
    if (ctx == NULL || pubKey == NULL || shareKey == NULL || shareKeyLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    if (ctx->x == NULL || pubKey->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    if (BN_Bytes(ctx->para->p) > *shareKeyLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

static void CheckAndFillZero(uint8_t *shareKey, uint32_t *shareKeyLen, uint32_t bytes)
{
    int32_t i;
    if (*shareKeyLen == bytes) { // (*shareKeyLen > bytes) is not possible
        return;
    }
    uint32_t fill = bytes - *shareKeyLen;
    for (i = (int32_t)*shareKeyLen - 1; i >= 0; i--) {
        shareKey[i + (int32_t)fill] = shareKey[i];
    }
    for (i = 0; i < (int32_t)fill; i++) {
        shareKey[i] = 0;
    }
    *shareKeyLen = bytes;
}

int32_t CRYPT_DH_ComputeShareKey(const CRYPT_DH_Ctx *ctx, const CRYPT_DH_Ctx *pubKey,
    uint8_t *shareKey, uint32_t *shareKeyLen)
{
    uint32_t bytes = 0;
    int32_t ret = ComputeShareKeyInputCheck(ctx, pubKey, shareKey, shareKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    uint32_t bits = BN_Bits(ctx->para->p);
    BN_BigNum *tmp = BN_Create(bits);
    BN_Mont *mont = BN_MontCreate(ctx->para->p);
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (tmp == NULL || mont == NULL || opt == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_SubLimb(tmp, ctx->para->p, 1);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    /* Check whether the public key meets the requirements. */
    ret = PubCheck(pubKey->y, tmp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_MontExpConsttime(tmp, pubKey->y, ctx->x, mont, opt);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    ret = BN_Bn2Bin(tmp, shareKey, shareKeyLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    // no need to filled zero in the leading.
    if ((ctx->flags & CRYPT_DH_NO_PADZERO) == 0) {
        bytes = BN_BITS_TO_BYTES(bits);
        CheckAndFillZero(shareKey, shareKeyLen, bytes);
    }
EXIT:
    BN_Destroy(tmp);
    BN_MontDestroy(mont);
    BN_OptimizerDestroy(opt);
    return ret;
}

static int32_t PrvLenCheck(const CRYPT_DH_Ctx *ctx, const BSL_Param *prv)
{
    if (ctx->para->q != NULL) {
        if (BN_Bytes(ctx->para->q) < prv->valueLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
            return CRYPT_DH_KEYINFO_ERROR;
        }
    } else {
        if (BN_Bytes(ctx->para->p) < prv->valueLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
            return CRYPT_DH_KEYINFO_ERROR;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_SetPrvKey(CRYPT_DH_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    const BSL_Param *prv = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_DH_PRVKEY);
    if (prv == NULL || prv->value == NULL || prv->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    int32_t ret = PrvLenCheck(ctx, prv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    BN_BigNum *bnX = BN_Create(BN_BYTES_TO_BITS(prv->valueLen));
    BN_BigNum *xLimb = BN_Create(BN_Bits(ctx->para->p) + 1);
    if (bnX == NULL || xLimb == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = GetXLimb(xLimb, ctx->para->p, ctx->para->q);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_Bin2Bn(bnX, prv->value, prv->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    // Satisfy x <= q - 1 or x <= p - 2
    if (BN_Cmp(bnX, xLimb) > 0) {
        ret = CRYPT_DH_KEYINFO_ERROR;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    // x != 0
    if (BN_IsZero(bnX)) {
        ret = CRYPT_DH_KEYINFO_ERROR;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    BN_Destroy(xLimb);
    BN_Destroy(ctx->x);
    ctx->x = bnX;
    return ret;
ERR:
    BN_Destroy(bnX);
    BN_Destroy(xLimb);
    return ret;
}

// No parameter information is required for setting the public key.
// Therefore, the validity of the public key is not checked during the setting.
// The validity of the public key is checked during the calculation of the shared key.
int32_t CRYPT_DH_SetPubKey(CRYPT_DH_Ctx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // assume that the two scenarios will not coexist.
    const BSL_Param *pub = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_DH_PUBKEY);
    if (pub == NULL) {
        pub = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    }
    
    if (pub == NULL || pub->value == NULL || pub->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->valueLen > BN_BITS_TO_BYTES(DH_MAX_PBITS)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    BN_BigNum *bnY = BN_Create(BN_BYTES_TO_BITS(pub->valueLen));
    if (bnY == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BN_Bin2Bn(bnY, pub->value, pub->valueLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

    BN_Destroy(ctx->y);
    ctx->y = bnY;
    return ret;
ERR:
    BN_Destroy(bnY);
    return ret;
}

int32_t CRYPT_DH_GetPrvKey(const CRYPT_DH_Ctx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    BSL_Param *prv = BSL_PARAM_FindParam(para, CRYPT_PARAM_DH_PRVKEY);
    if (prv == NULL || prv->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->x == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    if (ctx->para->q != NULL) {
        if (BN_Bytes(ctx->para->q) > prv->valueLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
        }
    } else {
        if (BN_Bytes(ctx->para->p) > prv->valueLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
        }
    }
    uint32_t useLen = prv->valueLen;
    int32_t ret = BN_Bn2Bin(ctx->x, prv->value, &(useLen));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    prv->useLen = useLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_GetPubKey(const CRYPT_DH_Ctx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // assume that the two scenarios will not coexist.
    BSL_Param *pub = BSL_PARAM_FindParam(para, CRYPT_PARAM_DH_PUBKEY);
    if (pub == NULL) {
        pub = BSL_PARAM_FindParam(para, CRYPT_PARAM_PKEY_ENCODE_PUBKEY);
    }

    if (pub == NULL || pub->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para == NULL || ctx->para->p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    if (ctx->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    uint32_t pubLen = BN_Bytes(ctx->para->p);
    if (pubLen > pub->valueLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_DH_BUFF_LEN_NOT_ENOUGH;
    }
    // RFC 8446 requires the dh public value should be encoded as a big-endian integer and padded to
    // the left with zeros to the size of p in bytes.
    int32_t ret = BN_Bn2BinFixZero(ctx->y, pub->value, pubLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub->useLen = pubLen;
    return CRYPT_SUCCESS;
}

uint32_t CRYPT_DH_GetBits(const CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (ctx->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    return BN_Bits(ctx->para->p);
}

static uint32_t CRYPT_DH_GetPrvKeyLen(const CRYPT_DH_Ctx *ctx)
{
    return BN_Bytes(ctx->x);
}

static uint32_t CRYPT_DH_GetPubKeyLen(const CRYPT_DH_Ctx *ctx)
{
    if (ctx->para != NULL) {
        return BN_Bytes(ctx->para->p);
    }
    if (ctx->y != NULL) {
        return BN_Bytes(ctx->y);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return 0;
}

static uint32_t CRYPT_DH_GetSharedKeyLen(const CRYPT_DH_Ctx *ctx)
{
    if (ctx->para != NULL) {
        return BN_Bytes(ctx->para->p);
    }
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return 0;
}

int32_t CRYPT_DH_Check(const CRYPT_DH_Ctx *prv, const CRYPT_DH_Ctx *pub)
{
    int32_t ret;
    if (prv == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->x == NULL || pub->y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_KEYINFO_ERROR);
        return CRYPT_DH_KEYINFO_ERROR;
    }
    if (prv->para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_PARA_ERROR);
        return CRYPT_DH_PARA_ERROR;
    }
    BN_Mont *mont = BN_MontCreate(prv->para->p);
    BN_BigNum *y = BN_Create(BN_Bits(prv->para->p));
    if (y == NULL || mont == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    ret = BN_MontExpConsttime(y, prv->para->g, prv->x, mont, NULL);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    if (BN_Cmp(y, pub->y) != 0) {
        ret = CRYPT_DH_PAIRWISE_CHECK_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
    }

ERR:
    BN_Destroy(y);
    BN_MontDestroy(mont);
    return ret;
}

int32_t CRYPT_DH_Cmp(const CRYPT_DH_Ctx *a, const CRYPT_DH_Ctx *b)
{
    RETURN_RET_IF(a == NULL || b == NULL, CRYPT_NULL_INPUT);

    RETURN_RET_IF(a->y == NULL || b->y == NULL, CRYPT_DH_KEYINFO_ERROR);
    RETURN_RET_IF(BN_Cmp(a->y, b->y) != 0, CRYPT_DH_PUBKEY_NOT_EQUAL);

    // para must be both null and non-null.
    RETURN_RET_IF((a->para == NULL) != (b->para == NULL), CRYPT_DH_PARA_ERROR);
    if (a->para != NULL) {
        RETURN_RET_IF(BN_Cmp(a->para->p, b->para->p) != 0 ||
                      BN_Cmp(a->para->q, b->para->q) != 0 ||
                      BN_Cmp(a->para->g, b->para->g) != 0,
                      CRYPT_DH_PARA_NOT_EQUAL);
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_SetParamById(CRYPT_DH_Ctx *ctx, CRYPT_PKEY_ParaId id)
{
    CRYPT_DH_Para *para = CRYPT_DH_NewParaById(id);
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_NEW_PARA_FAIL);
        return CRYPT_EAL_ERR_NEW_PARA_FAIL;
    }
    int32_t ret = CRYPT_DH_SetParaEx(ctx, para);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_DH_FreePara(para);
    }
    return ret;
}

static int32_t CRYPT_DH_GetLen(const CRYPT_DH_Ctx *ctx, GetLenFunc func, void *val, uint32_t len)
{
    if (val == NULL || len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    *(int32_t *)val = func(ctx);
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_DH_SetFlag(CRYPT_DH_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_SET_FLAG_LEN_ERROR);
        return CRYPT_DH_SET_FLAG_LEN_ERROR;
    }
    uint32_t flag = *(const uint32_t *)val;
    if (flag == 0 || flag >= CRYPT_DH_MAXFLAG) {
        BSL_ERR_PUSH_ERROR(CRYPT_DH_FLAG_NOT_SUPPORT_ERROR);
        return CRYPT_DH_FLAG_NOT_SUPPORT_ERROR;
    }
    ctx->flags |= flag;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_DH_Ctrl(CRYPT_DH_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_GET_PARAID:
            return CRYPT_DH_GetLen(ctx, (GetLenFunc)CRYPT_DH_GetParaId, val, len);
        case CRYPT_CTRL_GET_BITS:
            return CRYPT_DH_GetLen(ctx, (GetLenFunc)CRYPT_DH_GetBits, val, len);
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_DH_GetLen(ctx, (GetLenFunc)CRYPT_DH_GetSecBits, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DH_GetPubKeyLen);
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DH_GetPrvKeyLen);
        case CRYPT_CTRL_GET_SHARED_KEY_LEN:
            return GetUintCtrl(ctx, val, len, (GetUintCallBack)CRYPT_DH_GetSharedKeyLen);
        case CRYPT_CTRL_SET_PARA_BY_ID:
            return CRYPT_DH_SetParamById(ctx, *(CRYPT_PKEY_ParaId *)val);
        case CRYPT_CTRL_SET_DH_FLAG:
            return CRYPT_DH_SetFlag(ctx, val, len);
        case CRYPT_CTRL_UP_REFERENCES:
            if (val == NULL || len != (uint32_t)sizeof(int)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            return BSL_SAL_AtomicUpReferences(&(ctx->references), (int *)val);
        default:
            break;
    }
    BSL_ERR_PUSH_ERROR(CRYPT_DH_UNSUPPORTED_CTRL_OPTION);
    return CRYPT_DH_UNSUPPORTED_CTRL_OPTION;
}

/**
 * @ingroup dh
 * @brief dh get security bits
 *
 * @param ctx [IN] dh Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_DH_GetSecBits(const CRYPT_DH_Ctx *ctx)
{
    if (ctx == NULL || ctx->para == NULL || ctx->para->p == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return 0;
    }
    if (ctx->para->q == NULL) {
        return BN_SecBits(BN_Bits(ctx->para->p), -1);
    }
    return BN_SecBits(BN_Bits(ctx->para->p), BN_Bits(ctx->para->q));
}

#endif /* HITLS_CRYPTO_DH */
