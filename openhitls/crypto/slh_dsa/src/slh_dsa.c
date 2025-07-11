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
#ifdef HITLS_CRYPTO_SLH_DSA

#include <stddef.h>
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_obj_internal.h"
#include "bsl_asn1.h"
#include "crypt_errno.h"
#include "crypt_util_rand.h"
#include "eal_md_local.h"
#include "crypt_slh_dsa.h"
#include "slh_dsa_local.h"
#include "slh_dsa_hash.h"
#include "slh_dsa_fors.h"
#include "slh_dsa_xmss.h"
#include "slh_dsa_hypertree.h"

#define MAX_DIGEST_SIZE 64
#define BYTE_BITS          8
#define SLH_DSA_PREFIX_LEN 2
#define ASN1_HEADER_LEN    2
#define SPLIT_CEIL(a, b)   (((a) + (b) - 1) / (b))
#define SPLIT_BYTES(a)     SPLIT_CEIL(a, BYTE_BITS)

typedef struct {
    BSL_Param *pubSeed;
    BSL_Param *pubRoot;
} SlhDsaPubKeyParam;

typedef struct {
    BSL_Param *prvSeed;
    BSL_Param *prvPrf;
    BSL_Param *pubSeed;
    BSL_Param *pubRoot;
} SlhDsaPrvKeyParam;

// reference to FIPS-205, table 2
static uint32_t g_slhDsaN[CRYPT_SLH_DSA_ALG_ID_MAX] = {16, 16, 16, 16, 24, 24, 24, 24, 32, 32, 32, 32};
static uint32_t g_slhDsaH[CRYPT_SLH_DSA_ALG_ID_MAX] = {63, 63, 66, 66, 63, 63, 66, 66, 64, 64, 68, 68};
static uint32_t g_slhDsaD[CRYPT_SLH_DSA_ALG_ID_MAX] = {7, 7, 22, 22, 7, 7, 22, 22, 8, 8, 17, 17};
static uint32_t g_slhDsaHp[CRYPT_SLH_DSA_ALG_ID_MAX] = {9, 9, 3, 3, 9, 9, 3, 3, 8, 8, 4, 4}; // xmss height
static uint32_t g_slhDsaA[CRYPT_SLH_DSA_ALG_ID_MAX] = {12, 12, 6, 6, 14, 14, 8, 8, 14, 14, 9, 9};
static uint32_t g_slhDsaK[CRYPT_SLH_DSA_ALG_ID_MAX] = {14, 14, 33, 33, 17, 17, 33, 33, 22, 22, 35, 35};
static uint32_t g_slhDsaM[CRYPT_SLH_DSA_ALG_ID_MAX] = {30, 30, 34, 34, 39, 39, 42, 42, 47, 47, 49, 49};
static uint32_t g_slhDsaPkBytes[CRYPT_SLH_DSA_ALG_ID_MAX] = {32, 32, 32, 32, 48, 48, 48, 48, 64, 64, 64, 64};
static uint32_t g_slhDsaSigBytes[CRYPT_SLH_DSA_ALG_ID_MAX] = {7856,  7856,  17088, 17088, 16224, 16224,
                                                              35664, 35664, 29792, 29792, 49856, 49856};
static uint8_t g_secCategory[] = {1, 1, 1, 1, 3, 3, 3, 3, 5, 5, 5, 5};

// "UC" means uncompressed
static void UCAdrsSetLayerAddr(SlhDsaAdrs *adrs, uint32_t layer)
{
    PUT_UINT32_BE(layer, adrs->uc.layerAddr, 0);
}

static void UCAdrsSetTreeAddr(SlhDsaAdrs *adrs, uint64_t tree)
{
    // Write 8-byte tree address starting from offset 4 in 12-byte treeAddr field
    PUT_UINT64_BE(tree, adrs->uc.treeAddr, 4);
}

static void UCAdrsSetType(SlhDsaAdrs *adrs, AdrsType type)
{
    PUT_UINT32_BE(type, adrs->uc.type, 0);
    (void)memset_s(adrs->uc.padding, sizeof(adrs->uc.padding), 0, sizeof(adrs->uc.padding));
}

static void UCAdrsSetKeyPairAddr(SlhDsaAdrs *adrs, uint32_t keyPair)
{
    PUT_UINT32_BE(keyPair, adrs->uc.padding, 0);
}

static void UCAdrsSetChainAddr(SlhDsaAdrs *adrs, uint32_t chain)
{
    PUT_UINT32_BE(chain, adrs->uc.padding, 4); // chain address is 4 bytes, start from 4-th byte
}

static void UCAdrsSetTreeHeight(SlhDsaAdrs *adrs, uint32_t height)
{
    PUT_UINT32_BE(height, adrs->uc.padding, 4); // tree height is 4 bytes, start from 4-th byte
}

static void UCAdrsSetHashAddr(SlhDsaAdrs *adrs, uint32_t hash)
{
    PUT_UINT32_BE(hash, adrs->uc.padding, 8); // hash address is 4 bytes, start from 8-th byte
}

static void UCAdrsSetTreeIndex(SlhDsaAdrs *adrs, uint32_t index)
{
    PUT_UINT32_BE(index, adrs->uc.padding, 8); // tree index is 4 bytes, start from 8-th byte
}

static uint32_t UCAdrsGetTreeHeight(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->uc.padding, 0);
}

static uint32_t UCAdrsGetTreeIndex(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->uc.padding, 8); // tree index is 4 bytes, start from 8-th byte
}

static void UCAdrsCopyKeyPairAddr(SlhDsaAdrs *adrs, const SlhDsaAdrs *adrs2)
{
    (void)memcpy_s(adrs->uc.padding, sizeof(adrs->uc.padding), adrs2->uc.padding,
                   4); // key pair address is 4 bytes, start from 4-th byte
}

static uint32_t UCAdrsGetAdrsLen(void)
{
    return SLH_DSA_ADRS_LEN;
}

// "C" means compressed
static void CAdrsSetLayerAddr(SlhDsaAdrs *adrs, uint32_t layer)
{
    adrs->c.layerAddr = layer;
}

static void CAdrsSetTreeAddr(SlhDsaAdrs *adrs, uint64_t tree)
{
    // Write 8-byte tree address starting from offset 0 in 8-byte treeAddr field
    PUT_UINT64_BE(tree, adrs->c.treeAddr, 0);
}

static void CAdrsSetType(SlhDsaAdrs *adrs, AdrsType type)
{
    adrs->c.type = type;
    (void)memset_s(adrs->c.padding, sizeof(adrs->c.padding), 0, sizeof(adrs->c.padding));
}

static void CAdrsSetKeyPairAddr(SlhDsaAdrs *adrs, uint32_t keyPair)
{
    PUT_UINT32_BE(keyPair, adrs->c.padding, 0);
}

static void CAdrsSetChainAddr(SlhDsaAdrs *adrs, uint32_t chain)
{
    PUT_UINT32_BE(chain, adrs->c.padding, 4); // chain address is 4 bytes, start from 4-th byte
}

static void CAdrsSetTreeHeight(SlhDsaAdrs *adrs, uint32_t height)
{
    PUT_UINT32_BE(height, adrs->c.padding, 4); // tree height is 4 bytes, start from 4-th byte
}

static void CAdrsSetHashAddr(SlhDsaAdrs *adrs, uint32_t hash)
{
    PUT_UINT32_BE(hash, adrs->c.padding, 8); // hash address is 4 bytes, start from 8-th byte
}

static void CAdrsSetTreeIndex(SlhDsaAdrs *adrs, uint32_t index)
{
    PUT_UINT32_BE(index, adrs->c.padding, 8); // tree index is 4 bytes, start from 8-th byte
}

static uint32_t CAdrsGetTreeHeight(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->c.padding, 0); // tree height is 4 bytes, start from 0-th byte
}

static uint32_t CAdrsGetTreeIndex(const SlhDsaAdrs *adrs)
{
    return GET_UINT32_BE(adrs->c.padding, 8); // tree index is 4 bytes, start from 8-th byte
}

static void CAdrsCopyKeyPairAddr(SlhDsaAdrs *adrs, const SlhDsaAdrs *adrs2)
{
    (void)memcpy_s(adrs->c.padding, sizeof(adrs->c.padding), adrs2->c.padding,
                   4); // key pair address is 4 bytes, start from 4-th byte
}

static uint32_t CAdrsGetAdrsLen(void)
{
    return SLH_DSA_ADRS_COMPRESSED_LEN;
}

static AdrsOps g_adrsOps[2] = {{
                                   .setLayerAddr = UCAdrsSetLayerAddr,
                                   .setTreeAddr = UCAdrsSetTreeAddr,
                                   .setType = UCAdrsSetType,
                                   .setKeyPairAddr = UCAdrsSetKeyPairAddr,
                                   .setChainAddr = UCAdrsSetChainAddr,
                                   .setTreeHeight = UCAdrsSetTreeHeight,
                                   .setHashAddr = UCAdrsSetHashAddr,
                                   .setTreeIndex = UCAdrsSetTreeIndex,
                                   .getTreeHeight = UCAdrsGetTreeHeight,
                                   .getTreeIndex = UCAdrsGetTreeIndex,
                                   .copyKeyPairAddr = UCAdrsCopyKeyPairAddr,
                                   .getAdrsLen = UCAdrsGetAdrsLen,
                               },
                               {
                                   .setLayerAddr = CAdrsSetLayerAddr,
                                   .setTreeAddr = CAdrsSetTreeAddr,
                                   .setType = CAdrsSetType,
                                   .setKeyPairAddr = CAdrsSetKeyPairAddr,
                                   .setChainAddr = CAdrsSetChainAddr,
                                   .setTreeHeight = CAdrsSetTreeHeight,
                                   .setHashAddr = CAdrsSetHashAddr,
                                   .setTreeIndex = CAdrsSetTreeIndex,
                                   .getTreeHeight = CAdrsGetTreeHeight,
                                   .getTreeIndex = CAdrsGetTreeIndex,
                                   .copyKeyPairAddr = CAdrsCopyKeyPairAddr,
                                   .getAdrsLen = CAdrsGetAdrsLen,
                               }};

void BaseB(const uint8_t *x, uint32_t xLen, uint32_t b, uint32_t *out, uint32_t outLen)
{
    uint32_t bit = 0;
    uint32_t o = 0;
    uint32_t xi = 0;
    for (uint32_t i = 0; i < outLen; i++) {
        while (bit < b && xi < xLen) {
            o = (o << BYTE_BITS) + x[xi];
            bit += 8;
            xi++;
        }
        bit -= b;
        out[i] = o >> bit;
        // keep the remaining bits
        o &= (1 << bit) - 1;
    }
}

// ToInt(b[0:l]) mod 2^m
static uint64_t ToIntMod(const uint8_t *b, uint32_t l, uint32_t m)
{
    uint64_t ret = 0;
    for (uint32_t i = 0; i < l; i++) {
        ret = (ret << BYTE_BITS) + b[i];
    }

    return ret & (~(uint64_t)0 >> (64 - m)); // mod 2^m is same to ~(uint64_t)0 >> (64 - m)
}

CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtx(void)
{
    CryptSlhDsaCtx *ctx = (CryptSlhDsaCtx *)BSL_SAL_Calloc(sizeof(CryptSlhDsaCtx), 1);
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->para.algId = CRYPT_SLH_DSA_ALG_ID_MAX;
    ctx->isPrehash = false;
    ctx->isDeterministic = false;
    return ctx;
}

CryptSlhDsaCtx *CRYPT_SLH_DSA_NewCtxEx(void *libCtx)
{
    CryptSlhDsaCtx *ctx = CRYPT_SLH_DSA_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }
    ctx->libCtx = libCtx;
    return ctx;
}

void CRYPT_SLH_DSA_FreeCtx(CryptSlhDsaCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx->context);
    BSL_SAL_ClearFree(ctx->addrand, ctx->addrandLen);
    BSL_SAL_CleanseData(ctx->prvKey.seed, sizeof(ctx->prvKey.seed));
    BSL_SAL_CleanseData(ctx->prvKey.prf, sizeof(ctx->prvKey.prf));
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_SLH_DSA_Gen(CryptSlhDsaCtx *ctx)
{
    int32_t ret;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->para.algId >= CRYPT_SLH_DSA_ALG_ID_MAX) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
        return CRYPT_SLHDSA_ERR_INVALID_ALGID;
    }
    uint32_t n = ctx->para.n;
    uint32_t d = ctx->para.d;
    uint32_t hp = ctx->para.hp;
    ret = CRYPT_RandEx(ctx->libCtx, ctx->prvKey.seed, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_RandEx(ctx->libCtx, ctx->prvKey.prf, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = CRYPT_RandEx(ctx->libCtx, ctx->prvKey.pub.seed, n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    SlhDsaAdrs adrs = {0};
    ctx->adrsOps.setLayerAddr(&adrs, d - 1);
    uint8_t node[SLH_DSA_MAX_N] = {0};
    ret = XmssNode(node, 0, hp, &adrs, ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(ctx->prvKey.pub.root, n, node, n);
    return CRYPT_SUCCESS;
}

static int32_t GetAddRand(CryptSlhDsaCtx *ctx)
{
    if (ctx->addrand != NULL) {
        // the additional rand is set.
        return CRYPT_SUCCESS;
    }
    if (!ctx->isDeterministic) {
        ctx->addrand = (uint8_t *)BSL_SAL_Malloc(ctx->para.n);
        if (ctx->addrand == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        int32_t ret = CRYPT_RandEx(ctx->libCtx, ctx->addrand, ctx->para.n);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    } else {
        // FIPS-204, Algorithm 19, line 2.
        // if is deterministic, use the public key seed as the random number.
        uint8_t *rand = (uint8_t *)BSL_SAL_Malloc(ctx->para.n);
        if (rand == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        (void)memcpy_s(rand, ctx->para.n, ctx->prvKey.pub.seed, ctx->para.n);
        ctx->addrand = rand;
    }
    ctx->addrandLen = ctx->para.n;
    return CRYPT_SUCCESS;
}

static void GetTreeAndLeafIdx(const uint8_t *digest, const CryptSlhDsaCtx *ctx, uint64_t *treeIdx, uint32_t *leafIdx)
{
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;
    uint32_t h = ctx->para.h;
    uint32_t d = ctx->para.d;

    uint32_t mdIdx = SPLIT_BYTES(k * a);
    uint32_t treeIdxLen = SPLIT_BYTES(h - h / d);
    uint32_t leafIdxLen = SPLIT_BYTES(h / d);
    *treeIdx = ToIntMod(digest + mdIdx, treeIdxLen, h - h / d);
    *leafIdx = (uint32_t)ToIntMod(digest + mdIdx + treeIdxLen, leafIdxLen, h / d);
}

static int32_t CRYPT_SLH_DSA_SignInternal(CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint8_t *sig,
                                          uint32_t *sigLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;
    uint32_t sigBytes = ctx->para.sigBytes;
    uint32_t mdIdx = SPLIT_BYTES(k * a);
    uint64_t treeIdx;
    uint32_t leafIdx;

    if (*sigLen < sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
        return CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }
    SlhDsaAdrs adrs = {0};
    uint32_t offset = 0;
    uint32_t left = *sigLen;

    ret = GetAddRand(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = ctx->hashFuncs.prfmsg(ctx, ctx->addrand, msg, msgLen, sig);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;
    uint8_t digest[SLH_DSA_MAX_M] = {0};
    ret = ctx->hashFuncs.hmsg(ctx, sig, msg, msgLen, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    GetTreeAndLeafIdx(digest, ctx, &treeIdx, &leafIdx);
    ctx->adrsOps.setTreeAddr(&adrs, treeIdx);
    ctx->adrsOps.setType(&adrs, FORS_TREE);
    ctx->adrsOps.setKeyPairAddr(&adrs, leafIdx);
    ret = ForsSign(digest, mdIdx, &adrs, ctx, sig + offset, &left);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t pk[SLH_DSA_MAX_N] = {0};
    ret = ForsPkFromSig(sig + n, left, digest, mdIdx, &adrs, ctx, pk);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += left;
    left = *sigLen - offset;
    ret = HypertreeSign(pk, n, treeIdx, leafIdx, ctx, sig + offset, &left);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    *sigLen = offset + left;
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_SLH_DSA_VerifyInternal(const CryptSlhDsaCtx *ctx, const uint8_t *msg, uint32_t msgLen,
                                            const uint8_t *sig, uint32_t sigLen)
{
    int32_t ret;
    uint32_t n = ctx->para.n;
    uint32_t a = ctx->para.a;
    uint32_t k = ctx->para.k;
    uint32_t sigBytes = ctx->para.sigBytes;
    uint32_t mdIdx = SPLIT_BYTES(k * a);
    uint64_t treeIdx;
    uint32_t leafIdx;

    if (sigLen != sigBytes) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_SIG_LEN);
        return CRYPT_SLHDSA_ERR_INVALID_SIG_LEN;
    }

    SlhDsaAdrs adrs = {0};
    uint32_t offset = 0;

    uint8_t digest[SLH_DSA_MAX_M] = {0};
    ret = ctx->hashFuncs.hmsg(ctx, sig, msg, msgLen, digest);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += n;

    GetTreeAndLeafIdx(digest, ctx, &treeIdx, &leafIdx);
    ctx->adrsOps.setTreeAddr(&adrs, treeIdx);
    ctx->adrsOps.setType(&adrs, FORS_TREE);
    ctx->adrsOps.setKeyPairAddr(&adrs, leafIdx);
    uint8_t pk[SLH_DSA_MAX_N] = {0};
    ret = ForsPkFromSig(sig + offset, (1 + a) * k * n, digest, mdIdx, &adrs, ctx, pk);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    offset += (1 + a) * k * n;
    ret = HypertreeVerify(pk, n, sig + offset, sigLen - offset, treeIdx, leafIdx, ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static uint32_t GetMdSize(const EAL_MdMethod *hashMethod, int32_t hashId)
{
    if (hashId == CRYPT_MD_SHAKE128) {
        return 32;  // To use SHAKE128, generate a 32-byte digest.
    } else if (hashId == CRYPT_MD_SHAKE256) {
        return 64;  // To use SHAKE256, generate a 64-byte digest.
    }
    return hashMethod->mdSize;
}

static int32_t MsgEncode(const CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t **mpOut, uint32_t *mpLenOut)
{
    int32_t ret;
    BslOidString *oid = NULL;
    uint32_t offset = 0;
    uint8_t prehash[MAX_DIGEST_SIZE] = {0};
    uint32_t prehashLen = sizeof(prehash);

    uint32_t mpLen = SLH_DSA_PREFIX_LEN + ctx->contextLen;
    if (ctx->isPrehash) {
        oid = BSL_OBJ_GetOidFromCID((BslCid)algId);
        if (oid == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED);
            return CRYPT_SLHDSA_ERR_PREHASH_ID_NOT_SUPPORTED;
        }
        mpLen += 2 + oid->octetLen; // asn1 header length is 2
        prehashLen = GetMdSize(EAL_MdFindMethod(algId), algId);
        const CRYPT_ConstData constData = {data, dataLen};
        ret = CalcHash(EAL_MdFindMethod(algId), &constData, 1, prehash, &prehashLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        mpLen += prehashLen;
    } else {
        mpLen += dataLen;
    }
    
    uint8_t *mp = (uint8_t *)BSL_SAL_Malloc(mpLen);
    if (mp == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    mp[0] = ctx->isPrehash ? 1 : 0;
    mp[1] = ctx->contextLen;
    (void)memcpy_s(mp + SLH_DSA_PREFIX_LEN, mpLen - SLH_DSA_PREFIX_LEN, ctx->context, ctx->contextLen);
    offset += SLH_DSA_PREFIX_LEN + ctx->contextLen;

    if (ctx->isPrehash) {
        // asn1 encoding of hash oid
        (mp + offset)[0] = BSL_ASN1_TAG_OBJECT_ID;
        (mp + offset)[1] = oid->octetLen;
        offset += 2; // asn1 header length is 2
        (void)memcpy_s(mp + offset, mpLen - offset, oid->octs, oid->octetLen);
        offset += oid->octetLen;
        (void)memcpy_s(mp + offset, mpLen - offset, prehash, prehashLen);
    } else {
        (void)memcpy_s(mp + offset, mpLen - offset, data, dataLen);
    }
    *mpOut = mp;
    *mpLenOut = mpLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_Sign(CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen, uint8_t *sign,
                           uint32_t *signLen)
{
    int32_t ret;
    uint8_t *mp = NULL;
    uint32_t mpLen = 0;

    if (ctx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ret = MsgEncode(ctx, algId, data, dataLen, &mp, &mpLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_SLH_DSA_SignInternal(ctx, mp, mpLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(mp);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BSL_SAL_Free(mp);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_Verify(const CryptSlhDsaCtx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
                             const uint8_t *sign, uint32_t signLen)
{
    (void)algId;
    int32_t ret;
    uint8_t *mp = NULL;
    uint32_t mpLen = 0;

    if (ctx == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ret = MsgEncode(ctx, algId, data, dataLen, &mp, &mpLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_SLH_DSA_VerifyInternal(ctx, mp, mpLen, sign, signLen);
    BSL_SAL_Free(mp);
    return ret;
}

static void SlhDsaSetAlgId(CryptSlhDsaCtx *ctx, CRYPT_SLH_DSA_AlgId algId)
{
    ctx->para.algId = algId;
    ctx->para.n = g_slhDsaN[algId];
    ctx->para.h = g_slhDsaH[algId];
    ctx->para.d = g_slhDsaD[algId];
    ctx->para.hp = g_slhDsaHp[algId];
    ctx->para.a = g_slhDsaA[algId];
    ctx->para.k = g_slhDsaK[algId];
    ctx->para.m = g_slhDsaM[algId];
    ctx->para.pkBytes = g_slhDsaPkBytes[algId];
    ctx->para.sigBytes = g_slhDsaSigBytes[algId];
    ctx->para.secCategory = g_secCategory[algId];
    SlhDsaInitHashFuncs(ctx);
    if (ctx->para.isCompressed) {
        ctx->adrsOps = g_adrsOps[1];
    } else {
        ctx->adrsOps = g_adrsOps[0];
    }
}

int32_t CRYPT_SLH_DSA_Ctrl(CryptSlhDsaCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
        case CRYPT_CTRL_SET_PARA_BY_ID:
            if (val == NULL || len != sizeof(CRYPT_SLH_DSA_AlgId)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            CRYPT_SLH_DSA_AlgId algId = *(CRYPT_SLH_DSA_AlgId *)val;
            if (algId >= CRYPT_SLH_DSA_ALG_ID_MAX) {
                BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_ALGID);
                return CRYPT_SLHDSA_ERR_INVALID_ALGID;
            }
            SlhDsaSetAlgId(ctx, algId);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_PREHASH_FLAG:
            if (val == NULL || len != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->isPrehash = (*(int32_t *)val != 0);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_CTX_INFO:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            if (len > 255) {
                BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW);
                return CRYPT_SLHDSA_ERR_CONTEXT_LEN_OVERFLOW;
            }
            ctx->contextLen = len;
            BSL_SAL_Free(ctx->context);
            ctx->context = (uint8_t *)BSL_SAL_Malloc(len);
            if (ctx->context == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            (void)memcpy_s(ctx->context, len, val, len);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_SLH_DSA_KEY_LEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.n;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_DETERMINISTIC_FLAG:
            if (val == NULL || len != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->isDeterministic = (*(int32_t *)val != 0);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_SET_SLH_DSA_ADDRAND:
            if (val == NULL || len != ctx->para.n) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            if (ctx->addrand != NULL) {
                BSL_SAL_Free(ctx->addrand);
            }
            uint8_t *rand = (uint8_t *)BSL_SAL_Malloc(len);
            if (rand == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            (void)memcpy_s(rand, len, val, len);
            ctx->addrand = rand;
            ctx->addrandLen = len;
            return CRYPT_SUCCESS;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static int32_t PubKeyParamCheck(const CryptSlhDsaCtx *ctx, BSL_Param *para, SlhDsaPubKeyParam *pub)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    pub->pubSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_SEED);
    pub->pubRoot = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_ROOT);
    if (pub->pubSeed == NULL || pub->pubSeed->value == NULL || pub->pubRoot == NULL || pub->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (pub->pubSeed->valueLen != ctx->para.n || pub->pubRoot->valueLen != ctx->para.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
        return CRYPT_SLHDSA_ERR_INVALID_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

static int32_t PrvKeyParamCheck(const CryptSlhDsaCtx *ctx, BSL_Param *para, SlhDsaPrvKeyParam *prv)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    prv->prvSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PRV_SEED);
    prv->prvPrf = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PRV_PRF);
    prv->pubSeed = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_SEED);
    prv->pubRoot = BSL_PARAM_FindParam(para, CRYPT_PARAM_SLH_DSA_PUB_ROOT);
    if (prv->prvSeed == NULL || prv->prvSeed->value == NULL || prv->prvPrf == NULL || prv->prvPrf->value == NULL ||
        prv->pubSeed == NULL || prv->pubSeed->value == NULL || prv->pubRoot == NULL || prv->pubRoot->value == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (prv->prvSeed->valueLen != ctx->para.n || prv->prvPrf->valueLen != ctx->para.n ||
        prv->pubSeed->valueLen != ctx->para.n || prv->pubRoot->valueLen != ctx->para.n) {
        BSL_ERR_PUSH_ERROR(CRYPT_SLHDSA_ERR_INVALID_KEYLEN);
        return CRYPT_SLHDSA_ERR_INVALID_KEYLEN;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_GetPubKey(const CryptSlhDsaCtx *ctx, BSL_Param *para)
{
    SlhDsaPubKeyParam pub;
    int32_t ret = PubKeyParamCheck(ctx, para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    pub.pubSeed->useLen = pub.pubRoot->useLen = ctx->para.n;
    (void)memcpy_s(pub.pubSeed->value, pub.pubSeed->valueLen, ctx->prvKey.pub.seed, ctx->para.n);
    (void)memcpy_s(pub.pubRoot->value, pub.pubRoot->valueLen, ctx->prvKey.pub.root, ctx->para.n);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_GetPrvKey(const CryptSlhDsaCtx *ctx, BSL_Param *para)
{
    SlhDsaPrvKeyParam prv;
    int32_t ret = PrvKeyParamCheck(ctx, para, &prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    prv.prvSeed->useLen = ctx->para.n;
    prv.prvPrf->useLen = ctx->para.n;
    prv.pubSeed->useLen = ctx->para.n;
    prv.pubRoot->useLen = ctx->para.n;
    (void)memcpy_s(prv.prvSeed->value, prv.prvSeed->valueLen, ctx->prvKey.seed, ctx->para.n);
    (void)memcpy_s(prv.prvPrf->value, prv.prvPrf->valueLen, ctx->prvKey.prf, ctx->para.n);
    (void)memcpy_s(prv.pubSeed->value, prv.pubSeed->valueLen, ctx->prvKey.pub.seed, ctx->para.n);
    (void)memcpy_s(prv.pubRoot->value, prv.pubRoot->valueLen, ctx->prvKey.pub.root, ctx->para.n);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_SetPubKey(CryptSlhDsaCtx *ctx, const BSL_Param *para)
{
    SlhDsaPubKeyParam pub;
    int32_t ret = PubKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(ctx->prvKey.pub.seed, ctx->para.n, pub.pubSeed->value, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.pub.root, ctx->para.n, pub.pubRoot->value, ctx->para.n);

    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_SetPrvKey(CryptSlhDsaCtx *ctx, const BSL_Param *para)
{
    SlhDsaPrvKeyParam prv;
    int32_t ret = PrvKeyParamCheck(ctx, (BSL_Param *)(uintptr_t)para, &prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    (void)memcpy_s(ctx->prvKey.seed, sizeof(ctx->prvKey.seed), prv.prvSeed->value, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.prf, sizeof(ctx->prvKey.prf), prv.prvPrf->value, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.pub.seed, sizeof(ctx->prvKey.pub.seed), prv.pubSeed->value, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.pub.root, sizeof(ctx->prvKey.pub.root), prv.pubRoot->value, ctx->para.n);

    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_SLH_DSA