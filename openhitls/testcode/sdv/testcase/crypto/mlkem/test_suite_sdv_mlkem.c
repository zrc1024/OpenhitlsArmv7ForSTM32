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

/* BEGIN_HEADER */
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_util_rand.h"
#include "eal_pkey_local.h"
#include "securec.h"
/* END_HEADER */

static uint8_t gKyberRandBuf[3][32] = { 0 };
uint32_t gKyberRandNum = 0;
static int32_t TEST_KyberRandom(uint8_t *randNum, uint32_t randLen)
{
    memcpy_s(randNum, randLen, gKyberRandBuf[gKyberRandNum], 32);
    gKyberRandNum++;
    return 0;
}

static int32_t TEST_KyberRandomEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    return TEST_KyberRandom(randNum, randLen);
}

/* @
* @test  SDV_CRYPTO_MLKEM_CTRL_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyCtrl test
* @precon  nan
* @brief  1. creat context
* 2.invoke CRYPT_EAL_PkeyCtrl to transfer various exception parameters.
* 3.call CRYPT_EAL_PkeyCtrl repeatedly to set the key information.
* @expect  1.success 2.returned as expected 3.cannot be set repeatedly.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_CTRL_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID + 100, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_MLKEM_CTRL_NOT_SUPPORT);

    ret = CRYPT_EAL_PkeyCtrl(NULL, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, NULL, sizeof(val));
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val) - 1);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
    ASSERT_EQ(ret, CRYPT_MLKEM_CTRL_INIT_REPEATED);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_KEYGEN_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyGen test
* @precon  nan
* @brief  1.register a random number and create a context.
* 2.invoke CRYPT_EAL_PkeyGen and transfer various parameters.
* 3.check the return value.
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_KEYGEN_API_TC001(int bits)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
        ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
        ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    int32_t ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_MLKEM_KEYINFO_NOT_SET);

    uint32_t val = (uint32_t)bits;
    ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_NO_REGIST_RAND);

    CRYPT_RandRegist(TestSimpleRand);
    CRYPT_RandRegistEx(TestSimpleRandEx);
    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* Use default random numbers for end-to-end testing */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_KEYGEN_API_TC002(int bits)
{
    TestMemInit();
    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_ENCAPS_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyEncaps test
* @precon  nan
* @brief  1.register a random number and generate a context and key pair.
* 2.call CRYPT_EAL_PkeyEncaps to transfer abnormal values.
* 3. check the return value.
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_ENCAPS_API_TC001(int bits)
{
    TestMemInit();

    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(NULL, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, NULL, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, NULL, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, NULL, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MLKEM_LEN_NOT_ENOUGH);
    cipherLen = cipherLen + 1;

    sharedLen = sharedLen - 1;
    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MLKEM_LEN_NOT_ENOUGH);
    sharedLen = sharedLen + 1;

    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_DECAPS_API_TC001
* @spec  -
* @title  CRYPT_EAL_PkeyEncaps test
* @precon  nan
* @brief  1.register a random number and generate a context and key pair.
* 2.call CRYPT_EAL_PkeyDecaps to transfer various abnormal values.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_DECAPS_API_TC001(int bits)
{
    TestMemInit();

    TestRandInit();
    CRYPT_EAL_PkeyCtx *ctx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE, "provider=default");
#else
    ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
#endif
    ASSERT_TRUE(ctx != NULL);

    uint32_t val = (uint32_t)bits;
    int32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    ret = CRYPT_EAL_PkeyGen(ctx);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    ret = CRYPT_EAL_PkeyDecaps(NULL, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, NULL, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, NULL, &sharedLen);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    cipherLen = cipherLen - 1;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MLKEM_LEN_NOT_ENOUGH);
    cipherLen = cipherLen + 1;

    sharedLen = sharedLen - 1;
    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_MLKEM_LEN_NOT_ENOUGH);
    sharedLen = sharedLen + 1;

    ret = CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, sharedKey, &sharedLen);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    TestRandDeInit();
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_SETPUB_API_TC002
* @spec  -
* @title  CRYPT_EAL_PkeySetPub and CRYPT_EAL_PkeyGetPub
* @precon  nan
* @brief 1.register a random number and create a context.
* 2.call CRYPT_EAL_PkeySetPub and CRYPT_EAL_PkeyGetPub and transfer various parameters.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_SETPUB_API_TC002(int bits, Hex *testEK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_EAL_ERR_ALGID);

    ek.id = CRYPT_PKEY_ML_KEM;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_NULL_INPUT);

    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
    (void)memcpy_s(ek.key.kemEk.data, encapsKeyLen, testEK->x, testEK->len);
    ek.key.kemEk.len = encapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_MLKEM_KEYLEN_ERROR);

    ek.key.kemEk.len = encapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_MLKEM_KEY_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_SUCCESS);
    (void)memset_s(ek.key.kemEk.data, encapsKeyLen, 0, encapsKeyLen);

    ek.key.kemEk.len = encapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_MLKEM_KEYLEN_ERROR);
    ek.key.kemEk.len = encapsKeyLen + 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ek", ek.key.kemEk.data, ek.key.kemEk.len, testEK->x, testEK->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(ek.key.kemEk.data);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_SETPRV_API_TC002
* @spec  -
* @title  CRYPT_EAL_PkeySetPrv and CRYPT_EAL_PkeyGetPrv
* @precon  nan
* @brief 1.register a random number and create a context.
* 2.call CRYPT_EAL_PkeySetPrv and CRYPT_EAL_PkeyGetPrv and transfer various parameters.
* 3.check return value
* @expect  1.success 2.success 3.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_SETPRV_API_TC002(int bits, Hex *testDK)
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_EAL_ERR_ALGID);

    dk.id = CRYPT_PKEY_ML_KEM;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_NULL_INPUT);

    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    (void)memcpy_s(dk.key.kemDk.data, decapsKeyLen, testDK->x, testDK->len);
    dk.key.kemDk.len = decapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_MLKEM_KEYLEN_ERROR);

    dk.key.kemDk.len = decapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_MLKEM_KEY_NOT_SET);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    (void)memset_s(dk.key.kemDk.data, decapsKeyLen, 0, decapsKeyLen);

    dk.key.kemDk.len = decapsKeyLen - 1;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_MLKEM_KEYLEN_ERROR);
    dk.key.kemDk.len = decapsKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare de", dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    BSL_SAL_Free(dk.key.kemDk.data);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_MLKEM_KEYCMP_FUNC_TC001
* @spec  -
* @title  Context Comparison and Copy Test
* @precon  nan
* @brief  1.Registers a random number that returns the specified value.
* 2. Call CRYPT_EAL_PkeyGen to generate a key pair. The first two groups of random numbers are the same,
*    and the third group of random numbers is different.
* 3. Call CRYPT_EAL_PkeyCopyCtx to copy the key pair.
* 4. Invoke CRYPT_EAL_PkeyCmp to compare key pairs.
* @expect  1.success 2.success 3.success 4.the returned value is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_KEYCMP_FUNC_TC001(int bits, Hex *r0, Hex *r1, Hex *r2, int isProvider)
{
    TestMemInit();
    gKyberRandNum = 0;
    memcpy_s(gKyberRandBuf[0], 32, r0->x, r0->len);
    memcpy_s(gKyberRandBuf[1], 32, r1->x, r1->len);
    memcpy_s(gKyberRandBuf[2], 32, r2->x, r2->len);
    CRYPT_RandRegist(TEST_KyberRandom);
    CRYPT_RandRegistEx(TEST_KyberRandomEx);

    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=default", isProvider);
    ASSERT_NE(ctx, NULL);
    uint32_t val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, NULL), CRYPT_NULL_INPUT);
    gKyberRandNum = 0;

    CRYPT_EAL_PkeyCtx *ctx2 = TestPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=default", isProvider);
    ASSERT_NE(ctx2, NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_MLKEM_KEY_NOT_EQUAL);
    val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx2, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_MLKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx2, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_MLKEM_KEY_NOT_EQUAL);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx2), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx2), CRYPT_SUCCESS);

    gKyberRandNum = 1;
    CRYPT_EAL_PkeyCtx *ctx3 = TestPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=default", isProvider);
    ASSERT_NE(ctx3, NULL);
    val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx3, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx3, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx3), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx3), CRYPT_MLKEM_KEY_NOT_EQUAL);

    CRYPT_EAL_PkeyCtx *ctx4 = BSL_SAL_Calloc(1u, sizeof(CRYPT_EAL_PkeyCtx));
    ASSERT_EQ(CRYPT_EAL_PkeyCopyCtx(ctx4, ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx4), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyCtx *ctx5 = CRYPT_EAL_PkeyDupCtx(ctx);
    ASSERT_TRUE(ctx5 != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(ctx, ctx5), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    CRYPT_EAL_PkeyFreeCtx(ctx4);
    CRYPT_EAL_PkeyFreeCtx(ctx5);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_KEYGEN_FUNC_TC001
* @spec  -
* @title  Generating a Key Pair
* @precon  nan
* @brief  
* 1. Register a random number and return the specified random number of the test vector.
* 2. Call CRYPT_EAL_PkeyGen to generate a key pair.
* 3. Compare key pairs and test vectors.
* @expect  
* 1. success
* 2. success
* 3. the key pair is the same as the test vector.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_KEYGEN_FUNC_TC001(int bits, Hex *z, Hex *d, Hex *testEK, Hex *testDK, int isProvider)
{
    TestMemInit();
    gKyberRandNum = 0;
    memcpy_s(gKyberRandBuf[0], 32, d->x, d->len);
    memcpy_s(gKyberRandBuf[1], 32, z->x, z->len);
    CRYPT_RandRegist(TEST_KyberRandom);
    CRYPT_RandRegistEx(TEST_KyberRandomEx);

    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=default", isProvider);

    ASSERT_NE(ctx, NULL);
    uint32_t val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen)), CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen)), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = CRYPT_PKEY_ML_KEM;
    ek.key.kemEk.len = encapsKeyLen;
    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    dk.id = CRYPT_PKEY_ML_KEM;
    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);

    ASSERT_EQ(CRYPT_EAL_PkeyGen(ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ek", ek.key.kemEk.data, ek.key.kemEk.len, testEK->x, testEK->len);
    ASSERT_COMPARE("compare dk", dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);
EXIT:
    BSL_SAL_Free(ek.key.kemEk.data);
    BSL_SAL_Free(dk.key.kemDk.data);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_ENCAPS_DECAPS_FUNC_TC001
* @spec  -
* @title Vector test for generating ciphertext, shared key, and decapsulation
* @precon nan
* @brief
* 1. Register a random number and return the specified random number of the test vector.
* 2. Call CRYPT_EAL_PkeyEncaps to generate the ciphertext and shared key.
* 3. Compare the ciphertext and shared key with the test vector.
* 4. Call CRYPT_EAL_PkeyDecaps to generate a shared key.
* 5. Compare the shared key with the test vector.
* @expect 1. Success 2. Success 3. The generation result is the same as expected 4. Success
*         5. The generation result is the same as expected
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_ENCAPS_DECAPS_FUNC_TC001(int bits, Hex *m, Hex *testEK, Hex *testDK, Hex *testCT, Hex *testSK, int isProvider)
{
    TestMemInit();
    gKyberRandNum = 0;
    memcpy_s(gKyberRandBuf[0], 32, m->x, m->len);
    CRYPT_RandRegist(TEST_KyberRandom);
    CRYPT_RandRegistEx(TEST_KyberRandomEx);

    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=default", isProvider);

    ASSERT_NE(ctx, NULL);
    uint32_t val = (uint32_t)bits;
    ASSERT_EQ(CRYPT_EAL_PkeySetParaById(ctx, val), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncapsInit(ctx, NULL), CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen)), CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen)), CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen)), CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = CRYPT_PKEY_ML_KEM;
    ek.key.kemEk.len = encapsKeyLen;
    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
    (void)memcpy_s(ek.key.kemEk.data, ek.key.kemEk.len, testEK->x, testEK->len);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    dk.id = CRYPT_PKEY_ML_KEM;
    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    (void)memcpy_s(dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);

    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    uint32_t decSharedLen = 32;
    uint8_t *decSharedKey = BSL_SAL_Malloc(decSharedLen);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ct", ciphertext, cipherLen, testCT->x, testCT->len);
    ASSERT_COMPARE("compare sk", sharedKey, sharedLen, testSK->x, testSK->len);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, testCT->x, testCT->len, decSharedKey, &decSharedLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare dec sk", decSharedKey, decSharedLen, testSK->x, testSK->len);
EXIT:
    BSL_SAL_Free(ek.key.kemEk.data);
    BSL_SAL_Free(dk.key.kemDk.data);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    BSL_SAL_Free(decSharedKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_DECAPS_FUNC_TC001
* @spec  -
* @title Vector test using ciphertext and shared key decapsulation
* @precon nan
* @brief
* 1. Set the decapsulation key.
* 2. Invoke CRYPT_EAL_PkeyDecaps to generate a shared key.
* 3. Compare the shared key with the test vector.
* @expect 1. Succeeded 2. Succeeded 3. The generation result is the same as expected.
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_DECAPS_FUNC_TC001(int bits, Hex *testDK, Hex *testCT, Hex *testSK, int isProvider)
{
    TestMemInit();
    CRYPT_EAL_PkeyCtx *ctx = TestPkeyNewCtx(NULL, CRYPT_PKEY_ML_KEM, CRYPT_EAL_PKEY_KEM_OPERATE,
        "provider=default", isProvider);

    ASSERT_NE(ctx, NULL);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyDecapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    dk.id = CRYPT_PKEY_ML_KEM;
    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    (void)memcpy_s(dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);

    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, testCT->x, testCT->len, sharedKey, &sharedLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare sk", sharedKey, sharedLen, testSK->x, testSK->len);
EXIT:
    BSL_SAL_Free(dk.key.kemDk.data);
    BSL_SAL_Free(sharedKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_PKEYNEWCTX_API_TC001
* @spec  -
* @title CRYPT_EAL_PkeyNewCtx interface test
* @precon nan
* @brief 1. The input parameter is the ID of the algorithm that does not support key generation CRYPT_MD_SHA256.
* 2. The input parameter is - 1.
* 3. The input parameter is CRYPT_PKEY_MAX + 1.
* @expect 1. Failure 2. Failure 3. Failure
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_PKEYNEWCTX_API_TC001()
{
    TestMemInit();
    CRYPT_RandRegist(TestSimpleRand);

    CRYPT_EAL_PkeyCtx *ctx1 = CRYPT_EAL_PkeyNewCtx((CRYPT_PKEY_AlgId)CRYPT_MD_SHA256);
    ASSERT_TRUE(ctx1 == NULL);

    CRYPT_EAL_PkeyCtx *ctx2 = CRYPT_EAL_PkeyNewCtx(-1);
    ASSERT_TRUE(ctx2 == NULL);

    CRYPT_EAL_PkeyCtx *ctx3 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_MAX + 1);
    ASSERT_TRUE(ctx3 == NULL);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(ctx1);
    CRYPT_EAL_PkeyFreeCtx(ctx2);
    CRYPT_EAL_PkeyFreeCtx(ctx3);
    CRYPT_RandRegist(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_ABNORMAL_DECAPS_FUNC_TC001
* @spec  -
* @title Invalid ciphertext. Decapsulation failed.
* @precon nan
* @brief 1. Generate a key pair.
* 2. Call CRYPT_EAL_PkeyEncaps for encapsulation.
* 3. Modify the content in ciphertext and call CRYPT_EAL_PkeyDecaps for decapsulation.
* 4. Inconsistent sharedKeys
* @expect 1. Success 2. Success 3. Success 4. Inconsistency
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_ABNORMAL_DECAPS_FUNC_TC001(int bits, Hex *m, Hex *testEK, Hex *testDK, Hex *testCT, Hex *testSK, Hex *changeCT)
{
    TestMemInit();
    gKyberRandNum = 0;
    memcpy_s(gKyberRandBuf[0], 32, m->x, m->len);
    CRYPT_RandRegist(TEST_KyberRandom);
    CRYPT_RandRegistEx(TEST_KyberRandomEx);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
    uint32_t val = (uint32_t)bits;
    uint32_t ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = CRYPT_PKEY_ML_KEM;
    ek.key.kemEk.len = encapsKeyLen;
    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
    (void)memcpy_s(ek.key.kemEk.data, ek.key.kemEk.len, testEK->x, testEK->len);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    dk.id = CRYPT_PKEY_ML_KEM;
    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    (void)memcpy_s(dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);

    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    uint32_t decSharedLen = 32;
    uint8_t *decSharedKey = BSL_SAL_Malloc(decSharedLen);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ct", ciphertext, cipherLen, testCT->x, testCT->len);
    ASSERT_COMPARE("compare sk", sharedKey, sharedLen, testSK->x, testSK->len);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, changeCT->x, changeCT->len, decSharedKey, &decSharedLen), CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(sharedKey, decSharedKey, sharedLen) != 0);

EXIT:
    BSL_SAL_Free(ek.key.kemEk.data);
    BSL_SAL_Free(dk.key.kemDk.data);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    BSL_SAL_Free(decSharedKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_ABNORMAL_DECAPS_FUNC_TC002
* @spec  -
* @title Invalid private key. Decapsulation failed.
* @precon nan
* @brief 1. Generate a key pair.
* 2. Call CRYPT_EAL_PkeyEncaps for encapsulation.
* 3. Call SetPrvKey to set invalid prvKey to the CTX.
* 4. Call CRYPT_EAL_PkeyDecaps for decapsulation.
* 5. Inconsistent sharedKeys
* @expect 1. Success 2. Success 3. Success 4. Success 5. Inconsistency
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_ABNORMAL_DECAPS_FUNC_TC002(int bits, Hex *m, Hex *testEK, Hex *testCT, Hex *testSK, Hex *changeDK)
{
    TestMemInit();
    gKyberRandNum = 0;
    memcpy_s(gKyberRandBuf[0], 32, m->x, m->len);
    CRYPT_RandRegist(TEST_KyberRandom);
    CRYPT_RandRegistEx(TEST_KyberRandomEx);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = CRYPT_PKEY_ML_KEM;
    ek.key.kemEk.len = encapsKeyLen;
    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
    (void)memcpy_s(ek.key.kemEk.data, ek.key.kemEk.len, testEK->x, testEK->len);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    dk.id = CRYPT_PKEY_ML_KEM;
    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    (void)memcpy_s(dk.key.kemDk.data, dk.key.kemDk.len, changeDK->x, changeDK->len);

    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    uint32_t decSharedLen = 32;
    uint8_t *decSharedKey = BSL_SAL_Malloc(decSharedLen);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("compare ct", ciphertext, cipherLen, testCT->x, testCT->len);
    ASSERT_COMPARE("compare sk", sharedKey, sharedLen, testSK->x, testSK->len);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, decSharedKey, &decSharedLen), CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(sharedKey, decSharedKey, sharedLen) != 0);

EXIT:
    BSL_SAL_Free(ek.key.kemEk.data);
    BSL_SAL_Free(dk.key.kemDk.data);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    BSL_SAL_Free(decSharedKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_MLKEM_ABNORMAL_DECAPS_FUNC_TC002
* @spec  -
* @title Invalid public key. Decapsulation failed.
* @precon nan
* @brief 1. Generate a key pair.
* 2. Call CRYPT_EAL_PkeyEncaps for encapsulation.
* 3. Call SetPrvKey to set invalid prvKey to the CTX.
* 4. Call CRYPT_EAL_PkeyDecaps for decapsulation.
* 5. Inconsistent sharedKeys
* @expect 1. Success 2. Success 3. Success 4. Success 5. Failure
* @prior  nan
* @auto  FALSE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_MLKEM_ABNORMAL_DECAPS_FUNC_TC003(int bits, Hex *m, Hex *testDK, Hex *changeEK)
{
    TestMemInit();
    gKyberRandNum = 0;
    memcpy_s(gKyberRandBuf[0], 32, m->x, m->len);
    CRYPT_RandRegist(TEST_KyberRandom);
    CRYPT_RandRegistEx(TEST_KyberRandomEx);

    CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ML_KEM);
    uint32_t val = (uint32_t)bits;
    int ret = CRYPT_EAL_PkeySetParaById(ctx, val);
    ASSERT_EQ(ret, CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyEncapsInit(ctx, NULL);
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t encapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PUBKEY_LEN, &encapsKeyLen, sizeof(encapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t decapsKeyLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_PRVKEY_LEN, &decapsKeyLen, sizeof(decapsKeyLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    uint32_t cipherLen = 0;
    ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_GET_CIPHERTEXT_LEN, &cipherLen, sizeof(cipherLen));
    ASSERT_EQ(ret, CRYPT_SUCCESS);

    CRYPT_EAL_PkeyPub ek = { 0 };
    ek.id = CRYPT_PKEY_ML_KEM;
    ek.key.kemEk.len = encapsKeyLen;
    ek.key.kemEk.data =  BSL_SAL_Malloc(encapsKeyLen);
    (void)memcpy_s(ek.key.kemEk.data, ek.key.kemEk.len, changeEK->x, changeEK->len);

    CRYPT_EAL_PkeyPrv dk = { 0 };
    dk.id = CRYPT_PKEY_ML_KEM;
    dk.key.kemDk.len = decapsKeyLen;
    dk.key.kemDk.data =  BSL_SAL_Malloc(decapsKeyLen);
    (void)memcpy_s(dk.key.kemDk.data, dk.key.kemDk.len, testDK->x, testDK->len);

    uint8_t *ciphertext = BSL_SAL_Malloc(cipherLen);
    uint32_t sharedLen = 32;
    uint8_t *sharedKey = BSL_SAL_Malloc(sharedLen);

    uint32_t decSharedLen = 32;
    uint8_t *decSharedKey = BSL_SAL_Malloc(decSharedLen);

    ASSERT_EQ(CRYPT_EAL_PkeySetPub(ctx, &ek), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyEncaps(ctx, ciphertext, &cipherLen, sharedKey, &sharedLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(ctx, &dk), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyDecaps(ctx, ciphertext, cipherLen, decSharedKey, &decSharedLen), CRYPT_SUCCESS);
    ASSERT_TRUE(memcmp(sharedKey, decSharedKey, sharedLen) != 0);

EXIT:
    BSL_SAL_Free(ek.key.kemEk.data);
    BSL_SAL_Free(dk.key.kemDk.data);
    BSL_SAL_Free(ciphertext);
    BSL_SAL_Free(sharedKey);
    BSL_SAL_Free(decSharedKey);
    CRYPT_EAL_PkeyFreeCtx(ctx);
    CRYPT_RandRegist(NULL);
    CRYPT_RandRegistEx(NULL);
    return;
}
/* END_CASE */
