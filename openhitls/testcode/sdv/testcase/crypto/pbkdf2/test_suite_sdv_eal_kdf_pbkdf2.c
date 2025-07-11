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

#include <pthread.h>
#include "securec.h"
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
/* END_HEADER */

#define DATA_LEN (64)
#define ITERATION_COUNT (1024)
#define DATA_MAX_LEN (512)
#define TEST_FAIL (-1)
#define TEST_SUCCESS (0)

/**
 * @test   SDV_CRYPT_EAL_KDF_PBKDF2_API_TC001
 * @title  pbkdf2 api test.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_PBKDF2_API_TC001(void)
{
    TestMemInit();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[DATA_LEN];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[DATA_LEN];
    uint32_t it = ITERATION_COUNT; // The number of iterations cannot be less than 1024.. GM/T 0091-2020
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    ASSERT_TRUE(ctx != NULL);

    CRYPT_MAC_AlgId macAlgId = CRYPT_MAC_HMAC_SHA1;
    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt, saltLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
        &it, sizeof(it)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    uint32_t iterCntFailed = 0;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
        &iterCntFailed, sizeof(iterCntFailed)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_PBKDF2_PARAM_ERROR);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
        &it, sizeof(it)), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_PBKDF2_PARAM_ERROR);

    macAlgId = CRYPT_MAC_HMAC_MD5;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA1;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA224;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA256;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA384;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SHA512;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    macAlgId = CRYPT_MAC_HMAC_SM3;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgId, sizeof(macAlgId)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfCtrl(ctx, 0, NULL, 0), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_PBKDF2_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_KDFCTX functions get output, expected result 1.
*     2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Successful.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_PBKDF2_FUN_TC001(int algId, Hex *key, Hex *salt, int it, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    ASSERT_TRUE(ctx != NULL);

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
        &it, sizeof(it)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPTO_PBKDF2_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_PBKDF2_DEFAULT_PROVIDER_FUNC_TC001(int algId, Hex *key, Hex *salt, int it, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);
    CRYPT_EAL_KdfCTX *ctx = NULL;

#ifdef HITLS_CRYPTO_PROVIDER
    ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_PBKDF2, "provider=default");
#else
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
#endif
    ASSERT_TRUE(ctx != NULL);

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
        &it, sizeof(it)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("result cmp", out, outLen, result->x, result->len);
EXIT:
    if (out != NULL) {
        free(out);
    }
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */
