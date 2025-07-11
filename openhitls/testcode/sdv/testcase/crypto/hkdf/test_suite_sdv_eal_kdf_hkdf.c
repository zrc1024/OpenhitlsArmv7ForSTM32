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

#include "securec.h"
#include "crypt_eal_kdf.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
/* END_HEADER */

#define DATA_LEN (64)


static uint32_t GetMaxKeyLen(int algId)
{
    switch (algId) {
        case CRYPT_MAC_HMAC_SHA1:
            return 5100;
        case CRYPT_MAC_HMAC_SHA224:
            return 7140;
        case CRYPT_MAC_HMAC_SHA256:
            return 8160;
        case CRYPT_MAC_HMAC_SHA384:
            return 12240;
        case CRYPT_MAC_HMAC_SHA512:
            return 16320;
        default:
            return 0;
    }
}

/**
 * @test   SDV_CRYPT_EAL_KDF_HKDF_API_TC001
 * @title  hkdf api test.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_HKDF_API_TC001(int algId)
{
    TestMemInit();
    uint32_t keyLen = DATA_LEN;
    uint8_t key[DATA_LEN];
    uint32_t saltLen = DATA_LEN;
    uint8_t salt[DATA_LEN];
    uint32_t infoLen = DATA_LEN;
    uint8_t info[DATA_LEN];
    uint32_t outLen = DATA_LEN;
    uint8_t out[DATA_LEN];

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[7] = {{0}, {0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt, saltLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info, infoLen), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS,
        key, keyLen), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(BSL_PARAM_InitValue(&params[5], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS,
        NULL, 0), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, NULL), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, NULL, outLen), CRYPT_NULL_INPUT);
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, 0), CRYPT_NULL_INPUT);

    outLen = GetMaxKeyLen(algId) + 1;
    ASSERT_EQ(CRYPT_EAL_KdfDerive(ctx, out, outLen), CRYPT_HKDF_DKLEN_OVERFLOW);
    outLen = DATA_LEN;

    CRYPT_MAC_AlgId macAlgIdFailed = CRYPT_MAC_MAX;
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &macAlgIdFailed, sizeof(macAlgIdFailed)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_KdfSetParam(ctx, params), CRYPT_HKDF_PARAM_ERROR);

    ASSERT_EQ(CRYPT_EAL_KdfDeInitCtx(ctx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_KdfCtrl(ctx, 0, NULL, 0), CRYPT_NULL_INPUT);
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
}
/* END_CASE */

/**
 * @test   SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001
 * @title  Perform the vector test to check whether the calculation result is consistent with the standard output.
 * @precon nan
 * @brief
 *    1.Call CRYPT_EAL_KdfCTX functions get output, expected result 1.
*     2.Compare the result to the expected value, expected result 2.
 * @expect
 *    1.Successful.
 *    2.The results are as expected.
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001(int algId, Hex *key, Hex *salt, Hex *info, Hex *result)
{
    if (IsHmacAlgDisabled(algId)) {
        SKIP_TEST();
    }
    TestMemInit();
    uint32_t outLen = result->len;
    uint8_t *out = malloc(outLen * sizeof(uint8_t));
    ASSERT_TRUE(out != NULL);

    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
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
 * @test   SDV_CRYPTO_HKDF_DEFAULT_PROVIDER_FUNC_TC001
 * @title  Default provider testing
 * @precon nan
 * @brief
 * Load the default provider and use the test vector to test its correctness
 */
/* BEGIN_CASE */
void SDV_CRYPTO_HKDF_DEFAULT_PROVIDER_FUNC_TC001(int algId, Hex *key, Hex *salt, Hex *info, Hex *result)
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
    ctx = CRYPT_EAL_ProviderKdfNewCtx(NULL, CRYPT_KDF_HKDF, "provider=default");
#else
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
#endif
    ASSERT_TRUE(ctx != NULL);

    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
    ASSERT_EQ(BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
        &algId, sizeof(algId)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32,
        &mode, sizeof(mode)), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS,
        key->x, key->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS,
        salt->x, salt->len), CRYPT_SUCCESS);
    ASSERT_EQ(BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS,
        info->x, info->len), CRYPT_SUCCESS);
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
