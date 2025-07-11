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
#ifdef HITLS_CRYPTO_SM4

#include "bsl_err_internal.h"
#include "crypt_sm4.h"
#include "modes_local.h"

/**
 * @brief Set the encryption key.
 *
 * @param ctx [IN] Mode handle
 * @param key [IN] Encrypt key
 * @param len [IN] Encrypt key length. Only 16 bytes (128 bits) are supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_SetEncryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len)
{
    return MODES_SetEncryptKey(ctx, key, len);
}

/**
 * @brief Set the decryption key.
 *
 * @param ctx [IN] Mode handle
 * @param key [IN] Decrypt key
 * @param len [IN] Decrypt key length. Only 16 bytes (128 bits) are supported.
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t MODES_SM4_SetDecryptKey(MODES_CipherCommonCtx *ctx, const uint8_t *key, uint32_t len)
{
    return MODES_SetDecryptKey(ctx, key, len);
}

#endif // HITLS_CRYPTO_SM4
