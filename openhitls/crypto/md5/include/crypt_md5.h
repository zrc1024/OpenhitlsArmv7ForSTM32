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

#ifndef CRYPT_MD5_H
#define CRYPT_MD5_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_MD5

#include <stdlib.h>
#include <stdint.h>
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPT_MD5_DIGESTSIZE 16
#define CRYPT_MD5_BLOCKSIZE  64

typedef struct CryptMdCtx CRYPT_MD5_Ctx;
/**
 * @ingroup MD5
 * @brief Generate md context.
 *
 * @retval Success: cipher ctx.
 *         Fails: NULL.
 */
CRYPT_MD5_Ctx *CRYPT_MD5_NewCtx(void);

/**
 * @ingroup MD5
 * @brief free md context.
 *
 * @param ctx [IN] md handle
 */
void CRYPT_MD5_FreeCtx(CRYPT_MD5_Ctx *ctx);
/**
 * @ingroup MD5
 * @brief This API is used to initialize the MD5 context.
 *
 * @param ctx [in,out] Pointer to the MD5 context.
 * @param param [in] Pointer to the parameter.
 *
 * @retval #CRYPT_SUCCESS       Initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 */
int32_t CRYPT_MD5_Init(CRYPT_MD5_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup MD5
 * @brief MD5 deinitialization API
 * @param ctx [in,out]   Pointer to the MD5 context.
 */
void CRYPT_MD5_Deinit(CRYPT_MD5_Ctx *ctx);

/**
 * @ingroup MD5
 * @brief Encode the input text and update the message digest.
 *
 * @param ctx [in,out] Pointer to the MD5 context.
 * @param in  [in] Pointer to the data to be calculated
 * @param len [in] Length of the data to be calculated
 *
 * @retval #CRYPT_SUCCESS               Succeeded in updating the internal status of the digest.
 * @retval #CRYPT_NULL_INPUT            The input parameter is NULL.
 * @retval #CRYPT_MD5_INPUT_OVERFLOW    The accumulated length of the input data exceeds the maximum (2^64 bits).
 */
int32_t CRYPT_MD5_Update(CRYPT_MD5_Ctx *ctx, const uint8_t *in, uint32_t len);

/**
 * @ingroup MD5
 * @brief Obtain the message digest based on the passed MD5 context.
 *
 * @param ctx    [in,out] Pointer to the MD5 context.
 * @param out    [in] Digest buffer
 * @param outLen [in,out] Digest buffer size
 *
 * @retval #CRYPT_SUCCESS                       succeeded in updating the internal status of the digest.
 * @retval #CRYPT_NULL_INPUT                    The input parameter is NULL.
 * @retval #CRYPT_MD5_OUT_BUFF_LEN_NOT_ENOUGH   The output buffer length is insufficient.
 */
int32_t CRYPT_MD5_Final(CRYPT_MD5_Ctx *ctx, uint8_t *out, uint32_t *outLen);

/**
 * @ingroup MD5
 * @brief MD5 copy CTX function
 * @param dst [out]  Pointer to the new MD5 context.
 * @param src [in]   Pointer to the original MD5 context.
 */
int32_t CRYPT_MD5_CopyCtx(CRYPT_MD5_Ctx *dst, const CRYPT_MD5_Ctx *src);

/**
 * @ingroup MD5
 * @brief MD5 dup CTX function
 * @param src [in]   Pointer to the original MD5 context.
 */
CRYPT_MD5_Ctx *CRYPT_MD5_DupCtx(const CRYPT_MD5_Ctx *src);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_MD5

#endif // CRYPT_MD5_H
