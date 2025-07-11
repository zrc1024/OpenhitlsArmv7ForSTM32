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

#ifndef CRYPT_ECDSA_H
#define CRYPT_ECDSA_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ECDSA

#include <stdint.h>
#include "crypt_types.h"
#include "crypt_local_types.h"
#include "crypt_ecc_pkey.h"
#include "crypt_ecc.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

/* ECDSA key context */
typedef struct ECC_PkeyCtx CRYPT_ECDSA_Ctx;

/* ECDSA parameter structure */
typedef struct EccPara CRYPT_EcdsaPara;

/**
 * @ingroup ecdsa
 * @brief ecdsa Allocate context memory space.
 *
 * @retval (CRYPT_ECDSA_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL                Invalid null pointer
 */
CRYPT_ECDSA_Ctx *CRYPT_ECDSA_NewCtx(void);

/**
 * @ingroup ecdsa
 * @brief ecdsa Allocate context memory space.
 * 
 * @param libCtx [IN] Library context
 *
 * @retval (CRYPT_ECDSA_Ctx *) Pointer to the memory space of the allocated context
 * @retval NULL                Invalid null pointer
 */
CRYPT_ECDSA_Ctx *CRYPT_ECDSA_NewCtxEx(void *libCtx);

/**
 * @ingroup ecdsa
 * @brief Copy the ECDSA context. After the duplication is complete, call the CRYPT_ECDSA_FreeCtx to release the memory.
 *
 * @param ctx [IN] Source ECDSA context
 *
 * @return CRYPT_ECDSA_Ctx ECDSA context pointer
 * If it fails, null is returned.
 */
CRYPT_ECDSA_Ctx *CRYPT_ECDSA_DupCtx(CRYPT_ECDSA_Ctx *ctx);

/**
 * @ingroup ecdsa
 * @brief ecdsa Releasing the key context structure
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_ECDSA_FreeCtx(CRYPT_ECDSA_Ctx *ctx);

/**
 * @ingroup ecdsa
 * @brief ecdsa Generate the key parameter structure
 *
 * @param id [IN] Curve ID Parameter ID, which can be selected CRYPT_ECC_NISTP224 to CRYPT_ECC_NISTP521 only
 *                from CRYPT_PKEY_ParaId.
 *
 * @retval (CRYPT_EcdsaPara *) Pointer to the memory space of the allocated context
 * @retval NULL                Invalid null pointer
 */
CRYPT_EcdsaPara *CRYPT_ECDSA_NewParaById(int32_t id);

/**
 * @ingroup ecdsa
 * @brief ecdsa Generate the key parameter structure
 *
 * @param eccPara [IN] Curve parameter information, which can be selected CRYPT_ECC_NISTP224 to CRYPT_ECC_NISTP521 only
 *                     from CRYPT_PKEY_ParaId.
 *
 * @retval (CRYPT_EcdsaPara *) Pointer to the memory space of the allocated context
 * @retval NULL Invalid null pointer
 */
CRYPT_EcdsaPara *CRYPT_ECDSA_NewPara(const BSL_Param *eccPara);

/**
 * @ingroup ecdsa
 * @brief Obtain the parameter ID.
 *
 * @param ctx [IN] ECDSA context
 *
 * @retval ID. If the context is invalid, CRYPT_PKEY_PARAID_MAX is returned.
 */
CRYPT_PKEY_ParaId CRYPT_ECDSA_GetParaId(const CRYPT_ECDSA_Ctx *ctx);

/**
 * @ingroup ecdsa
 * @brief ecdsa Release the key parameter structure
 *
 * @param para [IN] Pointer to the key parameter structure to be released. The parameter is set NULL by the invoker.
 */
void CRYPT_ECDSA_FreePara(CRYPT_EcdsaPara *para);

/**
 * @ingroup ecdsa
 * @brief Set the data of the key parameter structure to the key structure.
 *
 * @param ctx [OUT] Key structure for which related parameters need to be set
 * @param para [IN] Key parameters
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Internal memory allocation error
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t CRYPT_ECDSA_SetPara(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *param);

/**
 * @ingroup ecdsa
 * @brief Obtain the key parameter structure.
 *
 * @param ctx [IN] Key structure for which related parameters need to be get
 * @param para [OUT] Key parameters
 *
 * @retval CRYPT_NULL_INPUT     Invalid null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Internal memory allocation error
 * @retval CRYPT_SUCCESS        Get parameters successfully.
 */
int32_t CRYPT_ECDSA_GetPara(const CRYPT_ECDSA_Ctx *ctx, BSL_Param *param);

/**
 * @ingroup ecdsa
 * @brief ecdsa Obtain the key length.
 *
 * @param ctx [IN] ecdsa context structure
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not contain valid key length.
 * @retval uint32_t Valid key length
 */
uint32_t CRYPT_ECDSA_GetBits(const CRYPT_ECDSA_Ctx *ctx);

/**
 * @ingroup ecdsa
 * @brief ecdsa Obtains the length required for signing.
 *
 * @param ctx [IN] ecdsa context structure
 *
 * @retval 0        The input is incorrect or the corresponding key structure does not contain valid parameter data.
 * @retval uint32_t Length required for valid signature data
 */
uint32_t CRYPT_ECDSA_GetSignLen(const CRYPT_ECDSA_Ctx *ctx);

/**
 * @ingroup ecdsa
 * @brief Generate the ECDSA key pair.
 *
 * @param ctx [IN/OUT] ecdsa context structure
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error code.      An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        The key pair is successfully generated.
 */
int32_t CRYPT_ECDSA_Gen(CRYPT_ECDSA_Ctx *ctx);

/**
 * @ingroup ecdsa
 * @brief ECDSA Signature
 *
 * @param ctx [IN] ecdsa context structure
 * @param algId [IN] md algId
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [OUT] Signature data
 * @param signLen [IN/OUT] The input parameter is the space length of the sign,
 *                         and the output parameter is the valid length of the sign.
 *                         The required space can be obtained by calling CRYPT_ECDSA_GetSignLen.
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_ECDSA_ERR_EMPTY_KEY        The key cannot be empty.
 * @retval CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH  The buffer length is insufficient.
 * @retval BN error.                        An error occurs in the internal BigNum operation.
 * @retval ECC error.                       An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                    Signed successfully.
 */
int32_t CRYPT_ECDSA_Sign(const CRYPT_ECDSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup ecdsa
 * @brief ECDSA Signature
 *
 * @param ctx [IN] ecdsa context structure
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [OUT] Signature data
 * @param signLen [IN/OUT] The input parameter is the space length of the sign,
 *                         and the output parameter is the valid length of the sign.
 *                         The required space can be obtained by calling CRYPT_ECDSA_GetSignLen.
 *
 * @retval CRYPT_NULL_INPUT                 Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL             Memory allocation failure
 * @retval CRYPT_ECDSA_ERR_EMPTY_KEY        The key cannot be empty.
 * @retval CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH  The buffer length is insufficient.
 * @retval BN error.                        An error occurs in the internal BigNum operation.
 * @retval ECC error.                       An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                    Signed successfully.
 */
int32_t CRYPT_ECDSA_SignData(const CRYPT_ECDSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup ecdsa
 * @brief ECDSA Verification
 *
 * @param ctx [IN] ecdsa context structure
 * @param algId [IN] md algId
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [IN] Signature data
 * @param signLen [IN] Valid length of the sign
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_ECDSA_VERIFY_FAIL  Failed to verify the signature.
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval ECC error.               An error occurred in the internal ECC calculation.
 * @retval DSA error.               An error occurs in the DSA encoding and decoding part.
 * @retval CRYPT_SUCCESS            The signature is verified successfully.
 */
int32_t CRYPT_ECDSA_Verify(const CRYPT_ECDSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup ecdsa
 * @brief ECDSA Verification
 *
 * @param ctx [IN] ecdsa context structure
 * @param data [IN] Data to be signed
 * @param dataLen [IN] Length of the data to be signed
 * @param sign [IN] Signature data
 * @param signLen [IN] Valid length of the sign
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_ECDSA_VERIFY_FAIL  Failed to verify the signature.
 * @retval BN error.                An error occurs in the internal BigNum operation.
 * @retval ECC error.               An error occurred in the internal ECC calculation.
 * @retval DSA error.               An error occurs in the DSA encoding and decoding part.
 * @retval CRYPT_SUCCESS            The signature is verified successfully.
 */
int32_t CRYPT_ECDSA_VerifyData(const CRYPT_ECDSA_Ctx *ctx, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen);

/**
 * @ingroup ecdsa
 * @brief ECDSA Set the private key data.
 *
 * @param ctx [OUT] ecdsa context structure
 * @param para [IN] External private key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t CRYPT_ECDSA_SetPrvKey(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup ecdsa
 * @brief ECDSA Set the public key data.
 *
 * @param ctx [OUT] ecdsa context structure
 * @param para [IN] External public key data
 *
 * @retval CRYPT_NULL_INPUT     Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL Memory allocation failure
 * @retval ECC error.           An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS        Set successfully.
 */
int32_t CRYPT_ECDSA_SetPubKey(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *para);

/**
 * @ingroup ecdsa
 * @brief ECDSA Obtain the private key data.
 *
 * @param ctx [IN] ecdsa context structure
 * @param para [OUT] External private key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t CRYPT_ECDSA_GetPrvKey(const CRYPT_ECDSA_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup ecdsa
 * @brief ECDSA Obtain the public key data.
 *
 * @param ctx [IN] ecdsa context structure
 * @param para [OUT] External public key data
 *
 * @retval CRYPT_NULL_INPUT             Invalid null pointer input
 * @retval CRYPT_ECC_PKEY_ERR_EMPTY_KEY The key is empty.
 * @retval ECC error.                   An error occurred in the internal ECC calculation.
 * @retval CRYPT_SUCCESS                Obtained successfully.
 */
int32_t CRYPT_ECDSA_GetPubKey(const CRYPT_ECDSA_Ctx *ctx, BSL_Param *para);

/**
 * @ingroup ecdsa
 * @brief ecdsa control interface
 *
 * @param ctx [IN/OUT] ecdsa context structure
 * @param opt [IN] Operation mode. For details, see ECC_CtrlType.
 * @param val [IN] Input parameter
 * @param len [IN] val length
 *
 * @retval CRYPT_SUCCESS                            Set successfully.
 * @retval CRYPT_NULL_INPUT                         If any input parameter is empty
 * @retval CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT  Invalid point format
 * @retval CRYPT_ECC_PKEY_ERR_CTRL_LEN              The length of len is incorrect.
 * @retval CRYPT_ECDSA_ERR_UNSUPPORTED_CTRL_OPTION  The opt mode is not supported.
 */
int32_t CRYPT_ECDSA_Ctrl(CRYPT_ECDSA_Ctx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup ecdsa
 * @brief ecdsa Compare public keys and parameters
 *
 * @param a [IN] ecdsa Context structure
 * @param b [IN] ecdsa context structure
 *
 * @retval CRYPT_SUCCESS is the same
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_ECDSA_Cmp(const CRYPT_ECDSA_Ctx *a, const CRYPT_ECDSA_Ctx *b);

/**
 * @ingroup ecdsa
 * @brief ecdsa get security bits
 *
 * @param ctx [IN] ecdsa Context structure
 *
 * @retval security bits
 */
int32_t CRYPT_ECDSA_GetSecBits(const CRYPT_ECDSA_Ctx *ctx);

#ifdef HITLS_CRYPTO_PROVIDER
/**
 * @ingroup ecdsa
 * @brief ecdsa import key
 *
 * @param ctx [IN/OUT] ecdsa context structure
 * @param params [IN] parameters
 */
int32_t CRYPT_ECDSA_Import(CRYPT_ECDSA_Ctx *ctx, const BSL_Param *params);

/**
 * @ingroup ecdsa
 * @brief ecdsa export key
 *
 * @param ctx [IN] ecdsa context structure
 * @param params [IN/OUT] key parameters
 */
int32_t CRYPT_ECDSA_Export(const CRYPT_ECDSA_Ctx *ctx, BSL_Param *params);

#endif // HITLS_CRYPTO_PROVIDER
#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ECDSA

#endif // CRYPT_ECDSA_H
