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

#ifndef EAL_CIPHER_LOCAL_H
#define EAL_CIPHER_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_CIPHER)

#include "crypt_algid.h"
#include "crypt_eal_cipher.h"
#include "crypt_local_types.h"
#ifdef HITLS_CRYPTO_GCM
#include "crypt_modes_gcm.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @ingroup  crypt_cipherstates
 * Symmetry encryption/decryption status */
typedef enum {
    EAL_CIPHER_STATE_NEW,
    EAL_CIPHER_STATE_INIT,
    EAL_CIPHER_STATE_UPDATE,
    EAL_CIPHER_STATE_FINAL
} EAL_CipherStates;

/**
 * @ingroup  alg map
 * Symmetric encryption/decryption mode and ID of the encryption algorithm.
 */
typedef struct {
    uint32_t id;
    CRYPT_MODE_AlgId modeId;
} EAL_SymAlgMap;

/**
* @ingroup  EAL
*
* CRYPT_CipherInfo: User search algorithm information. Currently, only blockSize is available.
*/
typedef struct {
    CRYPT_CIPHER_AlgId id;
    uint8_t blockSize;
    uint32_t keyLen;
    uint32_t ivLen;
} CRYPT_CipherInfo;

/**
 * @ingroup  crypt_eal_cipherctx
 * Asymmetric algorithm data type */
struct CryptEalCipherCtx {
#ifdef HITLS_CRYPTO_PROVIDER
    bool isProvider;
#endif
    CRYPT_CIPHER_AlgId id;
    EAL_CipherStates states;                        /**< record status */
    void *ctx;                                      /**< handle of the mode */
    EAL_CipherUnitaryMethod *method;          /**< method corresponding to the encryption/decryption mode */
};

const EAL_SymMethod *EAL_GetSymMethod(int32_t algId);

/**
 * @brief Obtain the EAL_CipherMethod based on the algorithm ID.
 *
 * @param id [IN]     Symmetric encryption/decryption algorithm ID.
 * @param modeMethod  [IN/OUT] EAL_CipherMethod Pointer
 * @return If it's successful, the system returns CRYPT_SUCCESS and assigns the value to the method in m.
 * If it's failed, returns CRYPT_EAL_ERR_ALGID: ID of the unsupported algorithm.
 */
int32_t EAL_FindCipher(CRYPT_CIPHER_AlgId id, const EAL_CipherMethod **modeMethod);

/**
 * @brief Obtain keyLen/ivLen/blockSize based on the algorithm ID.
 *
 * @param id [IN] Symmetric algorithm ID.
 * @param id [OUT] Assign the obtained keyLen/ivLen/blockSize to the variable corresponding to info.
 *
 * @return Success: CRYPT_SUCCESS
 *         Failure: CRYPT_ERR_ALGID
 */
int32_t EAL_GetCipherInfo(CRYPT_CIPHER_AlgId id, CRYPT_CipherInfo *info);

/**
 * @brief Obtain mode method based on the algorithm ID
 *
 * @param id [IN] Symmetric encryption/decryption algorithm ID.
 * @return If the operation is successful, the combination of ciphers is returned.
 * If the operation fails, NULL is returned.
 */
const EAL_CipherMethod *EAL_FindModeMethod(CRYPT_MODE_AlgId id);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_CIPHER

#endif // EAL_CIPHER_LOCAL_H
