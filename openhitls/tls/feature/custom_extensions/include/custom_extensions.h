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
#ifndef CUSTOM_EXTENSIONS_H
#define CUSTOM_EXTENSIONS_H

#include "hitls_build.h"
#include "hitls.h"
#include "hitls_custom_extensions.h"

// Define CustomExt_Method structure
typedef struct {
    uint16_t extType;
    uint32_t context;
    HITLS_AddCustomExtCallback addCb;
    HITLS_FreeCustomExtCallback freeCb;
    void *addArg;
    HITLS_ParseCustomExtCallback parseCb;
    void *parseArg;
} CustomExt_Method;

// Define CustomExt_Methods structure
typedef struct CustomExt_Methods {
    CustomExt_Method *meths;
    uint32_t methsCount;
} CustomExt_Methods;


/**
 * @brief   Determines if packing custom extensions is needed for a given context.
 *
 * This function checks whether there are any custom extensions that need to be packed
 * based on the provided context. It iterates through the list of custom extension methods
 * and evaluates if any of them match the specified context.
 *
 * @param   exts    [IN] Pointer to the CustomExt_Methods structure containing extension methods
 * @param   context [IN] The context to check against the custom extensions
 * @retval  true if there are custom extensions that need to be packed for the given context
 * @retval  false otherwise
 */
bool IsPackNeedCustomExtensions(CustomExt_Methods *exts, uint32_t context);


/**
 * @brief   Determines if parsing custom extensions is needed for a given extension type and context.
 *
 * This function checks whether there are any custom extensions that need to be parsed
 * based on the provided extension type and context. It iterates through the list of custom
 * extension methods and evaluates if any of them match the specified extension type and context.
 *
 * @param   exts    [IN] Pointer to the CustomExt_Methods structure containing extension methods
 * @param   extType [IN] The extension type to check against the custom extensions
 * @param   context [IN] The context to check against the custom extensions
 * @retval  true if there are custom extensions that need to be parsed for the given extension type and context
 * @retval  false otherwise
 */
bool IsParseNeedCustomExtensions(CustomExt_Methods *exts, uint16_t extType, uint32_t context);

/**
 * @brief   Packs custom extensions into the provided buffer for a given context.
 *
 * This function iterates through the list of custom extension methods associated with the TLS context
 * and packs the relevant custom extensions into the provided buffer. It checks each extension method
 * to determine if it should be included based on the specified context. If an extension is applicable,
 * it uses the associated add callback to pack the extension data into the buffer.
 *
 * @param   ctx     [IN]  Pointer to the TLS context containing custom extension methods
 * @param   buf     [OUT] Buffer where the packed custom extensions will be stored
 * @param   bufLen  [IN]  Length of the buffer
 * @param   len     [OUT] Pointer to a variable where the total length of packed extensions will be stored
 * @param   context [IN]  The context to check against the custom extensions
 * @param   cert    [IN]  Pointer to the HITLS_X509_Cert structure representing certificate information
 * @param   certIndex  [IN]  Certificate index indicating its position in the certificate chain
 * @retval  HITLS_SUCCESS if the custom extensions are successfully packed
 * @retval  An error code if packing fails, see hitls_error.h for details
 */
int32_t PackCustomExtensions(const struct TlsCtx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint32_t context, HITLS_X509_Cert *cert, uint32_t certIndex);


/**
 * @brief   Frees the custom extension methods in the HITLS configuration.
 *
 * This function frees the custom extension methods in the HITLS configuration.
 *
 * @param   exts    [IN] Pointer to the CustomExt_Methods structure containing extension methods
 */
void FreeCustomExtensions(CustomExt_Methods *exts);

/**
 * @brief   Duplicates the custom extension methods in the HITLS configuration.
 *
 * This function duplicates the custom extension methods in the HITLS configuration.
 *
 * @param   exts    [IN] Pointer to the CustomExt_Methods structure containing extension methods
 * @retval  Pointer to the duplicated CustomExt_Methods structure
 */
CustomExt_Methods *DupCustomExtensions(CustomExt_Methods *exts);

/**
 * @brief   Parses custom extensions from the provided buffer for a given extension type and context.
 *
 * This function iterates through the list of custom extension methods associated with the TLS context
 * and parses the relevant custom extensions from the provided buffer. It checks each extension method
 * to determine if it should be parsed based on the specified extension type and context. If an extension
 * is applicable, it uses the associated parse callback to interpret the extension data.
 *
 * @param   ctx     [IN] Pointer to the TLS context containing custom extension methods
 * @param   buf     [IN] Buffer containing the custom extensions to be parsed
 * @param   extType [IN] The extension type to check against the custom extensions
 * @param   extLen  [IN] Length of the extension data in the buffer
 * @param   context [IN] The context to check against the custom extensions
 * @param   cert    [IN] Pointer to the HITLS_X509_Cert structure representing certificate information
 * @param   certIndex  [IN]  Certificate index indicating its position in the certificate chain
 * @retval  HITLS_SUCCESS if the custom extensions are successfully parsed
 * @retval  An error code if parsing fails, see hitls_error.h for details
 */
int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint16_t extType, uint32_t extLen,
    uint32_t context, HITLS_X509_Cert *cert, uint32_t certIndex);

#endif // CUSTOM_EXTENSIONS_H
