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

#ifndef SAL_DLIMPL_H
#define SAL_DLIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_DL

#include <stdint.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BslSalLoadLib pfLoadLib;
    BslSalUnLoadLib pfUnLoadLib;
    BslSalGetFunc pfGetFunc;
} BSL_SAL_DlCallback;

int32_t SAL_DlCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#ifdef HITLS_BSL_SAL_LINUX
/**
 * @brief Load a dynamic library
 * @param fileName Name of the library file to load
 * @param handle Pointer to store the handle of the loaded library
 * @return 0 on success, non-zero error code on failure
 */
int32_t SAL_LoadLib(const char *fileName, void **handle);

/**
 * @brief Unload a previously loaded dynamic library
 * @param handle Handle of the library to unload
 * @return 0 on success, non-zero error code on failure
 */
int32_t SAL_UnLoadLib(void *handle);

/**
 * @brief Get a function pointer from a loaded library
 * @param handle Handle of the loaded library
 * @param funcName Name of the function to retrieve
 * @param func Pointer to store the function pointer
 * @return 0 on success, non-zero error code on failure
 */
int32_t SAL_GetFunc(void *handle, const char *funcName, void **func);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_SAL_DL */
#endif // SAL_DLIMPL_H
