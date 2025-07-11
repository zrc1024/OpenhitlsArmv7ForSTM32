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

#if defined(HITLS_BSL_SAL_DL)
#include <stdio.h>
#include <stdint.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"

#include "string.h"
#include "sal_dlimpl.h"
#include "bsl_log_internal.h"

static BSL_SAL_DlCallback g_dlCallback = {0};

// Define macro for path reserve length
#define BSL_SAL_PATH_RESERVE 10

#define BSL_SAL_PATH_MAX 4095
#define BSL_SAL_NAME_MAX 255

int32_t BSL_SAL_LibNameFormat(BSL_SAL_LibFmtCmd cmd, const char *fileName, char **name)
{
    if (fileName == NULL || name == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    int32_t ret = 0;
    char *tempName = NULL;
    uint32_t dlPathLen = strlen(fileName) + BSL_SAL_PATH_RESERVE;
    if (dlPathLen > BSL_SAL_NAME_MAX) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_DL_PATH_EXCEED);
        return BSL_SAL_ERR_DL_PATH_EXCEED;
    }
    tempName = (char *)BSL_SAL_Calloc(1, dlPathLen);
    if (tempName == NULL) {
        return BSL_MALLOC_FAIL;
    }
    switch (cmd) {
        case BSL_SAL_LIB_FMT_SO:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s.so", fileName);
            break;
        case BSL_SAL_LIB_FMT_LIBSO:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "lib%s.so", fileName);
            break;
        case BSL_SAL_LIB_FMT_LIBDLL:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "lib%s.dll", fileName);
            break;
        case BSL_SAL_LIB_FMT_DLL:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s.dll", fileName);
            break;
        case BSL_SAL_LIB_FMT_OFF:
            ret = snprintf_s(tempName, dlPathLen, dlPathLen, "%s", fileName);
            break;
        default:
            // Default to the first(BSL_SAL_LIB_FMT_SO) conversion
            BSL_SAL_Free(tempName);
            BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
            return BSL_SAL_ERR_BAD_PARAM;
    }
    if (ret < 0) {
        BSL_SAL_Free(tempName);
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }
    *name = tempName;
    return BSL_SUCCESS;
}

int32_t BSL_SAL_LoadLib(const char *fileName, void **handle)
{
    if (fileName == NULL || handle == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pfLoadLib != NULL && g_dlCallback.pfLoadLib != BSL_SAL_LoadLib) {
        return g_dlCallback.pfLoadLib(fileName, handle);
    }
#ifdef HITLS_BSL_SAL_LINUX
    return SAL_LoadLib(fileName, handle);
#else
    return BSL_SAL_DL_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_UnLoadLib(void *handle)
{
    if (handle == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pfUnLoadLib != NULL && g_dlCallback.pfUnLoadLib != BSL_SAL_UnLoadLib) {
        return g_dlCallback.pfUnLoadLib(handle);
    }
#ifdef HITLS_BSL_SAL_LINUX
    return SAL_UnLoadLib(handle);
#else
    return BSL_SAL_DL_NO_REG_FUNC;
#endif
}

int32_t BSL_SAL_GetFuncAddress(void *handle, const char *funcName, void **func)
{
    if (handle == NULL || func == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_SAL_ERR_BAD_PARAM);
        return BSL_SAL_ERR_BAD_PARAM;
    }
    if (g_dlCallback.pfGetFunc != NULL && g_dlCallback.pfGetFunc != BSL_SAL_GetFuncAddress) {
        return g_dlCallback.pfGetFunc(handle, funcName, func);
    }
#ifdef HITLS_BSL_SAL_LINUX
    return SAL_GetFunc(handle, funcName, func);
#else
    return BSL_SAL_DL_NO_REG_FUNC;
#endif
}

int32_t SAL_DlCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_DL_SYM_CB_FUNC || type < BSL_SAL_DL_OPEN_CB_FUNC) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_DL_OPEN_CB_FUNC);
    ((void **)&g_dlCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}

#endif /* HITLS_BSL_SAL_DL */
