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

#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_params_key.h"

#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_PKEY)
int32_t CRYPT_GetPkeyProcessParams(BSL_Param *params, CRYPT_EAL_ProcessFuncCb *processCb, void **args)
{
    BSL_Param *processParam = BSL_PARAM_FindParam(params, CRYPT_PARAM_PKEY_PROCESS_FUNC);
    if (processParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = BSL_PARAM_GetPtrValue(processParam, CRYPT_PARAM_PKEY_PROCESS_FUNC,
        BSL_PARAM_TYPE_FUNC_PTR, (void **)processCb, NULL);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (*processCb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    BSL_Param *argsParam = BSL_PARAM_FindParam(params, CRYPT_PARAM_PKEY_PROCESS_ARGS);
    if (argsParam != NULL) {
        GOTO_ERR_IF(BSL_PARAM_GetPtrValue(argsParam, CRYPT_PARAM_PKEY_PROCESS_ARGS,
            BSL_PARAM_TYPE_CTX_PTR, args, NULL), ret);
    }
ERR:
    return ret;
}
#endif