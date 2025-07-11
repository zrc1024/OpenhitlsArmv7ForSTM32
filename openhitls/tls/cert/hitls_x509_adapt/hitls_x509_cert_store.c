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
#if defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER)
#include <stdint.h>
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"
#include "hitls_pki_x509.h"
#include "hitls_cert_local.h"
#include "hitls_error.h"
#include "hitls_x509_adapt.h"

HITLS_CERT_Store *HITLS_X509_Adapt_StoreNew(void)
{
    return (HITLS_CERT_Store *)HITLS_X509_StoreCtxNew();
}

HITLS_CERT_Store *HITLS_X509_Adapt_StoreDup(HITLS_CERT_Store *store)
{
    int references = 0;
    int32_t ret = HITLS_X509_StoreCtxCtrl((HITLS_X509_StoreCtx *)store, HITLS_X509_STORECTX_REF_UP, &references,
        sizeof(int));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return NULL;
    }

    return store;
}

void HITLS_X509_Adapt_StoreFree(HITLS_CERT_Store *store)
{
    HITLS_X509_StoreCtxFree(store);
}

int32_t HITLS_X509_Adapt_StoreCtrl(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output)
{
    (void)config;
    (void)output;
    switch (cmd) {
        case CERT_STORE_CTRL_SET_VERIFY_DEPTH:
            return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_PARAM_DEPTH, input, sizeof(int32_t));
        case CERT_STORE_CTRL_ADD_CERT_LIST:
            return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SHALLOW_COPY_SET_CA, input,
                sizeof(HITLS_X509_Cert));
        default:
            return HITLS_CERT_SELF_ADAPT_ERR;
    }
}
#endif /* defined(HITLS_TLS_CALLBACK_CERT) || defined(HITLS_TLS_FEATURE_PROVIDER) */
