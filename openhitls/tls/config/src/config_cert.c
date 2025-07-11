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

#include <stdlib.h>
#include <string.h>
#include "hitls_build.h"
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "tls_binlog_id.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "tls_config.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "cert.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif

#ifdef HITLS_TLS_FEATURE_SECURITY
static int32_t CheckCertSecuritylevel(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isCACert)
{
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16550, "unregistered callback");
    }

    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16551, "GET_PUB_KEY fail");
    }
    do {
        int32_t secBits = 0;
        ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
        if (ret != HITLS_SUCCESS) {
            break;
        }

        if (isCACert == true) {
            ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_CA_KEY, secBits, 0, cert);
            if (ret != SECURITY_SUCCESS) {
                (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16552, "CfgCheck fail");
                ret = HITLS_CERT_ERR_CA_KEY_WITH_INSECURE_SECBITS;
                break;
            }
        } else {
            ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_EE_KEY, secBits, 0, cert);
            if (ret != SECURITY_SUCCESS) {
                (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16553, "CfgCheck fail");
                ret = HITLS_CERT_ERR_EE_KEY_WITH_INSECURE_SECBITS;
                break;
            }
        }

        int32_t signAlg = 0;
        ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_SIGN_ALGO, NULL, (void *)&signAlg);
        if (ret != HITLS_SUCCESS) {
            (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16554, "GET_SIGN_ALGO fail");
            break;
        }

        ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signAlg, NULL);
        if (ret != SECURITY_SUCCESS) {
            (void)RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16555, "CfgCheck fail");
            ret = HITLS_CERT_ERR_INSECURE_SIG_ALG;
            break;
        }
        ret = HITLS_SUCCESS;
    } while (false);
    SAL_CERT_KeyFree(mgrCtx, pubkey);
    return ret;
}
#endif

int32_t HITLS_CFG_SetVerifyStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *newStore = NULL;
    if (isClone && store != NULL) {
        newStore = SAL_CERT_StoreDup(config->certMgrCtx, store);
        if (newStore == NULL) {
            return HITLS_CERT_ERR_STORE_DUP;
        }
    } else {
        newStore = store;
    }

    int32_t ret = SAL_CERT_SetVerifyStore(config->certMgrCtx, newStore);
    if (ret != HITLS_SUCCESS) {
        if (isClone && newStore != NULL) {
            SAL_CERT_StoreFree(config->certMgrCtx, newStore);
        }
    }
    return ret;
}

HITLS_CERT_Store *HITLS_CFG_GetVerifyStore(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetVerifyStore(config->certMgrCtx);
}

int32_t HITLS_CFG_SetChainStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *newStore = NULL;
    if (isClone && store != NULL) {
        newStore = SAL_CERT_StoreDup(config->certMgrCtx, store);
        if (newStore == NULL) {
            return HITLS_CERT_ERR_STORE_DUP;
        }
    } else {
        newStore = store;
    }

    int32_t ret = SAL_CERT_SetChainStore(config->certMgrCtx, newStore);
    if (ret != HITLS_SUCCESS) {
        if (isClone && newStore != NULL) {
            SAL_CERT_StoreFree(config->certMgrCtx, newStore);
        }
    }
    return ret;
}

HITLS_CERT_Store *HITLS_CFG_GetChainStore(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetChainStore(config->certMgrCtx);
}

int32_t HITLS_CFG_SetCertStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *newStore = NULL;
    if (isClone && store != NULL) {
        newStore = SAL_CERT_StoreDup(config->certMgrCtx, store);
        if (newStore == NULL) {
            return HITLS_CERT_ERR_STORE_DUP;
        }
    } else {
        newStore = store;
    }

    int32_t ret = SAL_CERT_SetCertStore(config->certMgrCtx, newStore);
    if (ret != HITLS_SUCCESS) {
        if (isClone && newStore != NULL) {
            SAL_CERT_StoreFree(config->certMgrCtx, newStore);
        }
    }
    return ret;
}

HITLS_CERT_Store *HITLS_CFG_GetCertStore(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCertStore(config->certMgrCtx);
}

int32_t HITLS_CFG_SetVerifyDepth(HITLS_Config *config, uint32_t depth)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetVerifyDepth(config->certMgrCtx, depth);
}

int32_t HITLS_CFG_GetVerifyDepth(const HITLS_Config *config, uint32_t *depth)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_GetVerifyDepth(config->certMgrCtx, depth);
}

int32_t HITLS_CFG_SetDefaultPasswordCb(HITLS_Config *config, HITLS_PasswordCb cb)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetDefaultPasswordCb(config->certMgrCtx, cb);
}

HITLS_PasswordCb HITLS_CFG_GetDefaultPasswordCb(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetDefaultPasswordCb(config->certMgrCtx);
}

int32_t HITLS_CFG_SetDefaultPasswordCbUserdata(HITLS_Config *config, void *userdata)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetDefaultPasswordCbUserdata(config->certMgrCtx, userdata);
}

void *HITLS_CFG_GetDefaultPasswordCbUserdata(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetDefaultPasswordCbUserdata(config->certMgrCtx);
}

static int32_t CFG_SetCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone, bool isTlcpEncCert)
{
    if (config == NULL || cert == NULL) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_X509 *newCert = cert;
    if (isClone) {
        newCert = SAL_CERT_X509Dup(config->certMgrCtx, cert);
        if (newCert == NULL) {
            return HITLS_CERT_ERR_X509_DUP;
        }
    }

    int32_t ret = SAL_CERT_SetCurrentCert(config, newCert, isTlcpEncCert);
    if (ret != HITLS_SUCCESS) {
        if (isClone) {
            SAL_CERT_X509Free(newCert);
        }
    }
    return ret;
}

int32_t HITLS_CFG_SetCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone)
{
    if (config == NULL || cert == NULL || config->certMgrCtx == NULL) {
        return HITLS_NULL_INPUT;
    }
#ifdef HITLS_TLS_FEATURE_SECURITY
    int32_t ret = CheckCertSecuritylevel(config, cert, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
    return CFG_SetCertificate(config, cert, isClone, false);
}
#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
int32_t HITLS_CFG_LoadCertFile(HITLS_Config *config, const char *file, HITLS_ParseFormat format)
{
    if (config == NULL || file == NULL || strlen(file) == 0) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret;
    HITLS_CERT_X509 *cert = SAL_CERT_X509Parse(LIBCTX_FROM_CONFIG(config),
            ATTRIBUTE_FROM_CONFIG(config), config, (const uint8_t *)file, (uint32_t)strlen(file),
        TLS_PARSE_TYPE_FILE, format);
    if (cert == NULL) {
        return HITLS_CFG_ERR_LOAD_CERT_FILE;
    }
#ifdef HITLS_TLS_FEATURE_SECURITY
    ret = CheckCertSecuritylevel(config, cert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(cert);
        return ret;
    }
#endif
    ret = SAL_CERT_SetCurrentCert(config, cert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(cert);
    }
    return ret;
}
#endif /* HITLS_TLS_CONFIG_CERT_LOAD_FILE */

int32_t HITLS_CFG_LoadCertBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || bufLen == 0) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_X509 *newCert = SAL_CERT_X509Parse(LIBCTX_FROM_CONFIG(config),
        ATTRIBUTE_FROM_CONFIG(config),config, buf, bufLen, TLS_PARSE_TYPE_BUFF, format);
    if (newCert == NULL) {
        return HITLS_CFG_ERR_LOAD_CERT_BUFFER;
    }
    int ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_SECURITY
    ret = CheckCertSecuritylevel(config, newCert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(newCert);
        return ret;
    }
#endif
    ret = SAL_CERT_SetCurrentCert(config, newCert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(newCert);
    }

    return ret;
}

HITLS_CERT_X509 *HITLS_CFG_GetCertificate(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCurrentCert(config->certMgrCtx);
}

static int32_t CFG_SetPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey, bool isClone,
    bool isTlcpEncCertPriKey)
{
    if (config == NULL || privateKey == NULL) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Key *newKey = NULL;
    if (isClone) {
        newKey = SAL_CERT_KeyDup(config->certMgrCtx, privateKey);
        if (newKey == NULL) {
            return HITLS_CERT_ERR_X509_DUP;
        }
    } else {
        newKey = privateKey;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, isTlcpEncCertPriKey);
    if (ret != HITLS_SUCCESS) {
        if (isClone) {
            SAL_CERT_KeyFree(config->certMgrCtx, newKey);
        }
    }
    return ret;
}

#ifdef HITLS_TLS_PROTO_TLCP11
int32_t HITLS_CFG_SetTlcpPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey,
    bool isClone, bool isTlcpEncCertPriKey)
{
    return CFG_SetPrivateKey(config, privateKey, isClone, isTlcpEncCertPriKey);
}

int32_t HITLS_CFG_SetTlcpCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone, bool isTlcpEncCert)
{
    return CFG_SetCertificate(config, cert, isClone, isTlcpEncCert);
}
#endif

int32_t HITLS_CFG_SetPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey, bool isClone)
{
    return CFG_SetPrivateKey(config, privateKey, isClone, false);
}

#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
int32_t HITLS_CFG_ProviderLoadKeyFile(HITLS_Config *config, const char *file, const char *format, const char *type)
{
    if (config == NULL || file == NULL || strlen(file) == 0) {
        return HITLS_NULL_INPUT;
    }
    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, (const uint8_t *)file, (uint32_t)strlen(file),
        TLS_PARSE_TYPE_FILE, format, type);
    if (newKey == NULL) {
        return HITLS_CFG_ERR_LOAD_KEY_FILE;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(config->certMgrCtx, newKey);
    }
    return ret;
}

int32_t HITLS_CFG_LoadKeyFile(HITLS_Config *config, const char *file, HITLS_ParseFormat format)
{
    if (config == NULL || file == NULL || strlen(file) == 0) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, (const uint8_t *)file, (uint32_t)strlen(file),
        TLS_PARSE_TYPE_FILE, SAL_CERT_GetParseFormatStr(format), NULL);
    if (newKey == NULL) {
        return HITLS_CFG_ERR_LOAD_KEY_FILE;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(config->certMgrCtx, newKey);
    }
    return ret;
}
#endif /* HITLS_TLS_CONFIG_CERT_LOAD_FILE */

int32_t HITLS_CFG_ProviderLoadKeyBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, const char *format,
    const char *type)
{
    if (config == NULL || buf == NULL || bufLen == 0) {
        return HITLS_NULL_INPUT;
    }
    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, buf, bufLen, TLS_PARSE_TYPE_BUFF, type, format);
    if (newKey == NULL) {
        return HITLS_CFG_ERR_LOAD_KEY_BUFFER;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(config->certMgrCtx, newKey);
    }
    return ret;
}

int32_t HITLS_CFG_LoadKeyBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || bufLen == 0) {
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, buf, bufLen, TLS_PARSE_TYPE_BUFF,
        SAL_CERT_GetParseFormatStr(format), NULL);
    if (newKey == NULL) {
        return HITLS_CFG_ERR_LOAD_KEY_BUFFER;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(config->certMgrCtx, newKey);
    }
    return ret;
}

HITLS_CERT_Key *HITLS_CFG_GetPrivateKey(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCurrentPrivateKey(config->certMgrCtx, false);
}

int32_t HITLS_CFG_CheckPrivateKey(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *certMgrCtx = config->certMgrCtx;
    if (certMgrCtx == NULL) {
        /* If no certificate callback is registered, the certificate management module will not initialized. */
        return HITLS_UNREGISTERED_CALLBACK;
    }

    HITLS_CERT_X509 *cert = SAL_CERT_GetCurrentCert(certMgrCtx);
    if (cert == NULL) {
        /* no certificate is added */
        return HITLS_CONFIG_NO_CERT;
    }

    HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(certMgrCtx, false);
    if (privateKey == NULL) {
        /* no private key is added */
        return HITLS_CONFIG_NO_PRIVATE_KEY;
    }

    return SAL_CERT_CheckPrivateKey(config, cert, privateKey);
}

int32_t HITLS_CFG_AddChainCert(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone)
{
    if (config == NULL || cert == NULL || config->certMgrCtx == NULL) {
        return HITLS_NULL_INPUT;
    }
    int32_t ret = HITLS_SUCCESS;
#ifdef HITLS_TLS_FEATURE_SECURITY
    ret = CheckCertSecuritylevel(config, cert, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
    HITLS_CERT_X509 *newCert = cert;
    if (isClone) {
        newCert = SAL_CERT_X509Dup(config->certMgrCtx, cert);
        if (newCert == NULL) {
            return HITLS_CERT_ERR_X509_DUP;
        }
    }

    ret = SAL_CERT_AddChainCert(config->certMgrCtx, newCert);
    if (ret != HITLS_SUCCESS) {
        if (isClone) {
            SAL_CERT_X509Free(newCert);
        }
    }
    return ret;
}

int32_t HITLS_CFG_AddCertToStore(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_StoreType storeType,
    bool isClone)
{
    if (config == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *store = NULL;
    switch (storeType) {
        case TLS_CERT_STORE_TYPE_DEFAULT:
            store = SAL_CERT_GetCertStore(config->certMgrCtx);
            break;
        case TLS_CERT_STORE_TYPE_VERIFY:
            store = SAL_CERT_GetVerifyStore(config->certMgrCtx);
            break;
        case TLS_CERT_STORE_TYPE_CHAIN:
            store = SAL_CERT_GetChainStore(config->certMgrCtx);
            break;
        default:
            return HITLS_CERT_ERR_INVALID_STORE_TYPE;
    }
    HITLS_CERT_X509 *newCert = cert;
    if (isClone) {
        newCert = SAL_CERT_X509Dup(config->certMgrCtx, cert);
        if (newCert == NULL) {
            return HITLS_CERT_ERR_X509_DUP;
        }
    }

    int32_t ret = SAL_CERT_StoreCtrl(config, store, CERT_STORE_CTRL_ADD_CERT_LIST, newCert, NULL);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

HITLS_CERT_X509 *HITLS_CFG_ParseCert(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || len == 0) {
        return NULL;
    }

    HITLS_CERT_X509 *newCert = SAL_CERT_X509Parse(LIBCTX_FROM_CONFIG(config),
            ATTRIBUTE_FROM_CONFIG(config), config, buf, len, type, format);
    if (newCert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17158, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "X509Parse fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CFG_ERR_LOAD_CERT_BUFFER);
        return NULL;
    }

    return newCert;
}

HITLS_CERT_Key *HITLS_CFG_ProviderParseKey(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, const char *format, const char *encodeType)
{
    if (config == NULL || buf == NULL || len == 0) {
        return NULL;
    }

    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, buf, len, type, format, encodeType);
    if (newKey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17165, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Provider KeyParse fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CFG_ERR_LOAD_KEY_BUFFER);
        return NULL;
    }

    return newKey;
}

HITLS_CERT_Key *HITLS_CFG_ParseKey(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || len == 0) {
        return NULL;
    }

    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, buf, len, type,
        SAL_CERT_GetParseFormatStr(format), NULL);
    if (newKey == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17164, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "KeyParse fail", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CFG_ERR_LOAD_KEY_BUFFER);
        return NULL;
    }

    return newKey;
}

HITLS_CERT_Chain *HITLS_CFG_GetChainCerts(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCurrentChainCerts(config->certMgrCtx);
}


int32_t HITLS_CFG_ClearChainCerts(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    SAL_CERT_ClearCurrentChainCerts(config->certMgrCtx);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_AddExtraChainCert(HITLS_Config *config, HITLS_CERT_X509 *cert)
{
    if (config == NULL || cert == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_AddExtraChainCert(config->certMgrCtx, cert);
}

HITLS_CERT_Chain *HITLS_CFG_GetExtraChainCerts(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetExtraChainCerts(config->certMgrCtx);
}

int32_t HITLS_CFG_RemoveCertAndKey(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    SAL_CERT_ClearCertAndKey(config->certMgrCtx);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetVerifyCb(HITLS_Config *config, HITLS_VerifyCb callback)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetVerifyCb(config->certMgrCtx, callback);
}

HITLS_VerifyCb HITLS_CFG_GetVerifyCb(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetVerifyCb(config->certMgrCtx);
}

#ifdef HITLS_TLS_FEATURE_CERT_CB
int32_t HITLS_CFG_SetCertCb(HITLS_Config *config, HITLS_CertCb certCb, void *arg)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetCertCb(config->certMgrCtx, certCb, arg);
}
#endif /* HITLS_TLS_FEATURE_CERT_CB */

#ifdef HITLS_TLS_FEATURE_CERT_MODE
int32_t HITLS_CFG_SetVerifyNoneSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportVerifyNone = support;

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetVerifyNoneSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportVerifyNone;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetClientVerifySupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportClientVerify;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_GetNoClientCertSupport(HITLS_Config *config, uint8_t *isSupport)
{
    if (config == NULL || isSupport == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSupport = (uint8_t)config->isSupportNoClientCert;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetClientVerifySupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }
    config->isSupportClientVerify = support;
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetNoClientCertSupport(HITLS_Config *config, bool support)
{
    if (config == NULL) {
        return HITLS_NULL_INPUT;
    }

    config->isSupportNoClientCert = support;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_EXTENSION_CERT_AUTH
int32_t HITLS_CFG_AddCAIndication(HITLS_Config *config, HITLS_TrustedCAType caType, const uint8_t *data, uint32_t len)
{
    if ((config == NULL) || (data == NULL) || (len == 0)) {
        return HITLS_NULL_INPUT;
    }

    HITLS_TrustedCANode *newCaNode = BSL_SAL_Calloc(1u, sizeof(HITLS_TrustedCANode));
    if (newCaNode == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16558, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }
    newCaNode->caType = caType;
    newCaNode->data = BSL_SAL_Dump(data, len);
    if (newCaNode->data == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16559, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        BSL_SAL_FREE(newCaNode);
        return HITLS_MEMALLOC_FAIL;
    }
    newCaNode->dataSize = len;

    if (config->caList == NULL) {
        config->caList = BSL_LIST_New(sizeof(HITLS_TrustedCANode *));
        if (config->caList == NULL) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16560, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "LIST_New fail", 0, 0, 0, 0);
            BSL_SAL_FREE(newCaNode->data);
            BSL_SAL_FREE(newCaNode);
            return HITLS_MEMALLOC_FAIL;
        }
    }

    /* tail insertion */
    int32_t ret = (int32_t)BSL_LIST_AddElement((BslList *)config->caList, newCaNode, BSL_LIST_POS_END);
    if (ret != 0) {
        BSL_SAL_FREE(newCaNode->data);
        BSL_SAL_FREE(newCaNode);
    }
    return ret;
}
HITLS_TrustedCAList *HITLS_CFG_GetCAList(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }
    return config->caList;
}

#endif