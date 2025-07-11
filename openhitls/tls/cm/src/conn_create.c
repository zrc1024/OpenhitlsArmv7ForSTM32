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
#include "securec.h"
#include "bsl_err_internal.h"
#include "tls_binlog_id.h"
#include "bsl_sal.h"
#include "bsl_errno.h"
#include "bsl_list.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_config.h"
#include "hitls_cert_type.h"
#include "hitls.h"
#include "tls.h"
#include "tls_config.h"
#include "cert.h"
#ifdef HITLS_TLS_FEATURE_SESSION
#include "session.h"
#include "session_mgr.h"
#endif
#include "bsl_uio.h"
#include "config.h"
#include "config_check.h"
#include "conn_common.h"
#include "conn_init.h"
#include "crypt.h"
#include "cipher_suite.h"

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
static int32_t PeerInfoInit(HITLS_Ctx *ctx)
{
    /* The peerInfo.caList is used to adapt to the OpenSSL behavior. When creating the SSL_CTX object, OpenSSL
     * initializes the member so that the member is not null */
    ctx->peerInfo.caList = BSL_LIST_New(sizeof(HITLS_TrustedCANode *));
    if (ctx->peerInfo.caList == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16468, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "LIST_New fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    return HITLS_SUCCESS;
}
#endif
/**
 * @ingroup    hitls
 * @brief      Create a TLS object and deep Copy the HITLS_Config to the HITLS_Ctx.
 * @attention  After the creation is successful, the HITLS_Config can be released.
 * @param      config [IN] config Context
 * @return     HITLS_Ctx Pointer. If the operation fails, null is returned.
 */
HITLS_Ctx *HITLS_New(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16469, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "config null", 0, 0, 0, 0);
        return NULL;
    }

    HITLS_Ctx *newCtx = (HITLS_Ctx *)BSL_SAL_Calloc(1u, sizeof(HITLS_Ctx));
    if (newCtx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16470, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return NULL;
    }

    int32_t ret = CheckConfig(config);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16471, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CheckConfig fail, ret %d", ret, 0, 0, 0);
        BSL_SAL_FREE(newCtx);
        return NULL;
    }

    ret = DumpConfig(newCtx, config);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16472, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "DumpConfig fail, ret %d", ret, 0, 0, 0);
        BSL_SAL_FREE(newCtx);
        return NULL;
    }
    (void)HITLS_CFG_UpRef(config);
    newCtx->globalConfig = config;
#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
    ret = PeerInfoInit(newCtx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16473, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "PeerInfoInit fail, ret %d", ret, 0, 0, 0);
        HITLS_Free(newCtx);
        return NULL;
    }
#endif
    ChangeConnState(newCtx, CM_STATE_IDLE);
    return newCtx;
}

static void CaListNodeDestroy(void *data)
{
    HITLS_TrustedCANode *tmpData = (HITLS_TrustedCANode *)data;
    BSL_SAL_FREE(tmpData->data);
    BSL_SAL_FREE(tmpData);
    return;
}

static void CleanPeerInfo(PeerInfo *peerInfo)
{
    BSL_SAL_FREE(peerInfo->groups);
    BSL_SAL_FREE(peerInfo->cipherSuites);
    BSL_LIST_FREE(peerInfo->caList, CaListNodeDestroy);
    BSL_SAL_FREE(peerInfo->signatureAlgorithms);
}

#if defined(HITLS_TLS_EXTENSION_COOKIE) || defined(HITLS_TLS_FEATURE_ALPN)
static void CleanNegotiatedInfo(TLS_NegotiatedInfo *negotiatedInfo)
{
#ifdef HITLS_TLS_EXTENSION_COOKIE
    BSL_SAL_FREE(negotiatedInfo->cookie);
#endif
#ifdef HITLS_TLS_FEATURE_ALPN
    BSL_SAL_FREE(negotiatedInfo->alpnSelected);
#endif
    return;
}
#endif

/**
 * @ingroup hitls
 * @brief   Release the TLS connection.
 * @param   ctx [IN] TLS connection handle.
 * @return  void
 */
void HITLS_Free(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
#ifdef HITLS_TLS_CONFIG_STATE
    ctx->rwstate = HITLS_NOTHING;
#endif
    CONN_Deinit(ctx);
    BSL_UIO_Free(ctx->uio);
#ifdef HITLS_TLS_FEATURE_FLIGHT
    BSL_UIO_Free(ctx->rUio);
    ctx->rUio = NULL;
#endif
    ctx->uio = NULL;
#ifdef HITLS_TLS_FEATURE_SESSION
    /* Release certificate resources before releasing the config file. Otherwise, memory leakage occurs */
    HITLS_SESS_Free(ctx->session);
#endif
    CFG_CleanConfig(&ctx->config.tlsConfig);
    HITLS_CFG_FreeConfig(ctx->globalConfig);
    CleanPeerInfo(&(ctx->peerInfo));
#if defined(HITLS_TLS_EXTENSION_COOKIE) || defined(HITLS_TLS_FEATURE_ALPN)
    CleanNegotiatedInfo(&ctx->negotiatedInfo);
#endif
#ifdef HITLS_TLS_FEATURE_PHA
    SAL_CRYPT_DigestFree(ctx->phaHash);
    ctx->phaHash = NULL;
    SAL_CRYPT_DigestFree(ctx->phaCurHash);
    ctx->phaCurHash = NULL;
    ctx->phaState = PHA_NONE;
    BSL_SAL_FREE(ctx->certificateReqCtx);
    ctx->certificateReqCtxSize = 0;
#endif
    BSL_SAL_FREE(ctx);
    return;
}

#ifdef HITLS_TLS_FEATURE_FLIGHT
int32_t HITLS_SetReadUio(HITLS_Ctx *ctx, BSL_UIO *uio)
{
    if ((ctx == NULL) || (uio == NULL)) {
        return HITLS_NULL_INPUT;
    }

    int32_t ret = BSL_UIO_UpRef(uio);
    if (ret != BSL_SUCCESS) {
        return HITLS_UIO_FAIL;
    }

    if (ctx->rUio != NULL) {
        /* A message is displayed, warning the user that the UIO is set repeatedly */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15662, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Warning: Repeated uio setting.", 0, 0, 0, 0);
        /* Release the original UIO */
        BSL_UIO_Free(ctx->rUio);
    }

    ctx->rUio = uio;

    return HITLS_SUCCESS;
}
#endif

static void ConfigPmtu(HITLS_Ctx *ctx, BSL_UIO *uio)
{
    (void)ctx;
    (void)uio;
#ifdef HITLS_TLS_PROTO_DTLS12
    /* The PMTU needs to be set for DTLS. If the PMTU is not set, use the default value */
    if ((ctx->config.pmtu == 0) && IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask)) {
        ctx->config.pmtu = DTLS_SCTP_PMTU;
    }
#endif
}

/**
 * @ingroup hitls
 * @brief   Set the UIO for the HiTLS context.
 * @attention This function must be called before HITLS_Connect and HITLS_Accept and released after HITLS_Free. If this
 *          function has been called, you must call BSL_UIO_Free to release the UIO.
 * @param   ctx [OUT] TLS connection handle.
 * @param   uio [IN] UIO object
 * @return  HITLS_SUCCESS succeeded
 *          Other Error Codes, see hitls_error.h
 */
int32_t HITLS_SetUio(HITLS_Ctx *ctx, BSL_UIO *uio)
{
    if ((ctx == NULL) || (uio == NULL)) {
        return HITLS_NULL_INPUT;
    }

    /* The UIO count increases by 1, and the reference counting is performed for the write UIO */
    int32_t ret = BSL_UIO_UpRef(uio);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16474, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
            "UIO_UpRef fail, ret %d", ret, 0, 0, 0);
        return HITLS_UIO_FAIL;
    }
#ifdef HITLS_TLS_FEATURE_FLIGHT
    /* The UIO count increases by 1, and the reference counting is performed for reading the UIO */
    ret = BSL_UIO_UpRef(uio);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16475, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
            "UIO_UpRef fail, ret %d", ret, 0, 0, 0);
        BSL_UIO_Free(uio); // free Drop the one on the top.
        return HITLS_UIO_FAIL;
    }
#endif
    /* The original write uio is not empty */
    if (ctx->uio != NULL) {
        /* A message is displayed, warning the user that the UIO is set repeatedly. */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15960, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Warning: Repeated uio setting.", 0, 0, 0, 0);
        /* Release the original write UIO */
        if (ctx->bUio != NULL) {
            ctx->uio = BSL_UIO_PopCurrent(ctx->uio);
        }
        BSL_UIO_FreeChain(ctx->uio);
    }
    ctx->uio = uio;
#ifdef HITLS_TLS_FEATURE_FLIGHT
    if (ctx->bUio != NULL) {
        ret = BSL_UIO_Append(ctx->bUio, ctx->uio);
        if (ret != BSL_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16476, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
                "UIO_Append fail, ret %d", ret, 0, 0, 0);
            BSL_UIO_Free(uio); // free Drop the one on the top.
            return HITLS_UIO_FAIL;
        }
        ctx->uio = ctx->bUio;
    }
    /* The original read UIO is not empty */
    if (ctx->rUio != NULL) {
        /* A message is displayed, warning the user that the UIO is set repeatedly */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15253, BSL_LOG_LEVEL_WARN, BSL_LOG_BINLOG_TYPE_RUN,
            "Warning: Repeated uio setting.", 0, 0, 0, 0);
        /* Release the original read UIO */
        BSL_UIO_Free(ctx->rUio);
    }
    ctx->rUio = uio;
#endif
    ConfigPmtu(ctx, uio);
    return HITLS_SUCCESS;
}

BSL_UIO *HITLS_GetUio(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
#ifdef HITLS_TLS_FEATURE_FLIGHT
    /* If |bUio| is active, the true caller-configured uio is its |next_uio|. */
    if (ctx->config.tlsConfig.isFlightTransmitEnable == true && ctx->bUio != NULL) {
        return BSL_UIO_Next(ctx->bUio);
    }
#endif
    return ctx->uio;
}

BSL_UIO *HITLS_GetReadUio(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->rUio;
}

/**
 * @ingroup hitls
 * @brief   Obtain user data from the HiTLS context. Generally, this interface is invoked during the callback registered
 *          with the HiTLS.
 * @attention must be invoked before HITLS_Connect and HITLS_Accept. The life cycle of the user identifier must be
 *           longer than the life cycle of the TLS object.
 * @param  ctx [OUT] TLS connection handle.
 * @param  userData [IN] User identifier.
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_NULL_INPUT The input parameter TLS object is a null pointer.
 */
void *HITLS_GetUserData(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return ctx->config.userData;
}

/**
 * @ingroup hitls
 * @brief User data is stored in the HiTLS context and can be obtained from the callback registered with the HiTLS.
 * @attention must be invoked before HITLS_Connect and HITLS_Accept. The life cycle of the user identifier must be
 *            longer than the life cycle of the TLS object. If the user data needs to be cleared, the
 * HITLS_SetUserData(ctx, NULL) interface can be invoked directly. The Clean interface is not provided separately.
 * @param  ctx [OUT] TLS connection handle.
 * @param  userData [IN] User identifier.
 * @retval HITLS_SUCCESS succeeded.
 * @retval HITLS_NULL_INPUT The input parameter TLS object is a null pointer.
 */
int32_t HITLS_SetUserData(HITLS_Ctx *ctx, void *userData)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    ctx->config.userData = userData;
    return HITLS_SUCCESS;
}

int32_t HITLS_SetErrorCode(HITLS_Ctx *ctx, int32_t errorCode)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    ctx->errorCode = errorCode;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetErrorCode(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return ctx->errorCode;
}

#ifdef HITLS_TLS_FEATURE_ALPN
int32_t HITLS_GetSelectedAlpnProto(HITLS_Ctx *ctx, uint8_t **proto, uint32_t *protoLen)
{
    if (ctx == NULL || proto == NULL || protoLen == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ctx->negotiatedInfo.alpnSelected == NULL) {
        return HITLS_NULL_INPUT;
    }

    *proto = ctx->negotiatedInfo.alpnSelected;
    *protoLen = ctx->negotiatedInfo.alpnSelectedSize;

    return HITLS_SUCCESS;
}
#endif

int32_t HITLS_IsServer(const HITLS_Ctx *ctx, uint8_t *isServer)
{
    if (ctx == NULL || isServer == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isServer = 0;
    if (ctx->isClient == false) {
        *isServer = 1;
    }

    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SESSION
/* Configure the handle for the session information about the HITLS link */
int32_t HITLS_SetSession(HITLS_Ctx *ctx, HITLS_Session *session)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    /* The client and server are specified only in hitls connect/accept. Therefore, the client cannot be specified here
     */
    HITLS_SESS_Free(ctx->session);

    /* Ignore whether the HITLS_SESS_Dup return is NULL or non-NULL */
    ctx->session = HITLS_SESS_Dup(session);
    return HITLS_SUCCESS;
}

/* Obtain the session information handle and directly obtain the pointer */
HITLS_Session *HITLS_GetSession(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->session;
}

/* Obtain the handle of the copied session information */
HITLS_Session *HITLS_GetDupSession(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return HITLS_SESS_Dup(ctx->session);
}
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_GetPeerSignatureType(const HITLS_Ctx *ctx, HITLS_SignAlgo *sigType)
{
    HITLS_SignAlgo signAlg = HITLS_SIGN_BUTT;
    HITLS_HashAlgo hashAlg = HITLS_HASH_BUTT;

    if (ctx == NULL || sigType == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (CFG_GetSignParamBySchemes(ctx, ctx->peerInfo.peerSignHashAlg,
        &signAlg, &hashAlg) == false) {
        return HITLS_CONFIG_NO_SUITABLE_CIPHER_SUITE;
    }

    *sigType = signAlg;

    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_GetLocalSignScheme(const HITLS_Ctx *ctx, HITLS_SignHashAlgo *localSignScheme)
{
    if (ctx == NULL || localSignScheme == NULL) {
        return HITLS_NULL_INPUT;
    }

    *localSignScheme = ctx->negotiatedInfo.signScheme;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_GetPeerSignScheme(const HITLS_Ctx *ctx, HITLS_SignHashAlgo *peerSignScheme)
{
    if (ctx == NULL || peerSignScheme == NULL) {
        return HITLS_NULL_INPUT;
    }

    *peerSignScheme = ctx->peerInfo.peerSignHashAlg;
    return HITLS_SUCCESS;
}
#endif

int32_t HITLS_SetEcGroups(HITLS_Ctx *ctx, uint16_t *lst, uint32_t groupSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetGroups(&(ctx->config.tlsConfig), lst, groupSize);
}

int32_t HITLS_SetSigalgsList(HITLS_Ctx *ctx, const uint16_t *signAlgs, uint16_t signAlgsSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetSignature(&(ctx->config.tlsConfig), signAlgs, signAlgsSize);
}

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_GetRenegotiationSupport(const HITLS_Ctx *ctx, uint8_t *isSupportRenegotiation)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetRenegotiationSupport(&(ctx->config.tlsConfig), isSupportRenegotiation);
}
#endif

int32_t HITLS_SetEcPointFormats(HITLS_Ctx *ctx, const uint8_t *pointFormats, uint32_t pointFormatsSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetEcPointFormats(&(ctx->config.tlsConfig), pointFormats, pointFormatsSize);
}

int32_t HITLS_ClearChainCerts(HITLS_Ctx *ctx)
{
    if (ctx == NULL || ctx->config.tlsConfig.certMgrCtx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_ClearChainCerts(&(ctx->config.tlsConfig));
}

#ifdef HITLS_TLS_FEATURE_CERT_MODE
int32_t HITLS_SetClientVerifySupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetClientVerifySupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetNoClientCertSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetNoClientCertSupport(&(ctx->config.tlsConfig), support);
}
#endif
#ifdef HITLS_TLS_FEATURE_PHA
int32_t HITLS_SetPostHandshakeAuthSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetPostHandshakeAuthSupport(&(ctx->config.tlsConfig), support);
}
#endif
#ifdef HITLS_TLS_FEATURE_CERT_MODE
int32_t HITLS_SetVerifyNoneSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVerifyNoneSupport(&(ctx->config.tlsConfig), support);
}
#endif
#if defined(HITLS_TLS_FEATURE_CERT_MODE) && defined(HITLS_TLS_FEATURE_RENEGOTIATION)
int32_t HITLS_SetClientOnceVerifySupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetClientOnceVerifySupport(&(ctx->config.tlsConfig), support);
}
#endif
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
int32_t HITLS_SetDhAutoSupport(HITLS_Ctx *ctx, bool support)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetDhAutoSupport(&(ctx->config.tlsConfig), support);
}

int32_t HITLS_SetTmpDh(HITLS_Ctx *ctx, HITLS_CRYPT_Key *dhPkey)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetTmpDh(&(ctx->config.tlsConfig), dhPkey);
}
#endif
#if defined(HITLS_TLS_CONNECTION_INFO_NEGOTIATION) && defined(HITLS_TLS_FEATURE_SESSION)
HITLS_CERT_Chain *HITLS_GetPeerCertChain(const HITLS_Ctx *ctx)
{
    CERT_Pair *certPair = NULL;
    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16477, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "ctx null", 0, 0, 0, 0);
        return NULL;
    }

    int32_t ret = SESS_GetPeerCert(ctx->session, &certPair);
    if (ret != HITLS_SUCCESS || certPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16478, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ret %d, GetPeerCert fail", ret, 0, 0, 0);
        return NULL;
    }

    HITLS_CERT_Chain *certChain = SAL_CERT_PairGetChain(certPair);
    return certChain;
}
#endif
#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
HITLS_TrustedCAList *HITLS_GetClientCAList(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->isClient) {
        return ctx->peerInfo.caList;
    }
    return ctx->globalConfig->caList;
}
#endif
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_GetSecureRenegotiationSupport(const HITLS_Ctx *ctx, uint8_t *isSecureRenegotiation)
{
    if (ctx == NULL || isSecureRenegotiation == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isSecureRenegotiation = (uint8_t)ctx->negotiatedInfo.isSecureRenegotiation;
    return HITLS_SUCCESS;
}
#endif
#ifdef HITLS_TLS_MAINTAIN_KEYLOG
static int32_t Uint8ToHex(const uint8_t *srcBuf, size_t srcLen, size_t *offset,
    size_t destMaxSize, uint8_t *destBuf)
{
    if (destMaxSize < 1) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16479, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "destMaxSize err", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    size_t length = (destMaxSize - 1) / 2;
    if (destBuf == NULL || offset == NULL || srcLen == 0 || srcBuf == NULL || length < srcLen) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16480, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    /* Initialize Offset */
    size_t offsetTemp = 0u;
    /* Converting an Array to a Hexadecimal Character String */
    for (size_t i = 0u; i < srcLen; i++) {
        if (sprintf_s((char *)&destBuf[offsetTemp], (destMaxSize - offsetTemp), "%02x", srcBuf[i]) == -1) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16481, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "sprintf_s fail", 0, 0, 0, 0);
            return HITLS_INVALID_INPUT;
        }
        offsetTemp += sizeof(uint16_t);
        if (offsetTemp >= destMaxSize) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16482, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "There's not enough memory", 0, 0, 0, 0);
            return HITLS_INVALID_INPUT;
        }
    }
    /* Update Offset */
    *offset = offsetTemp;

    return HITLS_SUCCESS;
}

int32_t HITLS_LogSecret(HITLS_Ctx *ctx, const char *label, const uint8_t *secret, size_t secretLen)
{
    if (ctx == NULL || label == NULL || secret == NULL || secretLen == 0) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16483, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }
    if (ctx->globalConfig->keyLogCb == NULL) {
        return HITLS_SUCCESS;
    }
    size_t offset = 0;
    uint8_t *random = ctx->negotiatedInfo.clientRandom;
    uint32_t randomLen = RANDOM_SIZE;
    size_t labelLen = strlen(label);
    const uint8_t blankSpace = 0x20;
    // The lengths of random and secret need to be converted into hexadecimal so they are doubled.
    size_t outLen = labelLen + randomLen + randomLen + secretLen + secretLen + 3;
    uint8_t *outBuffer = (uint8_t *)BSL_SAL_Calloc((uint32_t)outLen, sizeof(uint8_t));
    if (outBuffer == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16484, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    // Combine label, random, and secret into a character string separated by spaces and end with '\0'.
    (void)memcpy_s(outBuffer, outLen, label, labelLen);
    offset += labelLen;
    outBuffer[offset++] = blankSpace;
    size_t index = 0;

    // Convert random to a hexadecimal character string.
    int32_t ret = Uint8ToHex(random, randomLen, &index, outLen - offset, &outBuffer[offset]);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16485, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "random Uint8ToHex fail", 0, 0, 0, 0);
        BSL_SAL_FREE(outBuffer);
        return ret;
    }
    offset += index;
    outBuffer[offset++] = blankSpace;

    // Convert the master key buffer to a hexadecimal character string.
    ret = Uint8ToHex(secret, secretLen, &index, outLen - offset, &outBuffer[offset]);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16486, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "secret Uint8ToHex fail", 0, 0, 0, 0);
        BSL_SAL_FREE(outBuffer);
        return ret;
    }

    ctx->globalConfig->keyLogCb(ctx, (const char *)outBuffer);

    BSL_SAL_CleanseData(outBuffer, outLen);
    BSL_SAL_FREE(outBuffer);

    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_MAINTAIN_KEYLOG */

#ifdef HITLS_TLS_FEATURE_CERT_CB
int32_t HITLS_SetCertCb(HITLS_Ctx *ctx, HITLS_CertCb certCb, void *arg)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetCertCb(&(ctx->config.tlsConfig), certCb, arg);
}
#endif /* HITLS_TLS_FEATURE_CERT_CB */