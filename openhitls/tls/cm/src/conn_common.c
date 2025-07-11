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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "tls.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_type.h"
#ifdef HITLS_TLS_FEATURE_PSK
#include "hitls_psk.h"
#endif
#ifdef HITLS_TLS_FEATURE_ALPN
#include "hitls_alpn.h"
#endif
#include "hs.h"
#include "alert.h"
#include "app.h"
#ifdef HITLS_TLS_FEATURE_SESSION
#include "session.h"
#endif
#ifdef HITLS_TLS_FEATURE_INDICATOR
#include "indicator.h"
#endif
#include "rec.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "hs_ctx.h"
#include "conn_common.h"


static const char *GetStateString(uint32_t state)
{
    /* * Unknown status */
    if (state >= CM_STATE_END) {
        return "Unknown";
    }

    static const char *stateMachineStr[CM_STATE_END] = {
        [CM_STATE_IDLE] = "Idle",
        [CM_STATE_RENEGOTIATION] = "SecRenego",
        [CM_STATE_HANDSHAKING] = "Handshaking",
        [CM_STATE_TRANSPORTING] = "Transporting",
        [CM_STATE_ALERTING] = "Alerting",
        [CM_STATE_ALERTED] = "Alerted",
        [CM_STATE_CLOSED] = "Closed",
    };
    /* Current status */
    return stateMachineStr[state];
}

void ChangeConnState(HITLS_Ctx *ctx, CM_State state)
{
    if (GetConnState(ctx) == state) {
        return;
    }

    ctx->preState = ctx->state;
    ctx->state = state;
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15839, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "state [%s]",
        GetStateString(ctx->preState));
    BSL_LOG_BINLOG_VARLEN(BINLOG_ID15840, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "change to [%s]",
        GetStateString(state));
    return;
}

int32_t CommonEventInAlertingState(HITLS_Ctx *ctx)
{
    /* The alerting state indicates that an alert message is being sent over the current link. In this case, the alert
     * message should firstly be sent and then the link status will be updated */
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(ctx, &alertInfo);

    if (alertInfo.level > ALERT_LEVEL_FATAL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16458, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "level error", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret = ALERT_Flush(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16459, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "ALERT_Flush fail", 0, 0, 0, 0);
        /* If the alert fails to be sent, return error code to user */
        return ret;
    }
#ifdef HITLS_TLS_FEATURE_INDICATOR
    uint8_t data[2] = {alertInfo.level, alertInfo.description};
    INDICATOR_MessageIndicate(1, HS_GetVersion(ctx), REC_TYPE_ALERT, data, sizeof(data) / sizeof(uint8_t), ctx,
        ctx->config.tlsConfig.msgArg);

    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_WRITE_ALERT,
        (int32_t)(((uint32_t)(alertInfo.level) << INDICATOR_ALERT_LEVEL_OFFSET) | (uint32_t)(alertInfo.description)));
#endif
    /* If a fatal alert is sent, the link must be disconnected */
    if (alertInfo.level == ALERT_LEVEL_FATAL) {
#ifdef HITLS_TLS_FEATURE_SESSION
        SESS_Disable(ctx->session);
#endif
        ChangeConnState(ctx, CM_STATE_ALERTED);
        return HITLS_SUCCESS;
    }

    /* If the close_notify message is sent, the link must be disconnected */
    if (alertInfo.description == ALERT_CLOSE_NOTIFY) {
        if (ctx->userShutDown) {
            ChangeConnState(ctx, CM_STATE_CLOSED);
        } else {
            ChangeConnState(ctx, CM_STATE_ALERTED);
        }
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
        /* If the previous state was not in the transporting state, the connection should be closed directly, and
         * reading and writing are not allowed. */
        if (ctx->preState != CM_STATE_TRANSPORTING) {
            ctx->shutdownState |= HITLS_RECEIVED_SHUTDOWN;
        }
        return HITLS_SUCCESS;
    }

    /* Other warning alerts will not terminate the connection and the status will be restored to the previous status */
    ctx->state = ctx->preState;
    ALERT_CleanInfo(ctx);
    return HITLS_SUCCESS;
}

static int32_t AlertRecvProcess(HITLS_Ctx *ctx, const ALERT_Info *alertInfo)
{
#ifdef HITLS_TLS_FEATURE_INDICATOR
    uint8_t data[2] = {alertInfo->level, alertInfo->description};
    INDICATOR_MessageIndicate(0, HS_GetVersion(ctx), REC_TYPE_ALERT, data, sizeof(data) / sizeof(uint8_t), ctx,
        ctx->config.tlsConfig.msgArg);

    INDICATOR_StatusIndicate(ctx, INDICATE_EVENT_READ_ALERT,
        (int32_t)(((uint32_t)(alertInfo->level) << INDICATOR_ALERT_LEVEL_OFFSET) | (uint32_t)(alertInfo->description)));
#endif
    /* If a fatal alert is received, the link must be disconnected */
    if (alertInfo->level == ALERT_LEVEL_FATAL) {
#ifdef HITLS_TLS_FEATURE_SESSION
        SESS_Disable(ctx->session);
#endif
        ChangeConnState(ctx, CM_STATE_ALERTED);
        ctx->shutdownState |= HITLS_RECEIVED_SHUTDOWN;
        return HITLS_SUCCESS;
    }

    /* If a warning alert is received, the connection must be terminated if the alert is close_notify. Otherwise, the
     * alert will not be processed  */
    ALERT_CleanInfo(ctx);
    if (alertInfo->description != ALERT_CLOSE_NOTIFY) {
        /* Other warning alerts will not be processed */
        return HITLS_SUCCESS;
    }

    ctx->shutdownState |= HITLS_RECEIVED_SHUTDOWN;

    /* In quiet disconnection mode, close_notify does not need to be sent */
    if (ctx->config.tlsConfig.isQuietShutdown) {
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
        ChangeConnState(ctx, CM_STATE_ALERTED);
        return HITLS_SUCCESS;
    }

    if ((ctx->shutdownState & HITLS_SENT_SHUTDOWN) == 0) {
        if (GetConnState(ctx) != CM_STATE_TRANSPORTING) {
            /* If the close_notify message is received, the close_notify message must be sent to the peer */
            ALERT_Send(ctx, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
            ChangeConnState(ctx, CM_STATE_ALERTING);
            int32_t ret = ALERT_Flush(ctx);
            if (ret != HITLS_SUCCESS) {
                return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16460, "ALERT_Flush fail");
            }
            ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
        } else {
            ChangeConnState(ctx, CM_STATE_CLOSED);
        }
    }

    if (ctx->state != CM_STATE_CLOSED) {
        ChangeConnState(ctx, CM_STATE_ALERTED);
    }
    return HITLS_CM_LINK_CLOSED;
}

int32_t AlertEventProcess(HITLS_Ctx *ctx)
{
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(ctx, &alertInfo);

    /* An alert message is received. */
    if (alertInfo.flag == ALERT_FLAG_RECV) {
        return AlertRecvProcess(ctx, &alertInfo);
    }

    /* An alert message needs to be sent */
    if (alertInfo.flag == ALERT_FLAG_SEND) {
        ChangeConnState(ctx, CM_STATE_ALERTING);
        return CommonEventInAlertingState(ctx);
    }

    return HITLS_SUCCESS;
}

int32_t CommonEventInHandshakingState(HITLS_Ctx *ctx)
{
    int32_t ret;
    int32_t alertRet;

    do {
        ret = HS_DoHandshake(ctx);
        if (ret == HITLS_SUCCESS) {
            /* The handshake has completed */
            break;
        }
        if (ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG && REC_GetUnexpectedMsgType(ctx) == REC_TYPE_APP) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16489, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "The app message is received in the handshake state", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        }
        if (!ALERT_GetFlag(ctx)) {
            /* The handshake fails, but no alert is received. Return the error code to the user */
            return ret;
        }

        if (ALERT_HaveExceeded(ctx, MAX_ALERT_COUNT)) {
            /* If there are multiple consecutive alerts, the link is abnormal and needs to be terminated. */
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
            alertRet = AlertEventProcess(ctx);
            return (alertRet == HITLS_SUCCESS) ? ret : alertRet;
        }

        alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            /* If the alert message fails to be sent, return the error code to the user */
            return alertRet;
        }

        /* If fatal alert or close_notify has been processed, the handshake must be terminated */
        if (ctx->state == CM_STATE_ALERTED) {
            return ret;
        }
    } while (ret != HITLS_SUCCESS);

    // If HS_DoHandshake returns success, the connection has been established.
    ChangeConnState(ctx, CM_STATE_TRANSPORTING);

    /* In the UDP scenario, peer may retransmit the finished message even if the local endpoint is connected
     * Therefore, the hsCtx is not released in the UDP scenario */
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        HS_DeInit(ctx);
    }

    return HITLS_SUCCESS;
}

const HITLS_Config *HITLS_GetConfig(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return &(ctx->config.tlsConfig);
}

HITLS_Config *HITLS_GetGlobalConfig(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->globalConfig;
}

#ifdef HITLS_TLS_PROTO_TLS13
int32_t HITLS_ClearTLS13CipherSuites(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_ClearTLS13CipherSuites(&(ctx->config.tlsConfig));
}
#endif
int32_t HITLS_SetCipherSuites(HITLS_Ctx *ctx, const uint16_t *cipherSuites, uint32_t cipherSuitesSize)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetCipherSuites(&(ctx->config.tlsConfig), cipherSuites, cipherSuitesSize);
}
#ifdef HITLS_TLS_FEATURE_ALPN
int32_t HITLS_SetAlpnProtos(HITLS_Ctx *ctx, const uint8_t *protos, uint32_t protosLen)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetAlpnProtos(&(ctx->config.tlsConfig), protos, protosLen);
}
#endif
#ifdef HITLS_TLS_FEATURE_PSK
int32_t HITLS_SetPskClientCallback(HITLS_Ctx *ctx, HITLS_PskClientCb cb)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetPskClientCallback(&(ctx->config.tlsConfig), cb);
}

int32_t HITLS_SetPskServerCallback(HITLS_Ctx *ctx, HITLS_PskServerCb cb)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetPskServerCallback(&(ctx->config.tlsConfig), cb);
}

#if defined(HITLS_TLS_PROTO_TLS_BASIC) || defined(HITLS_TLS_PROTO_DTLS12)
int32_t HITLS_SetPskIdentityHint(HITLS_Ctx *ctx, const uint8_t *identityHint, uint32_t identityHintLen)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetPskIdentityHint(&(ctx->config.tlsConfig), identityHint, identityHintLen);
}
#endif
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
const HITLS_Cipher *HITLS_GetCurrentCipher(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return &(ctx->negotiatedInfo.cipherSuiteInfo);
}
#endif

int32_t HITLS_IsClient(const HITLS_Ctx *ctx, bool *isClient)
{
    if (ctx == NULL || isClient == NULL) {
        return HITLS_NULL_INPUT;
    }
    *isClient = ctx->isClient;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_GetHsRandom(const HITLS_Ctx *ctx, uint8_t *out, uint32_t *outlen, bool isClient)
{
    if (ctx == NULL || outlen == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (*outlen == 0) {
        *outlen = RANDOM_SIZE;
        return HITLS_SUCCESS;
    }

    uint32_t resLen = *outlen;

    if (resLen > RANDOM_SIZE) {
        resLen = RANDOM_SIZE;
    }

    if (out == NULL) {
        *outlen = resLen;
        return HITLS_SUCCESS;
    }

    if (isClient) {
        (void)memcpy_s(out, resLen, ctx->negotiatedInfo.clientRandom, resLen);
    } else {
        (void)memcpy_s(out, resLen, ctx->negotiatedInfo.serverRandom, resLen);
    }

    *outlen = resLen;
    return HITLS_SUCCESS;
}

/*
 * If current endpoint is a server and the server preference is supported, the local server group array is preferred.
 * If current endpoint is a server and the client preference is supported, the peer (client)group array is preferred
 */
static uint16_t FindPreference(const HITLS_Ctx *ctx, int32_t nmatch, bool *haveFound)
{
    uint16_t ans = 0;
    uint32_t preferGroupSize = 0;
    uint32_t secondPreferGroupSize = 0;
    uint16_t *preferGroups = NULL;
    uint16_t *secondPreferGroups = NULL;
    uint32_t peerGroupSize = ctx->peerInfo.groupsSize;
    uint32_t localGroupSize = ctx->config.tlsConfig.groupsSize;
    uint16_t *peerGroups = ctx->peerInfo.groups;
    uint16_t *localGroups = ctx->config.tlsConfig.groups;
    bool chooseServerPre = ctx->config.tlsConfig.isSupportServerPreference;
    uint16_t intersectionCnt = 0;

    preferGroupSize = (chooseServerPre == true) ? localGroupSize : peerGroupSize;
    secondPreferGroupSize = (chooseServerPre == true) ? peerGroupSize : localGroupSize;
    preferGroups = (chooseServerPre == true) ? localGroups : peerGroups;
    secondPreferGroups = (chooseServerPre == true) ? peerGroups : localGroups;

    for (uint32_t i = 0; i < preferGroupSize; i++) {
        for (uint32_t j = 0; j < secondPreferGroupSize; j++) {
            if (preferGroups[i] == secondPreferGroups[j]) {
                intersectionCnt++;
                // Currently, the preferred nmatch is already matched
                bool isMatch = (intersectionCnt == nmatch);
                *haveFound = (isMatch ? true : (*haveFound));
                ans = (isMatch ? preferGroups[i] : ans);
                // Jump out of the inner village and change
                break;
            }
        }
        if (*haveFound) {
            // Exit a loop
            break;
        }
    }
    if (nmatch == GET_GROUPS_CNT) {
        return (uint16_t)intersectionCnt;
    }
    return ans;
}

/*
 * nmatch Value range: - 1 or a positive integer
 * This function can be invoked only after negotiation and can be invoked only by the server.
 * When nmatch is a positive integer, check the intersection of groups on the client and server, and return the nmatch
 * group in the intersection by groupId. If the value of nmatch is - 1, the number of intersection groups on the client
 * and server is returned based on groupId.
 */
int32_t HITLS_GetSharedGroup(const HITLS_Ctx *ctx, int32_t nmatch, uint16_t *groupId)
{
    bool haveFound = false;
    if (ctx == NULL || groupId == NULL) {
        return HITLS_NULL_INPUT;
    }
    *groupId = 0;
    // Check the value range of nmatch and whether the interface is invoked by the server. The client cannot invoke the
    // interface because the client cannot sense the peerInfo.
    if (nmatch < GET_GROUPS_CNT || nmatch == 0 || ctx->isClient) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16464, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "invalid input", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }

    *groupId = FindPreference(ctx, nmatch, &haveFound);

    if (nmatch == GET_GROUPS_CNT) {
        // The value of *groupId is the number of intersections
        return HITLS_SUCCESS;
    } else if (haveFound == false) {
        // If nmatch is not equal to GET_GROUPS_CNT and haveFound is false
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16465, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input err", 0, 0, 0, 0);
        return HITLS_INVALID_INPUT;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_CONNECTION_INFO_NEGOTIATION */

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
int32_t HITLS_GetPeerFinishVerifyData(const HITLS_Ctx *ctx, void *buf, uint32_t bufLen, uint32_t *dataLen)
{
    uint32_t verifyDataSize, bufSize;
    const uint8_t *verifyData = NULL;

    if (ctx == NULL || buf == NULL || bufLen == 0 || dataLen == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ctx->isClient) {
        verifyDataSize = ctx->negotiatedInfo.serverVerifyDataSize;
        verifyData = ctx->negotiatedInfo.serverVerifyData;
    } else {
        verifyDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
        verifyData = ctx->negotiatedInfo.clientVerifyData;
    }

    if (bufLen > verifyDataSize) {
        bufSize = verifyDataSize;
    } else {
        bufSize = bufLen;
    }

    (void)memcpy_s(buf, bufLen, verifyData, bufSize);
    *dataLen = verifyDataSize;
    return HITLS_SUCCESS;
}

int32_t HITLS_GetFinishVerifyData(const HITLS_Ctx *ctx, void *buf, uint32_t bufLen, uint32_t *dataLen)
{
    uint32_t verifyDataSize, bufSize;
    const uint8_t *verifyData = NULL;

    if (ctx == NULL || buf == NULL || bufLen == 0 || dataLen == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ctx->isClient) {
        verifyDataSize = ctx->negotiatedInfo.clientVerifyDataSize;
        verifyData = ctx->negotiatedInfo.clientVerifyData;
    } else {
        verifyDataSize = ctx->negotiatedInfo.serverVerifyDataSize;
        verifyData = ctx->negotiatedInfo.serverVerifyData;
    }

    if (bufLen > verifyDataSize) {
        bufSize = verifyDataSize;
    } else {
        bufSize = bufLen;
    }

    (void)memcpy_s(buf, bufLen, verifyData, bufSize);
    *dataLen = verifyDataSize;
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */

#ifdef HITLS_TLS_PROTO_ALL
int32_t HITLS_GetVersionSupport(const HITLS_Ctx *ctx, uint32_t *version)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_GetVersionSupport(&(ctx->config.tlsConfig), version);
}

int32_t HITLS_SetVersionSupport(HITLS_Ctx *ctx, uint32_t version)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVersionSupport(&(ctx->config.tlsConfig), version);
}
#endif

#ifdef HITLS_TLS_SUITE_KX_RSA
int32_t HITLS_SetNeedCheckPmsVersion(HITLS_Ctx *ctx, bool needCheck)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetNeedCheckPmsVersion(&(ctx->config.tlsConfig), needCheck);
}
#endif

#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
static bool HS_IsAppDataAllowed(TLS_Ctx *ctx)
{
    uint32_t hsState = HS_GetState(ctx);
    if (ctx->isClient) {
        if (hsState == TRY_RECV_SERVER_HELLO) {
            return true;
        }
    } else {
        if (hsState == TRY_RECV_CLIENT_HELLO) {
            return true;
        }
    }
    return false;
}

void InnerRenegotiationProcess(HITLS_Ctx *ctx)
{
    ALERT_Info alertInfo = { 0 };
    ALERT_GetInfo(ctx, &alertInfo);
    if ((alertInfo.level == ALERT_LEVEL_WARNING) && (alertInfo.description == ALERT_NO_RENEGOTIATION)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16234, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "Receive no renegotiation alert during renegotiation process", 0, 0, 0, 0);
        ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
    }
}

int32_t CommonEventInRenegotiationState(HITLS_Ctx *ctx)
{
    int32_t ret;

    do {
        ret = HS_DoHandshake(ctx);
        if (ret == HITLS_SUCCESS) {
            /* The handshake has completed */
            break;
        }

        if (ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG && REC_GetUnexpectedMsgType(ctx) == REC_TYPE_APP) {
            if (ctx->allowAppOut && HS_IsAppDataAllowed(ctx)) {
                return ret;
            }
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17106, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "The app message is received in the handshake state", 0, 0, 0, 0);
            ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        }

        if (!ALERT_GetFlag(ctx)) {
            /* The handshake fails, but no alert is displayed. The system returns a message
             * to the user for processing */
            return ret;
        }
        InnerRenegotiationProcess(ctx);
        if (ALERT_HaveExceeded(ctx, MAX_ALERT_COUNT)) {
            /* If multiple consecutive alerts exist, the link is abnormal and needs to be terminated */
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
        }

        int32_t alertRet = AlertEventProcess(ctx);
        if (alertRet != HITLS_SUCCESS) {
            if (alertRet != HITLS_CM_LINK_CLOSED) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16466, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "AlertEventProcess fail", 0, 0, 0, 0);
            }
            /* If the alert fails to be sent, the system sends a message to the user for processing */
            return alertRet;
        }

        /*
            If fatal alert or close_notify has been processed, the handshake must be terminated.
        */
        if (ctx->state == CM_STATE_ALERTED) {
            return ret;
        }
    } while (ret != HITLS_SUCCESS);

    // If the HS_DoHandshake message is returned successfully, the link has been terminated.
    ChangeConnState(ctx, CM_STATE_TRANSPORTING);

    /* In the UDP scenario, the peer end may retransmit the finished message even if the local end is terminated.
     * Therefore, the hsCtx is not released in the UDP scenario */
    if (!BSL_UIO_GetUioChainTransportType(ctx->uio, BSL_UIO_UDP)) {
        HS_DeInit(ctx);
    }

    // Prevent the renegotiation status from being changed after the Hello Request message is sent.
    if (ctx->negotiatedInfo.isRenegotiation) {
        ctx->userRenego = false;
        ctx->negotiatedInfo.isRenegotiation = false; /* Disabling renegotiation */
        BSL_LOG_BINLOG_FIXLEN(
            BINLOG_ID15952, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN, "renegotiate completed.", 0, 0, 0, 0);
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */

#if defined(HITLS_TLS_FEATURE_PSK) && defined(HITLS_TLS_PROTO_TLS13)
int32_t HITLS_SetPskFindSessionCallback(HITLS_Ctx *ctx, HITLS_PskFindSessionCb cb)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetPskFindSessionCallback(&(ctx->config.tlsConfig), cb);
}

int32_t HITLS_SetPskUseSessionCallback(HITLS_Ctx *ctx, HITLS_PskUseSessionCb cb)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    return HITLS_CFG_SetPskUseSessionCallback(&(ctx->config.tlsConfig), cb);
}
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_GetNegotiateGroup(const HITLS_Ctx *ctx, uint16_t *group)
{
    if (ctx == NULL || group == NULL) {
        return HITLS_NULL_INPUT;
    }

    *group = ctx->negotiatedInfo.negotiatedGroup;
    return HITLS_SUCCESS;
}
#endif