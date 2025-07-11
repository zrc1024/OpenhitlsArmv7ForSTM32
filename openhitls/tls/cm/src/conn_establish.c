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
#include "bsl_err_internal.h"
#include "hitls.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "tls.h"
#include "hs.h"
#include "alert.h"
#include "conn_init.h"
#include "conn_common.h"
#include "rec.h"
#include "app.h"
#include "bsl_uio.h"
#include "record.h"
#include "hs_ctx.h"
#include "hs_state_recv.h"
#include "hs_state_send.h"
#include "hs_common.h"

#ifdef HITLS_TLS_PROTO_DTLS12
#define DTLS_MIN_MTU 256    /* Minimum MTU setting size */
#endif
#define DATA_MAX_LENGTH 1024
static int32_t ConnectEventInIdleState(HITLS_Ctx *ctx)
{
    ctx->isClient = true; // Set the configuration as a client

    int32_t ret = CONN_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16487, "CONN_Init fail");
    }

    ChangeConnState(ctx, CM_STATE_HANDSHAKING);

    // In idle state, after initialization, the handshake process is directly started. Therefore, the handshake status
    // function is directly invoked.
    return CommonEventInHandshakingState(ctx);
}

static int32_t AcceptEventInIdleState(HITLS_Ctx *ctx)
{
    ctx->isClient = false; // Set the configuration as the server

    int32_t ret = CONN_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16488, "CONN_Init fail");
    }

    ChangeConnState(ctx, CM_STATE_HANDSHAKING);

    // In idle state, after initialization, the handshake process is directly started. Therefore, the handshake status
    // function is directly invoked.
    return CommonEventInHandshakingState(ctx);
}

static int32_t EstablishEventInTransportingState(HITLS_Ctx *ctx)
{
    (void)ctx;
    // In the renegotiation state, the renegotiation handshake procedure is started.
    return HITLS_SUCCESS;
}

static int32_t EstablishEventInRenegotiationState(HITLS_Ctx *ctx)
{
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    // In the renegotiation state, the renegotiation handshake procedure is started.
    int32_t ret = CommonEventInRenegotiationState(ctx);
    if (ret != HITLS_SUCCESS) {
        if (ret == HITLS_REC_NORMAL_RECV_UNEXPECT_MSG && ctx->state != CM_STATE_ALERTED) {
            // In this case, the HITLS initiates renegotiation, but the peer end does not respond to the renegotiation
            // request but returns an APP message. In this case, the success message should be returned.
            return HITLS_SUCCESS;
        }
        return ret;
    }
    return HITLS_SUCCESS;
#else
    (void)ctx;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15405, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
        "invalid conn states %d", CM_STATE_RENEGOTIATION, NULL, NULL, NULL);
    return HITLS_INTERNAL_EXCEPTION;
#endif
}

static int32_t CloseEventInRenegotiationState(HITLS_Ctx *ctx)
{
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
    if ((ctx->shutdownState & HITLS_SENT_SHUTDOWN) == 0) {
        ALERT_Send(ctx, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
        int32_t ret = ALERT_Flush(ctx);
        if (ret != HITLS_SUCCESS) {
            ChangeConnState(ctx, CM_STATE_ALERTED);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16528, "ALERT_Flush fail");
        }
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
    }
    /* In the renegotiation state, if the HITLS_Close function is called, the connection is directly disconnected
     * and read/write operations are not allowed. */
    ctx->shutdownState |= HITLS_RECEIVED_SHUTDOWN;
    ChangeConnState(ctx, CM_STATE_CLOSED);
    return HITLS_SUCCESS;
#else
    (void)ctx;
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15406, BSL_LOG_LEVEL_FATAL, BSL_LOG_BINLOG_TYPE_RUN,
        "invalid conn states %d", CM_STATE_RENEGOTIATION, NULL, NULL, NULL);
    return HITLS_INTERNAL_EXCEPTION;
#endif
}

static int32_t EstablishEventInAlertedState(HITLS_Ctx *ctx)
{
    (void)ctx;
    // Directly return a message indicating that the link status is abnormal.
    return HITLS_CM_LINK_FATAL_ALERTED;
}

static int32_t EstablishEventInClosedState(HITLS_Ctx *ctx)
{
    (void)ctx;
    // Directly return a message indicating that the link status is abnormal.
    return HITLS_CM_LINK_CLOSED;
}

static int32_t CloseEventInIdleState(HITLS_Ctx *ctx)
{
    ChangeConnState(ctx, CM_STATE_CLOSED);
    ctx->shutdownState |= (HITLS_SENT_SHUTDOWN | HITLS_RECEIVED_SHUTDOWN);
    return HITLS_SUCCESS;
}

static int32_t CloseEventInHandshakingState(HITLS_Ctx *ctx)
{
    if ((ctx->shutdownState & HITLS_SENT_SHUTDOWN) == 0) {
        ALERT_Send(ctx, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
        int32_t ret = ALERT_Flush(ctx);
        if (ret != HITLS_SUCCESS) {
            ChangeConnState(ctx, CM_STATE_ALERTED);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16463, "ALERT_Flush fail");
        }
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
    }
    /* In the handshaking state, if the close function is called, the connection is directly disconnected
     * and read/write operations are not allowed. */
    ctx->shutdownState |= HITLS_RECEIVED_SHUTDOWN;
    ChangeConnState(ctx, CM_STATE_CLOSED);
    return HITLS_SUCCESS;
}

static int32_t CloseEventInTransportingState(HITLS_Ctx *ctx)
{
    if ((ctx->shutdownState & HITLS_SENT_SHUTDOWN) == 0) {
        ALERT_Send(ctx, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
        int32_t ret = ALERT_Flush(ctx);
        if (ret != HITLS_SUCCESS) {
            ChangeConnState(ctx, CM_STATE_ALERTING);
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16490, "ALERT_Flush fail");
        }
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
    }

    ChangeConnState(ctx, CM_STATE_CLOSED);
    return HITLS_SUCCESS;
}

static int32_t CloseEventInAlertingState(HITLS_Ctx *ctx)
{
    /* If there are fatal alerts that are not sent, the system continues to send the alert. Otherwise, the system sends
     * the close_notify alert */
    ALERT_Send(ctx, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
    return CommonEventInAlertingState(ctx);
}

static int32_t CloseEventInAlertedState(HITLS_Ctx *ctx)
{
    /*
     * 1. Receive a fatal alert from the peer end.
     * 2. A fatal alert has been sent to the peer end.
     * 3. Receive the close notification from the peer end.
     */
    // Read and write operations are not allowed in the alerted state
    ChangeConnState(ctx, CM_STATE_CLOSED);
    ctx->shutdownState |= (HITLS_SENT_SHUTDOWN | HITLS_RECEIVED_SHUTDOWN);
    return HITLS_SUCCESS;
}

static int32_t CloseEventInClosedState(HITLS_Ctx *ctx)
{
    int32_t ret;

    /* When a user invokes the close function for the first time, a close notify message is sent to the peer end. When
     * the user invokes the close function for the second time, the user attempts to receive the close notify message.
     */
    if ((ctx->shutdownState & HITLS_RECEIVED_SHUTDOWN) == 0) {
        uint8_t data[DATA_MAX_LENGTH];  // Discard the received APP message.
        uint32_t readLen = 0;

        ALERT_CleanInfo(ctx);

        ret = APP_Read(ctx, data, sizeof(data), &readLen);
        if (ret == HITLS_SUCCESS) {
            return HITLS_SUCCESS;
        }

        if (ALERT_GetFlag(ctx) == false) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16491, "Read fail");
        }

        int32_t alertRet = AlertEventProcess(ctx);
        if (alertRet == HITLS_CM_LINK_CLOSED) {
            return HITLS_SUCCESS;
        }
        if (alertRet != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(alertRet, BINLOG_ID16492, "AlertEventProcess fail");
        }
        return ret;
    }

    if ((ctx->shutdownState & HITLS_SENT_SHUTDOWN) == 0) {
        ALERT_Send(ctx, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
        ret = ALERT_Flush(ctx);
        if (ret != HITLS_SUCCESS) {
            ChangeConnState(ctx, CM_STATE_ALERTING);
            return ret;
        }
        ctx->shutdownState |= HITLS_SENT_SHUTDOWN;
    }

    ChangeConnState(ctx, CM_STATE_CLOSED);
    return HITLS_SUCCESS;
}

// Check and process the CTX status before HITLS_Connect and HITLS_Accept.
int32_t ProcessCtxState(HITLS_Ctx *ctx)
{
    int32_t ret;

    if (ctx == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16493, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        return HITLS_NULL_INPUT;
    }

    /* Process the unsent alert message first, and then enter the corresponding state processing function based on the
     * processing result */
    if (GetConnState(ctx) == CM_STATE_ALERTING) {
        ret = CommonEventInAlertingState(ctx);
        if (ret != HITLS_SUCCESS) {
            /* If the alert fails to be sent, a response is returned to the user */
            return ret;
        }
    }

    if ((GetConnState(ctx) >= CM_STATE_END) || (GetConnState(ctx) == CM_STATE_ALERTING)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16494, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "internal exception occurs", 0, 0, 0, 0);
        /* If the alert message is sent successfully, the system switches to another state. Otherwise, an internal
         * exception occurs */
        return HITLS_INTERNAL_EXCEPTION;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_SetEndPoint(HITLS_Ctx *ctx, bool isClient)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (GetConnState(ctx) != CM_STATE_IDLE) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }

    ctx->isClient = isClient;

    int32_t ret = CONN_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    ChangeConnState(ctx, CM_STATE_HANDSHAKING);
    return HITLS_SUCCESS;
}

static int32_t ProcessEvent(HITLS_Ctx *ctx, ManageEventProcess proc)
{
    return proc(ctx);
}

int32_t HITLS_Connect(HITLS_Ctx *ctx)
{
    int32_t ret = ProcessCtxState(ctx);
    // Process the alerting state
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ctx->allowAppOut = false;

    ManageEventProcess connectEventProcess[CM_STATE_END] = {
        ConnectEventInIdleState,
        CommonEventInHandshakingState,
        EstablishEventInTransportingState,
        EstablishEventInRenegotiationState,
        NULL,  // The alerting phase has been processed in the ProcessCtxState function
        EstablishEventInAlertedState,
        EstablishEventInClosedState
    };

    ManageEventProcess proc = connectEventProcess[GetConnState(ctx)];
    return ProcessEvent(ctx, proc);
}

int32_t HITLS_Accept(HITLS_Ctx *ctx)
{
    int32_t ret = ProcessCtxState(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ctx->allowAppOut = false;
#ifdef HITLS_TLS_FEATURE_PHA
    ret = CommonCheckPostHandshakeAuth(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
#endif
    ManageEventProcess acceptEventProcess[CM_STATE_END] = {
        AcceptEventInIdleState,
        CommonEventInHandshakingState,
        EstablishEventInTransportingState,
        EstablishEventInRenegotiationState,
        NULL,
        EstablishEventInAlertedState,
        EstablishEventInClosedState
    };

    ManageEventProcess proc = acceptEventProcess[GetConnState(ctx)];
    return ProcessEvent(ctx, proc);
}

int32_t HITLS_Close(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    ctx->userShutDown = 1;

    if (ctx->config.tlsConfig.isQuietShutdown) {
        ctx->shutdownState |= (HITLS_SENT_SHUTDOWN | HITLS_RECEIVED_SHUTDOWN);
        ChangeConnState(ctx, CM_STATE_CLOSED);
        return HITLS_SUCCESS;
    }

    ManageEventProcess closeEventProcess[CM_STATE_END] = {
        CloseEventInIdleState,
        CloseEventInHandshakingState,  // Notify is sent to the peer end when the close interface is invoked during and
                                        // after link establishment.
        CloseEventInTransportingState,  // Therefore, the same function is used for processing.
        CloseEventInRenegotiationState, // In the renegotiation process, invoking the close function also sends a notify
                                        // message to the peer end.
        CloseEventInAlertingState,
        CloseEventInAlertedState,
        CloseEventInClosedState};

    if (GetConnState(ctx) >= CM_STATE_END) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16497, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "internal exception occurs", 0, 0, 0, 0);
        return HITLS_INTERNAL_EXCEPTION;
    }

    int32_t ret;

    do {
        ManageEventProcess proc = closeEventProcess[GetConnState(ctx)];
        ret = ProcessEvent(ctx, proc);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    } while (GetConnState(ctx) != CM_STATE_CLOSED);

    return HITLS_SUCCESS;
}

int32_t HITLS_GetError(const HITLS_Ctx *ctx, int32_t ret)
{
    if (ctx == NULL) {
        /* Unknown error */
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_ERR_SYSCALL, BINLOG_ID16498, "ctx null");
    }

    /* No internal error occurs in the SSL */
    if (ret == HITLS_SUCCESS) {
        return HITLS_SUCCESS;
    }
    if (ret == HITLS_CALLBACK_CLIENT_HELLO_RETRY) {
        return HITLS_WANT_CLIENT_HELLO_CB;
    }
    if (ret == HITLS_CALLBACK_CERT_RETRY) {
        return HITLS_WANT_X509_LOOKUP;
    }
    /* HANDSHAKING state */
    if (ctx->state == CM_STATE_HANDSHAKING) {
        /* In non-blocking mode, I/O read/write failure is acceptable and link establishment is allowed */
        if (ret == HITLS_REC_NORMAL_IO_BUSY || ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            return (ctx->isClient == true) ? HITLS_WANT_CONNECT : HITLS_WANT_ACCEPT;
        }

        /* Unacceptable exceptions occur on the underlying I/O */
        if (ret == HITLS_REC_ERR_IO_EXCEPTION) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_ERR_SYSCALL, BINLOG_ID16499, "Unacceptable exceptions occured");
        }

        /* The TLS protocol is incorrect */
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_ERR_TLS, BINLOG_ID16500, "TLS protocol err");
    }

    /* TRANSPORTING state */
    if (ctx->state == CM_STATE_TRANSPORTING) {
        /* An I/O read/write failure occurs in non-blocking mode. This failure is acceptable and data can be written */
        if (ret == HITLS_REC_NORMAL_IO_BUSY) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_WANT_WRITE, BINLOG_ID16501, "This failure is acceptable");
        }

        /* An I/O read/write failure occurs in non-blocking mode. This failure is acceptable and data can be read
         * continuously */
        if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_WANT_READ, BINLOG_ID16502, "This failure is acceptable");
        }

        /* Unacceptable exceptions occur on the underlying I/O */
        if (ret == HITLS_REC_ERR_IO_EXCEPTION) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_ERR_SYSCALL, BINLOG_ID16503, "Unacceptable exceptions occured");
        }

        /* The TLS protocol is incorrect */
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_ERR_TLS, BINLOG_ID16504, "TLS protocol err");
    }

    /* ALERTING state */
    if (ctx->state == CM_STATE_ALERTING) {
        if (ret == HITLS_REC_NORMAL_IO_BUSY) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_WANT_WRITE, BINLOG_ID16505, "This failure is acceptable");
        }

        if (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_WANT_READ, BINLOG_ID16506, "This failure is acceptable");
        }
    }

    /* ALERTED state ,indicating that the TLS protocol is faulty and the link is abnormal */
    if (ctx->state == CM_STATE_ALERTED) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_ERR_TLS, BINLOG_ID16507, "TLS protocol is faulty");
    }

    /* Unknown error */
    return RETURN_ERROR_NUMBER_PROCESS(HITLS_ERR_SYSCALL, BINLOG_ID16508, "unknown error");
}

#ifdef HITLS_TLS_CONFIG_STATE
int32_t HITLS_IsHandShakeDone(const HITLS_Ctx *ctx, uint8_t *isDone)
{
    if (ctx == NULL || isDone == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isDone = 0;
    if (ctx->state == CM_STATE_TRANSPORTING) {
        *isDone = 1;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_GetHandShakeState(const HITLS_Ctx *ctx, uint32_t *state)
{
    if (ctx == NULL || state == NULL) {
        return HITLS_NULL_INPUT;
    }

    uint32_t hsState = TLS_IDLE;
    /* In initialization state */
    if (ctx->state == CM_STATE_IDLE) {
        hsState = TLS_IDLE;
    }

    /* The link has been set up */
    if (ctx->state == CM_STATE_TRANSPORTING) {
        hsState = TLS_CONNECTED;
    }

    /* The link is being established. If hsctx is not empty, obtain the status */
    if (ctx->state == CM_STATE_HANDSHAKING ||
        ctx->state == CM_STATE_RENEGOTIATION) {
        hsState = HS_GetState(ctx);
    }

    if (ctx->state == CM_STATE_ALERTING) {
        /* If hsCtx is not empty, it indicates that the link is being established. Obtain the corresponding status */
        if (ctx->hsCtx != NULL) {
            hsState = HS_GetState(ctx);
        } else {
            /* After the link is established, the hsCtx is released. In this case, the hsCtx is in connected state */
            hsState = TLS_CONNECTED;
        }
    }

    if (ctx->state == CM_STATE_ALERTED || ctx->state == CM_STATE_CLOSED) {
        if (ctx->preState == CM_STATE_IDLE && ctx->hsCtx == NULL) {
            hsState = TLS_IDLE;
        } else if (ctx->hsCtx != NULL) {
            /* If the value of ctx->hsCtx is not NULL, it indicates that the link is being established */
            hsState = HS_GetState(ctx);
        } else {
            /* If hsCtx is NULL, the link has been established */
            hsState = TLS_CONNECTED;
        }
    }

    *state = hsState;
    return HITLS_SUCCESS;
}

int32_t HITLS_IsHandShaking(const HITLS_Ctx *ctx, uint8_t *isHandShaking)
{
    if (ctx == NULL || isHandShaking == NULL) {
        return HITLS_NULL_INPUT;
    }

    *isHandShaking = 0;
    uint32_t state = GetConnState(ctx);
    if ((state == CM_STATE_HANDSHAKING) || (state == CM_STATE_RENEGOTIATION)) {
        *isHandShaking = 1;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_IsBeforeHandShake(const HITLS_Ctx *ctx, uint8_t *isBefore)
{
    if (ctx == NULL || isBefore == NULL) {
        return HITLS_NULL_INPUT;
    }
    *isBefore = 0;
    if (GetConnState(ctx) == CM_STATE_IDLE) {
        *isBefore = 1;
    }
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_CONFIG_STATE */
#ifdef HITLS_TLS_PROTO_DTLS12
int32_t HITLS_SetMtu(HITLS_Ctx *ctx, long mtu)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (mtu < DTLS_MIN_MTU) {
        return HITLS_CONFIG_INVALID_LENGTH;
    }

    ctx->config.pmtu = (uint16_t)mtu;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONNECTION_INFO_NEGOTIATION
int32_t HITLS_GetClientVersion(const HITLS_Ctx *ctx, uint16_t *clientVersion)
{
    if (ctx == NULL || clientVersion == NULL) {
        return HITLS_NULL_INPUT;
    }
    *clientVersion = ctx->negotiatedInfo.clientVersion;
    return HITLS_SUCCESS;
}
#endif

#ifdef HITLS_TLS_CONFIG_STATE
const char *HITLS_GetStateString(uint32_t state)
{
    return HS_GetStateStr(state);
}
#endif

int32_t HITLS_DoHandShake(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ctx->isClient) {
        return HITLS_Connect(ctx);
    } else {
        return HITLS_Accept(ctx);
    }
}
#ifdef HITLS_TLS_FEATURE_KEY_UPDATE
/* The updateType types are as follows: HITLS_UPDATE_NOT_REQUESTED (0), HITLS_UPDATE_REQUESTED (1) or
 * HITLS_KEY_UPDATE_REQ_END(255). The local end sends 1 and the peer end sends 0 to the local end. The local end sends 0
 * and the peer end does not send 0 to the local end.
 */
int32_t HITLS_KeyUpdate(HITLS_Ctx *ctx, uint32_t updateType)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    // Check whether the version is TLS1.3, whether the current status is transporting, and whether update is allowed.
    int32_t ret = HS_CheckKeyUpdateState(ctx, updateType);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    ctx->keyUpdateType = updateType;
    ctx->isKeyUpdateRequest = true;
    ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15955, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_Init fail when start keyupdate.", 0, 0, 0, 0);
        return ret;
    }
    // Successfully sendKeyUpdate. Set isKeyUpdateRequest to false and keyUpdateType to HITLS_KEY_UPDATE_REQ_END.
    ChangeConnState(ctx, CM_STATE_HANDSHAKING);
    HS_ChangeState(ctx, TRY_SEND_KEY_UPDATE);

    return HITLS_SUCCESS;
}

int32_t HITLS_GetKeyUpdateType(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (ctx->isKeyUpdateRequest) {
        return (int32_t)ctx->keyUpdateType;
    }

    return HITLS_KEY_UPDATE_REQ_END;
}
#endif
#ifdef HITLS_TLS_FEATURE_RENEGOTIATION
static int32_t CheckRenegotiateValid(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    uint8_t isSupport = false;

    (void)HITLS_GetRenegotiationSupport(ctx, &isSupport);
    /* Renegotiation is disabled */
    if (isSupport == false) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16071, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "forbid renegotiate.", 0, 0, 0, 0);
        return HITLS_CM_LINK_UNSUPPORT_SECURE_RENEGOTIATION;
    }

    /* If the version is TLS1.3 or the current link does not support security renegotiation, the system returns. */
    if ((ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) || (!ctx->negotiatedInfo.isSecureRenegotiation)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15953, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "unsupported renegotiate.", 0, 0, 0, 0);
        return HITLS_CM_LINK_UNSUPPORT_SECURE_RENEGOTIATION;
    }

    /* If the link is not established, renegotiation cannot be performed. */
    if ((ctx->state != CM_STATE_TRANSPORTING) && (ctx->state != CM_STATE_RENEGOTIATION)) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15954, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "please complete the link establishment first.", 0, 0, 0, 0);
        return HITLS_CM_LINK_UNESTABLISHED;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_Renegotiate(HITLS_Ctx *ctx)
{
    int32_t ret = CheckRenegotiateValid(ctx);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (ctx->negotiatedInfo.isRenegotiation) {
        /* If the current state is renegotiation, no change is made. */
        return HITLS_SUCCESS;
    }

    ctx->negotiatedInfo.isRenegotiation = true; /* Start renegotiation */

    if (ctx->hsCtx != NULL) {
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
        /* The retransmission queue needs to be cleared in the dtls over UDP scenario. */
        REC_RetransmitListClean(ctx->recCtx);
#endif
        HS_DeInit(ctx);
    }

    ret = HS_Init(ctx);
    if (ret != HITLS_SUCCESS) {
        ctx->negotiatedInfo.isRenegotiation = false; /* renegotiation fails */
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15955, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "HS_Init fail when start renegotiate.", 0, 0, 0, 0);
        return ret;
    }

    ctx->userRenego = true; /* renegotiation initiated by the local end */
    ctx->negotiatedInfo.renegotiationNum++;
    ChangeConnState(ctx, CM_STATE_RENEGOTIATION);
    return HITLS_SUCCESS;
}
#endif /* HITLS_TLS_FEATURE_RENEGOTIATION */

#ifdef HITLS_TLS_FEATURE_PHA
int32_t HITLS_VerifyClientPostHandshake(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (ctx->isClient) {
        return HITLS_INVALID_INPUT;
    }
    if (ctx->state != CM_STATE_TRANSPORTING || ctx->phaState != PHA_EXTENSION) {
        return HITLS_MSG_HANDLE_STATE_ILLEGAL;
    }
    ctx->phaState = PHA_PENDING;
    return HITLS_SUCCESS;
}
#endif