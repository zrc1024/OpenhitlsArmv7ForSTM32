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
#include "bsl_sal.h"
#include "bsl_module_list.h"
#include "tls_binlog_id.h"
#include "hitls_error.h"
#include "rec.h"
#include "bsl_uio.h"
#include "record.h"

#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
int32_t REC_RetransmitListAppend(REC_Ctx *recCtx, REC_Type type, const uint8_t *msg, uint32_t len)
{
    RecRetransmitList *retransmitList = &recCtx->retransmitList;
    RecRetransmitList *retransmitNode = (RecRetransmitList *)BSL_SAL_Calloc(1u, sizeof(RecRetransmitList));
    if (retransmitNode == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17277, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Calloc fail", 0, 0, 0, 0);
        return HITLS_MEMALLOC_FAIL;
    }

    LIST_INIT(&(retransmitNode->head));
    retransmitNode->type = type;
    retransmitNode->msg = BSL_SAL_Dump(msg, len);
    if (retransmitNode->msg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17278, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "Dump fail", 0, 0, 0, 0);
        BSL_SAL_FREE(retransmitNode);
        return HITLS_MEMALLOC_FAIL;
    }
    retransmitNode->len = len;

    if (type == REC_TYPE_CHANGE_CIPHER_SPEC) {
        retransmitList->isExistCcsMsg = true;
    }

    /* insert new node */
    LIST_ADD_BEFORE(&retransmitList->head, &retransmitNode->head);
    return HITLS_SUCCESS;
}

void REC_RetransmitListClean(REC_Ctx *recCtx)
{
    ListHead *head = NULL;
    ListHead *tmpHead = NULL;
    RecRetransmitList *retransmitList = &recCtx->retransmitList;
    RecRetransmitList *retransmitNode = NULL;

    retransmitList->isExistCcsMsg = false;
    LIST_FOR_EACH_ITEM_SAFE(head, tmpHead, &(retransmitList->head)) {
        LIST_REMOVE(head);
        retransmitNode = LIST_ENTRY(head, RecRetransmitList, head);
        BSL_SAL_FREE(retransmitNode->msg);
        BSL_SAL_FREE(retransmitNode);
    }
    return;
}

void REC_RetransmitListFlush(TLS_Ctx *ctx)
{
    REC_Ctx *recCtx = ctx->recCtx;
    RecRetransmitList *retransmitList = &recCtx->retransmitList;
    RecRetransmitList *retransmitNode = NULL;

    if (retransmitList->isExistCcsMsg == true) {
        REC_ActiveOutdatedWriteState(ctx);
    }

    ListHead *head = NULL;
    ListHead *tmpHead = NULL;
    LIST_FOR_EACH_ITEM_SAFE(head, tmpHead, &(retransmitList->head)) {
        retransmitNode = LIST_ENTRY(head, RecRetransmitList, head);
        /* UDP does not fail to send. Therefore, the sending failure case does not need to be considered. */
        (void)REC_Write(ctx, retransmitNode->type, retransmitNode->msg, retransmitNode->len);
        if (retransmitNode->type == REC_TYPE_CHANGE_CIPHER_SPEC) {
            REC_DeActiveOutdatedWriteState(ctx);
        }
    }
    if (ctx->config.tlsConfig.isFlightTransmitEnable) {
        (void)BSL_UIO_Ctrl(ctx->uio, BSL_UIO_FLUSH, 0, NULL);
    }
    return;
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP */