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
#ifdef HITLS_BSL_LIST

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_list.h"

BslListNode *BSL_LIST_FirstNode(const BslList *list)
{
    if (list == NULL) {
        return NULL;
    }

    return list->first;
}

void *BSL_LIST_GetData(const BslListNode *pstNode)
{
    if (pstNode == NULL) {
        return NULL;
    }

    return pstNode->data;
}

BslListNode *BSL_LIST_GetNextNode(const BslList *pstList, const BslListNode *pstListNode)
{
    if (pstList == NULL) {
        return NULL;
    }

    if (pstListNode != NULL) {
        return pstListNode->next;
    }

    return pstList->first;
}

void *BSL_LIST_GetIndexNodeEx(uint32_t ulIndex, const BslListNode *pstListNode, const BslList *pstList)
{
    const BslListNode *pstTmpListNode = NULL;
    (void)pstListNode;
    if (pstList == NULL) {
        return NULL;
    }

    if (ulIndex >= (uint32_t)pstList->count) {
        return NULL;
    }

    if (pstList->first == NULL) {
        return NULL;
    }

    pstTmpListNode = pstList->first;
    for (uint32_t ulIter = 0; ulIter < ulIndex; ulIter++) {
        pstTmpListNode = pstTmpListNode->next;
        if (pstTmpListNode == NULL) {
            return NULL;
        }
    }

    return pstTmpListNode->data;
}

BslListNode *BSL_LIST_GetPrevNode(const BslListNode *pstListNode)
{
    if (pstListNode == NULL) {
        return NULL;
    }

    return pstListNode->prev;
}

void BSL_LIST_DeleteNode(BslList *pstList, const BslListNode *pstListNode, BSL_LIST_PFUNC_FREE pfFreeFunc)
{
    BslListNode *pstCurrentNode = NULL;

    if (pstList == NULL) {
        return;
    }

    pstCurrentNode = pstList->first;

    while (pstCurrentNode != NULL) {
        if (pstCurrentNode == pstListNode) {
            // found matching node, delete this node and adjust the list
            if ((pstCurrentNode->next) != NULL) {
                pstCurrentNode->next->prev = pstCurrentNode->prev;
            } else {
                pstList->last = pstCurrentNode->prev;
            }

            if ((pstCurrentNode->prev) != NULL) {
                pstCurrentNode->prev->next = pstCurrentNode->next;
            } else {
                pstList->first = pstCurrentNode->next;
            }
            if (pstCurrentNode == pstList->curr) {
                pstList->curr = pstList->curr->next;
            }
            pstList->count--;

            if (pfFreeFunc == NULL) {
                BSL_SAL_FREE(pstCurrentNode->data);
            } else {
                pfFreeFunc(pstCurrentNode->data);
            }

            BSL_SAL_FREE(pstCurrentNode);
            return;
        }

        pstCurrentNode = pstCurrentNode->next;
    }

    return;
}

void BSL_LIST_DetachNode(BslList *pstList, BslListNode **pstListNode)
{
    if (pstList == NULL || pstListNode == NULL) {
        return;
    }

    BslListNode *pstCurrentNode = pstList->first;
    while (pstCurrentNode != NULL) {
        if (pstCurrentNode == *pstListNode) {
            // found matching node, delete this node and adjust the list
            if ((pstCurrentNode->next) != NULL) {
                pstCurrentNode->next->prev = pstCurrentNode->prev;
                *pstListNode = pstCurrentNode->next; // update the current node and point it to the next node
            } else {
                pstList->last = pstCurrentNode->prev;
                *pstListNode = pstList->last;
            }

            if ((pstCurrentNode->prev) != NULL) {
                pstCurrentNode->prev->next = pstCurrentNode->next;
            } else {
                pstList->first = pstCurrentNode->next;
            }

            pstList->count--;

            BSL_SAL_FREE(pstCurrentNode);
            return;
        }

        pstCurrentNode = pstCurrentNode->next;
    }

    return;
}
#endif /* HITLS_BSL_LIST */
