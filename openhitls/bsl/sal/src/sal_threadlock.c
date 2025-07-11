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

#include <stddef.h>
#include <pthread.h>

#include "hitls_build.h"

#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_errno.h"
#include "sal_lockimpl.h"
#include "bsl_sal.h"

static BSL_SAL_ThreadCallback g_threadCallback = {0};

int32_t BSL_SAL_ThreadLockNew(BSL_SAL_ThreadLockHandle *lock)
{
    if ((g_threadCallback.pfThreadLockNew != NULL) && (g_threadCallback.pfThreadLockNew != BSL_SAL_ThreadLockNew)) {
        return g_threadCallback.pfThreadLockNew(lock);
    }
#if defined (HITLS_BSL_SAL_LOCK) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_RwLockNew(lock);
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadReadLock(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadReadLock != NULL) && (g_threadCallback.pfThreadReadLock != BSL_SAL_ThreadReadLock)) {
        return g_threadCallback.pfThreadReadLock(lock);
    }
#if defined (HITLS_BSL_SAL_LOCK) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_RwReadLock(lock);
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadWriteLock(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadWriteLock != NULL) &&
        (g_threadCallback.pfThreadWriteLock != BSL_SAL_ThreadWriteLock)) {
        return g_threadCallback.pfThreadWriteLock(lock);
    }
#if defined (HITLS_BSL_SAL_LOCK) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_RwWriteLock(lock);
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadUnlock(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadUnlock != NULL) && (g_threadCallback.pfThreadUnlock != BSL_SAL_ThreadUnlock)) {
        return g_threadCallback.pfThreadUnlock(lock);
    }
#if defined (HITLS_BSL_SAL_LOCK) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_RwUnlock(lock);
#else
    return BSL_SUCCESS;
#endif
}

void BSL_SAL_ThreadLockFree(BSL_SAL_ThreadLockHandle lock)
{
    if ((g_threadCallback.pfThreadLockFree != NULL) && (g_threadCallback.pfThreadLockFree != BSL_SAL_ThreadLockFree)) {
        g_threadCallback.pfThreadLockFree(lock);
        return;
    }
#if defined (HITLS_BSL_SAL_LOCK) && defined(HITLS_BSL_SAL_LINUX)
    SAL_RwLockFree(lock);
#endif
}

uint64_t BSL_SAL_ThreadGetId(void)
{
    if ((g_threadCallback.pfThreadGetId != NULL) && (g_threadCallback.pfThreadGetId != BSL_SAL_ThreadGetId)) {
        return g_threadCallback.pfThreadGetId();
    }
#if defined (HITLS_BSL_SAL_THREAD) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_GetPid();
#else
    return BSL_SUCCESS;
#endif
}

int32_t BSL_SAL_ThreadRunOnce(uint32_t *onceControl, BSL_SAL_ThreadInitRoutine initFunc)
{
    if (onceControl == NULL || initFunc == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
#if defined (HITLS_BSL_SAL_THREAD) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_PthreadRunOnce(onceControl, initFunc);
#else
    if (*onceControl == 1) {
        return BSL_SUCCESS;
    }
    initFunc();
    *onceControl = 1;
    return BSL_SUCCESS;
#endif
}

int32_t SAL_ThreadCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_THREAD_GET_ID_CB_FUNC || type < BSL_SAL_THREAD_LOCK_NEW_CB_FUNC) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_THREAD_LOCK_NEW_CB_FUNC);
    ((void **)&g_threadCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}
