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
#include "securec.h"
#include "hitls_build.h"
#include "bsl_log_internal.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "bsl_binlog_id.h"
#include "sal_memimpl.h"

static BSL_SAL_MemCallback g_memCallback = {0};

void *BSL_SAL_Malloc(uint32_t size)
{
    // When size is 0, malloc of different systems may return NULL or non-NULL. Here, a definite result is required.
    // If the callback is registered, everything is determined by the callback.
    if (g_memCallback.pfMalloc != NULL && g_memCallback.pfMalloc != BSL_SAL_Malloc) {
        return g_memCallback.pfMalloc(size);
    }
    if (size == 0) {
        return NULL;
    }
#if defined(HITLS_BSL_SAL_MEM) && defined(HITLS_BSL_SAL_LINUX)
    return SAL_MallocImpl(size);
#else
    return NULL;
#endif
}

void BSL_SAL_Free(void *value)
{
    if (g_memCallback.pfFree == NULL || g_memCallback.pfFree == BSL_SAL_Free) {
#if defined(HITLS_BSL_SAL_MEM) && defined(HITLS_BSL_SAL_LINUX)
        SAL_FreeImpl(value);
#endif
        return;
    }
    g_memCallback.pfFree(value);
}

void *BSL_SAL_Calloc(uint32_t num, uint32_t size)
{
    if (num == 0 || size == 0) {
        return BSL_SAL_Malloc(0);
    }
    if (num > UINT32_MAX / size) { // process the rewinding according to G.INT.02 in the HW C Coding Specifications V5.1
        return NULL;
    }
    uint32_t blockSize = num * size;
    uint8_t *ptr = BSL_SAL_Malloc(blockSize);
    if (ptr == NULL) {
        return NULL;
    }
    // If the value is greater than SECUREC_MEM_MAX_LEN, segment processing is required.
    // This is because memset_s can process only the value which the size is SECUREC_MEM_MAX_LEN.
    uint32_t offset = 0;
    while (blockSize > SECUREC_MEM_MAX_LEN) {
        if (memset_s(&ptr[offset], SECUREC_MEM_MAX_LEN, 0, SECUREC_MEM_MAX_LEN) != EOK) {
            BSL_SAL_FREE(ptr);
            return NULL;
        }
        offset += SECUREC_MEM_MAX_LEN;
        blockSize -= SECUREC_MEM_MAX_LEN;
    }
    if (memset_s(&ptr[offset], blockSize, 0, blockSize) != EOK) {
        BSL_SAL_FREE(ptr);
        return NULL;
    }
    return ptr;
}

void *BSL_SAL_Realloc(void *addr, uint32_t newSize, uint32_t oldSize)
{
    if (addr == NULL) {
        return BSL_SAL_Malloc(newSize);
    }
    uint32_t minSize = (oldSize > newSize) ? newSize : oldSize;

    void *ptr = BSL_SAL_Malloc(newSize);
    if (ptr == NULL) {
        return NULL;
    }

    if (memcpy_s(ptr, newSize, addr, minSize) != EOK) {
        BSL_SAL_FREE(ptr);
    } else {
        BSL_SAL_FREE(addr);
    }

    return ptr;
}

void *BSL_SAL_Dump(const void *src, uint32_t size)
{
    if (src == NULL) {
        return NULL;
    }
    void *ptr = BSL_SAL_Malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    if (memcpy_s(ptr, size, src, size) != EOK) {
        BSL_SAL_FREE(ptr);
        return NULL;
    }

    return ptr;
}

int32_t SAL_MemCallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb)
{
    if (type > BSL_SAL_MEM_FREE || type < BSL_SAL_MEM_MALLOC) {
        return BSL_SAL_ERR_BAD_PARAM;
    }
    uint32_t offset = (uint32_t)(type - BSL_SAL_MEM_MALLOC);
    ((void **)&g_memCallback)[offset] = funcCb;
    return BSL_SUCCESS;
}

#if !defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O3")
#endif
#define CLEAN_THRESHOLD_SIZE 16UL

static void CleanSensitiveDataLess16Byte(void *buf, uint32_t bufLen)
{
    uint8_t *tmp = (uint8_t *)buf;
    switch (bufLen) {
        case 16: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 15: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 14: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 13: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 12: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 11: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 10: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 9: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 8: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 7: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 6: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 5: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 4: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 3: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 2: *(tmp++) = (uint8_t)0;
        /* FALLTHRU */
        case 1: *(tmp) = (uint8_t)0;
        /* FALLTHRU */
        default:
            break;
    }
}

static void CleanSensitiveData(void *buf, uint32_t bufLen)
{
    uint8_t *tmp = (uint8_t *)buf;
    uint32_t boundOpt;

    if (((uintptr_t)buf & 0x3) == 0) { // buf & 0x3, used to determine whether 4-byte alignment
        // shift rightwards by 4 bits and then leftwards by 4 bits, which is used to calculate an integer multiple of 16
        boundOpt = (bufLen >> 4) << 4;
        for (uint32_t i = 0; i < boundOpt; i += 16) { // Clear 16 pieces of memory each time.
            uint32_t *ctmp = (uint32_t *)(tmp + i);
            ctmp[0] = 0;
            ctmp[1] = 0;
            ctmp[2] = 0;
            ctmp[3] = 0;
        }
    } else {
        // shifted rightward by 2 bits and then left by 2 bits, used to calculate an integer multiple of 4.
        boundOpt = (bufLen >> 2) << 2;
        for (uint32_t i = 0; i < boundOpt; i += 4) { // Clear 4 pieces of memory each time.
            tmp[i] = 0;
            tmp[i + 1] = 0;
            tmp[i + 2] = 0;
            tmp[i + 3] = 0;
        }
    }
    for (uint32_t i = boundOpt; i < bufLen; ++i) {
        tmp[i] = 0;
    }
}

void BSL_SAL_CleanseData(void *ptr, uint32_t size)
{
    if (ptr == NULL) {
        return;
    }
    if (size > CLEAN_THRESHOLD_SIZE) {
        CleanSensitiveData(ptr, size);
    } else {
        CleanSensitiveDataLess16Byte(ptr, size);
    }
}

void BSL_SAL_ClearFree(void *ptr, uint32_t size)
{
    if (ptr == NULL) {
        return;
    }
    if (size != 0) {
        BSL_SAL_CleanseData(ptr, size);
    }
    BSL_SAL_FREE(ptr);
}

#if !defined(__clang__)
#pragma GCC pop_options
#endif
