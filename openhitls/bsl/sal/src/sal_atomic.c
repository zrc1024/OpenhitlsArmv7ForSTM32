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

#include "sal_atomic.h"
#include "bsl_errno.h"

int BSL_SAL_AtomicAdd(int *val, int amount, int *ref, BSL_SAL_ThreadLockHandle lock)
{
    if (val == NULL || ref == NULL) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(lock);
    if (ret != 0) {
        return ret;
    }
    *val += amount;
    *ref = *val;
    return BSL_SAL_ThreadUnlock(lock);
}
