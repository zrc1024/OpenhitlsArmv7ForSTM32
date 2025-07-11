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

#ifndef SAL_TIMEIMPL_H
#define SAL_TIMEIMPL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_TIME

#include <stdint.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct {
    BslSalGetSysTime pfGetSysTime;
    BslSalDateToStrConvert pfDateToStrConvert;
    BslSalSysTimeGet pfSysTimeGet;
    BslSalUtcTimeToDateConvert pfUtcTimeToDateConvert;
    BslSalSleep pfSleep;
    BslSalTick pfTick;
    BslSalTicksPerSec pfTicksPerSec;
} BSL_SAL_TimeCallback;

int32_t SAL_TimeCallback_Ctrl(BSL_SAL_CB_FUNC_TYPE type, void *funcCb);

#ifdef HITLS_BSL_SAL_LINUX
int64_t TIME_GetSysTime(void);
uint32_t TIME_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len);
uint32_t TIME_SysTimeGet(BSL_TIME *sysTime);
uint32_t TIME_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime);
void SAL_Sleep(uint32_t time);
long SAL_Tick(void);
long SAL_TicksPerSec(void);
#endif

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_BSL_SAL_TIME
#endif // SAL_TIMEIMPL_H

