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
#if defined(HITLS_BSL_SAL_LINUX) && defined(HITLS_BSL_SAL_TIME)

#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include "bsl_sal.h"
#include "sal_time.h"
#include "bsl_errno.h"

int64_t TIME_GetSysTime(void)
{
    return (int64_t)time(NULL);
}

uint32_t TIME_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len)
{
    struct tm timeStruct = {0};
    timeStruct.tm_year = (int32_t)dateTime->year - (int32_t)BSL_TIME_YEAR_START;
    timeStruct.tm_mon  = (int32_t)dateTime->month - 1;
    timeStruct.tm_mday = (int32_t)dateTime->day;
    timeStruct.tm_hour = (int32_t)dateTime->hour;
    timeStruct.tm_min  = (int32_t)dateTime->minute;
    timeStruct.tm_sec  = (int32_t)dateTime->second;
    if (asctime_r(&timeStruct, timeStr) != NULL) {
        return BSL_SUCCESS;
    }
    (void)len;
    return BSL_INTERNAL_EXCEPTION;
}

uint32_t TIME_SysTimeGet(BSL_TIME *sysTime)
{
    time_t currentTime;
    struct timeval tv;
    uint32_t ret = BSL_SAL_ERR_BAD_PARAM;

    tzset();
    currentTime = (time_t)BSL_SAL_CurrentSysTimeGet();
    if (currentTime != 0) {
        ret = BSL_SAL_UtcTimeToDateConvert(currentTime, sysTime);
        if (ret == BSL_SUCCESS) {
            /* milliseconds : non-thread safe */
            (void)gettimeofday(&tv, NULL);
            sysTime->millSec = (uint16_t)tv.tv_usec / 1000U;  /* 1000 is multiple */
            sysTime->microSec = (uint32_t)tv.tv_usec % 1000U; /* 1000 is multiple */
        }
    }

    return ret;
}

uint32_t TIME_UtcTimeToDateConvert(int64_t utcTime, BSL_TIME *sysTime)
{
    struct tm tempTime;
    time_t utcTimeTmp = (time_t)utcTime;
    if (gmtime_r(&utcTimeTmp, &tempTime) == NULL) {
        return BSL_SAL_ERR_BAD_PARAM;
    }

    sysTime->year = (uint16_t)((uint16_t)tempTime.tm_year + BSL_TIME_YEAR_START); /* 1900 is base year */
    sysTime->month = (uint8_t)((uint8_t)tempTime.tm_mon + 1U);
    sysTime->day = (uint8_t)tempTime.tm_mday;
    sysTime->hour = (uint8_t)tempTime.tm_hour;
    sysTime->minute = (uint8_t)tempTime.tm_min;
    sysTime->second = (uint8_t)tempTime.tm_sec;
    sysTime->millSec = 0U;
    sysTime->microSec = 0U;
    return BSL_SUCCESS;
}

void SAL_Sleep(uint32_t time)
{
    sleep(time);
}

long SAL_Tick(void)
{
    struct tms buf = {0};
    clock_t tickCount = times(&buf);
    return (long)tickCount;
}

long SAL_TicksPerSec(void)
{
    return sysconf(_SC_CLK_TCK);
}
#endif
