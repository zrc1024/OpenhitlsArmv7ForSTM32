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

#ifndef SAL_TIME_H
#define SAL_TIME_H

#include "hitls_build.h"
#ifdef HITLS_BSL_SAL_TIME

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "bsl_sal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_TIME_CMP_ERROR   0U   /* The comparison between two dates is incorrect. */
#define BSL_TIME_CMP_EQUAL   1U   /* The two dates are the same. */
#define BSL_TIME_DATE_BEFORE 2U   /* The first date is earlier than the second date */
#define BSL_TIME_DATE_AFTER  3U   /* The first date is later than the second date. */

#define BSL_TIME_YEAR_START 1900U
#define BSL_TIME_SYSTEM_EPOCH_YEAR 1970U
#define BSL_TIME_DAY_PER_NONLEAP_YEAR 365U

#define BSL_TIME_BIG_MONTH_DAY 31U
#define BSL_TIME_SMALL_MONTH_DAY 30U
#define BSL_TIME_LEAP_FEBRUARY_DAY 29U
#define BSL_TIME_NOLEAP_FEBRUARY_DAY 28U

#define BSL_MONTH_JAN 1U     /* January */
#define BSL_MONTH_FEB 2U     /* February */
#define BSL_MONTH_MAR 3U     /* March */
#define BSL_MONTH_APR 4U     /* April */
#define BSL_MONTH_MAY 5U     /* May */
#define BSL_MONTH_JUN 6U     /* June */
#define BSL_MONTH_JUL 7U     /* July */
#define BSL_MONTH_AUG 8U     /* August */
#define BSL_MONTH_SEM 9U     /* September */
#define BSL_MONTH_OCT 10U    /* October */
#define BSL_MONTH_NOV 11U    /* November */
#define BSL_MONTH_DEC 12U    /* December */

#define BSL_TIME_TICKS_PER_SECOND_DEFAULT 100U
#define BSL_SECOND_TRANSFER_RATIO         1000U        /* conversion ratio of microseconds -> milliseconds -> seconds */

#define BSL_UTCTIME_MAX 2005949145599L /* UTC time corresponding to December 31, 65535 23:59:59 */

bool BSL_IsLeapYear(uint32_t year);

/**
 * @brief Obtain the date in string format.
 * @param dateTime [IN] Pointer to the date structure to be converted into a string.
 * @param timeStr [OUT] Pointer to the date string buffer.
 * @param len [IN] Date string buffer length, which must be greater than 26.
 * @return BSL_SUCCESS is successfully executed.
 *         BSL_INTERNAL_EXCEPTION Execution Failure
 */
uint32_t BSL_DateToStrConvert(const BSL_TIME *dateTime, char *timeStr, size_t len);

/**
 * @brief Add the time.
 * @param date [IN]
 * @param us [IN]
 * @return BSL_SUCCESS is successfully executed.
 * For other failures, see BSL_SAL_DateToUtcTimeConvert and BSL_SAL_UtcTimeToDateConvert.
 */
uint32_t BSL_DateTimeAddUs(BSL_TIME *dateR, const BSL_TIME *dateA, uint32_t us);

/**
 * @brief Check whether the time format is correct.
 * @param dateTime [IN] Time to be checked
 * @return true  The time format is correct.
 *         false incorrect
 */
bool BSL_DateTimeCheck(const BSL_TIME *dateTime);

void BSL_SysTimeFuncUnReg(void);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_BSL_SAL_TIME */

#endif // SAL_TIME_H
