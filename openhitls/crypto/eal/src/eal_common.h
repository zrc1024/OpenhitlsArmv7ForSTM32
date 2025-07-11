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

#ifndef EAL_COMMON_H
#define EAL_COMMON_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_EAL

#include <stdint.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define EAL_ERR_REPORT(oper, type, id, err) \
    do { \
        EAL_EventReport((oper), (type), (id), (err)); \
        BSL_ERR_PUSH_ERROR((err)); \
    } while (0)

void EAL_EventReport(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_EAL

#endif // EAL_COMMON_H
