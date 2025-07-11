#include "test.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bsl_err.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "bsl_sal.h"
#include "crypt_eal_init.h"
#include "crypt_errno.h"
#include "crypt_eal_rand.h"

void PrintLastError(void) {
    const char *file = NULL;
    uint32_t line = 0;
    BSL_ERR_GetLastErrorFileLine(&file, &line); // 获取错误发生的文件名和行数
    printf("failed at file %s at line %d\n", file, (int)line);
}

void test(void) {

    BSL_ERR_Init(); // 初始化错误码模块
    // 调用算法API接口之前需要调用BSL_SAL_CallBack_Ctrl函数注册malloc和free函数。该步骤仅需执行一次
    // 如果未注册并且默认能力没有被裁剪,使用默认linux实现
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, (void *)(uintptr_t)malloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, (void *)(uintptr_t)free);
    int32_t ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU | CRYPT_EAL_INIT_PROVIDER);
    uint8_t input[] = "abc"; // Any length, for example, 100 bytes.
    uint32_t inLen = strlen(input);
    uint8_t out[32]; // SM3 digest length is 32.
    CRYPT_EAL_MdCTX *ctx = NULL;
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    if (ctx == NULL) {
        PrintLastError();
        goto EXIT;
    }
    uint32_t outLen = CRYPT_EAL_MdGetDigestSize(CRYPT_MD_SM3);
    ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(ctx, input, inLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        goto EXIT;
    }
    ret = CRYPT_EAL_MdFinal(ctx, out, &outLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        goto EXIT;
    }
    printf("SM3 hash result for \"abc\": \r\n");
    for (uint32_t i = 0; i < outLen; i++) {
        printf("%02x", out[i]);
    }
    printf("\r\n");
    uint8_t input1[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    ret = CRYPT_EAL_MdInit(ctx);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        goto EXIT;
    }
    ret = CRYPT_EAL_MdUpdate(ctx, input1, strlen(input1));
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        goto EXIT;
    }
    ret = CRYPT_EAL_MdFinal(ctx, out, &outLen);
    if (ret != CRYPT_SUCCESS) {
        PrintLastError();
        goto EXIT;
    }
    printf("SM3 hash result for \"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd\": \r\n");
    for (uint32_t i = 0; i < outLen; i++) {
        printf("%02x", out[i]);
    }
    printf("\r\n");
EXIT:
    // 释放上下文内存。
    CRYPT_EAL_RandDeinit();
    BSL_ERR_DeInit();
}