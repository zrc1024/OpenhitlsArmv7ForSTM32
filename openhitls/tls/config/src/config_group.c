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
#include "hitls_build.h"
#include "config_type.h"
#include "hitls_crypt_type.h"
#include "tls_config.h"
#include "hitls_error.h"
#include "crypt_algid.h"
#include "config.h"
#ifdef HITLS_TLS_FEATURE_PROVIDER
#include "securec.h"
#include "crypt_eal_provider.h"
#include "crypt_params_key.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_pkey.h"
#endif

static const uint16_t DEFAULT_GROUP_ID[] = {
    HITLS_HYBRID_X25519_MLKEM768,
    HITLS_EC_GROUP_CURVE25519,
    HITLS_EC_GROUP_SECP256R1,
    HITLS_EC_GROUP_SECP384R1,
    HITLS_EC_GROUP_SECP521R1,
    HITLS_EC_GROUP_SM2,
    HITLS_FF_DHE_2048,
    HITLS_FF_DHE_3072,
    HITLS_FF_DHE_4096,
    HITLS_FF_DHE_6144,
    HITLS_FF_DHE_8192,
};

#ifndef HITLS_TLS_FEATURE_PROVIDER
static const TLS_GroupInfo GROUP_INFO[] = {
    {
        "x25519",
        CRYPT_PKEY_PARAID_MAX,
        CRYPT_PKEY_X25519,
        128,                                    // secBits
        HITLS_EC_GROUP_CURVE25519,             // groupId
        32, 32, 0,                             // pubkeyLen=32, sharedkeyLen=32 (256 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK,  // versionBits
        false,
    },
#ifdef HITLS_TLS_FEATURE_KEM
    {
        "X25519MLKEM768",
        CRYPT_HYBRID_X25519_MLKEM768,
        CRYPT_PKEY_HYBRID_KEM,
        192,                                    // secBits
        HITLS_HYBRID_X25519_MLKEM768,          // groupId
        1184 + 32, 32 + 32, 1088 + 32,         // pubkeyLen=1216, sharedkeyLen=64, ciphertextLen=1120
        TLS13_VERSION_BIT,                     // versionBits
        true,
    },
    {
        "SecP256r1MLKEM768",
        CRYPT_HYBRID_ECDH_NISTP256_MLKEM768,
        CRYPT_PKEY_HYBRID_KEM,
        192,                                    // secBits
        HITLS_HYBRID_ECDH_NISTP256_MLKEM768,   // groupId
        1184 + 65, 32 + 32, 1088 + 65,         // pubkeyLen=1249, sharedkeyLen=64, ciphertextLen=1153
        TLS13_VERSION_BIT,                     // versionBits
        true,
    },
    {
        "SecP384r1MLKEM1024",
        CRYPT_HYBRID_ECDH_NISTP384_MLKEM1024,
        CRYPT_PKEY_HYBRID_KEM,
        256,                                    // secBits
        HITLS_HYBRID_ECDH_NISTP384_MLKEM1024,  // groupId
        1568 + 97, 32 + 48, 1568 + 97,         // pubkeyLen=1665, sharedkeyLen=80, ciphertextLen=1665
        TLS13_VERSION_BIT,                     // versionBits
        true,
    },
#endif /* HITLS_TLS_FEATURE_KEM */
    {
        "secp256r1",
        CRYPT_ECC_NISTP256, // CRYPT_ECC_NISTP256
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_SECP256R1, // groupId
        65, 32, 0, // pubkeyLen=65, sharedkeyLen=32 (256 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "secp384r1",
        CRYPT_ECC_NISTP384, // CRYPT_ECC_NISTP384
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        192, // secBits
        HITLS_EC_GROUP_SECP384R1, // groupId
        97, 48, 0, // pubkeyLen=97, sharedkeyLen=48 (384 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "secp521r1",
        CRYPT_ECC_NISTP521, // CRYPT_ECC_NISTP521
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        256, // secBits
        HITLS_EC_GROUP_SECP521R1, // groupId
        133, 66, 0, // pubkeyLen=133, sharedkeyLen=66 (521 bits)
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "brainpoolP256r1",
        CRYPT_ECC_BRAINPOOLP256R1, // CRYPT_ECC_BRAINPOOLP256R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_BRAINPOOLP256R1, // groupId
        65, 32, 0, // pubkeyLen=65, sharedkeyLen=32 (256 bits)
        TLS10_VERSION_BIT | TLS11_VERSION_BIT| TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "brainpoolP384r1",
        CRYPT_ECC_BRAINPOOLP384R1, // CRYPT_ECC_BRAINPOOLP384R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        192, // secBits
        HITLS_EC_GROUP_BRAINPOOLP384R1, // groupId
        97, 48, 0, // pubkeyLen=97, sharedkeyLen=48 (384 bits)
        TLS10_VERSION_BIT| TLS11_VERSION_BIT|TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "brainpoolP512r1",
        CRYPT_ECC_BRAINPOOLP512R1, // CRYPT_ECC_BRAINPOOLP512R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        256, // secBits
        HITLS_EC_GROUP_BRAINPOOLP512R1, // groupId
        129, 64, 0, // pubkeyLen=129, sharedkeyLen=64 (512 bits)
        TLS10_VERSION_BIT| TLS11_VERSION_BIT|TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "sm2",
        CRYPT_PKEY_PARAID_MAX, // CRYPT_PKEY_PARAID_MAX
        CRYPT_PKEY_SM2, // CRYPT_PKEY_SM2
        128, // secBits
        HITLS_EC_GROUP_SM2, // groupId
        65, 32, 0, // pubkeyLen=65, sharedkeyLen=32 (256 bits)
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe8192",
        CRYPT_DH_RFC7919_8192, // CRYPT_DH_8192
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        192, // secBits
        HITLS_FF_DHE_8192, // groupId
        1024, 1024, 0, // pubkeyLen=1024, sharedkeyLen=1024 (8192 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe6144",
        CRYPT_DH_RFC7919_6144, // CRYPT_DH_6144
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        128, // secBits
        HITLS_FF_DHE_6144, // groupId
        768, 768, 0, // pubkeyLen=768, sharedkeyLen=768 (6144 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe4096",
        CRYPT_DH_RFC7919_4096, // CRYPT_DH_4096
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        128, // secBits
        HITLS_FF_DHE_4096, // groupId
        512, 512, 0, // pubkeyLen=512, sharedkeyLen=512 (4096 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe3072",
        CRYPT_DH_RFC7919_3072, // Fixed constant name
        CRYPT_PKEY_DH,
        128,
        HITLS_FF_DHE_3072,
        384, 384, 0, // pubkeyLen=384, sharedkeyLen=384 (3072 bits)
        TLS13_VERSION_BIT,
        false,
    },
    {
        "ffdhe2048",
        CRYPT_DH_RFC7919_2048, // CRYPT_DH_2048
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        112, // secBits
        HITLS_FF_DHE_2048, // groupId
        256, 256, 0, // pubkeyLen=256, sharedkeyLen=256 (2048 bits)
        TLS13_VERSION_BIT, // versionBits
        false,
    }
};

int32_t ConfigLoadGroupInfo(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_INVALID_INPUT;
    }
    return HITLS_CFG_SetGroups(config, DEFAULT_GROUP_ID, sizeof(DEFAULT_GROUP_ID) / sizeof(DEFAULT_GROUP_ID[0]));
}

const TLS_GroupInfo *ConfigGetGroupInfo(const HITLS_Config *config, uint16_t groupId)
{
    (void)config;
    for (uint32_t i = 0; i < sizeof(GROUP_INFO) / sizeof(TLS_GroupInfo); i++) {
        if (GROUP_INFO[i].groupId == groupId) {
            return &GROUP_INFO[i];
        }
    }
    return NULL;
}

const TLS_GroupInfo *ConfigGetGroupInfoList(const HITLS_Config *config, uint32_t *size)
{
    (void)config;
    *size = sizeof(GROUP_INFO) / sizeof(GROUP_INFO[0]);
    return &GROUP_INFO[0];
}
#else

static int32_t ProviderAddGroupInfo(const BSL_Param *params, void *args)
{
    if (params == NULL || args == NULL) {
        return HITLS_INVALID_INPUT;
    }
    TLS_CapabilityData *data = (TLS_CapabilityData *)args;
    TLS_Config *config = data->config;
    TLS_GroupInfo *group = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    BSL_Param *param = NULL;
    int32_t ret = HITLS_CONFIG_ERR_LOAD_GROUP_INFO;
    if (config->groupInfolen == config->groupInfoSize) {
        void *ptr = BSL_SAL_Realloc(config->groupInfo,
            (config->groupInfoSize + TLS_CAPABILITY_LIST_MALLOC_SIZE) * sizeof(TLS_GroupInfo),
            config->groupInfoSize * sizeof(TLS_GroupInfo));
        if (ptr == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        config->groupInfo = ptr;
        (void)memset_s(config->groupInfo + config->groupInfoSize,
            TLS_CAPABILITY_LIST_MALLOC_SIZE * sizeof(TLS_GroupInfo),
            0,
            TLS_CAPABILITY_LIST_MALLOC_SIZE * sizeof(TLS_GroupInfo));
        config->groupInfoSize += TLS_CAPABILITY_LIST_MALLOC_SIZE;
    }
    
    group = config->groupInfo + config->groupInfolen;
    PROCESS_STRING_PARAM(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME, name);
    PROCESS_PARAM_UINT16(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID, groupId);
    PROCESS_PARAM_INT32(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID, paraId);
    PROCESS_PARAM_INT32(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID, algId);
    PROCESS_PARAM_INT32(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS, secBits);
    PROCESS_PARAM_UINT32(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS, versionBits);
    PROCESS_PARAM_BOOL(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM, isKem);
    PROCESS_PARAM_INT32(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_PUBKEY_LEN, pubkeyLen);
    PROCESS_PARAM_INT32(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_SHAREDKEY_LEN, sharedkeyLen);
    PROCESS_PARAM_INT32(param, group, params, CRYPT_PARAM_CAP_TLS_GROUP_CIPHERTEXT_LEN, ciphertextLen);

    ret = HITLS_SUCCESS;
    pkey = CRYPT_EAL_ProviderPkeyNewCtx(LIBCTX_FROM_CONFIG(config), group->algId, group->isKem ? CRYPT_EAL_PKEY_KEM_OPERATE : CRYPT_EAL_PKEY_EXCH_OPERATE,
        ATTRIBUTE_FROM_CONFIG(config));
    if (pkey != NULL) {
        config->groupInfolen++;
        CRYPT_EAL_PkeyFreeCtx(pkey);
        group = NULL;
    }
    
ERR:
    if (group != NULL) {
        BSL_SAL_Free(group->name);
        (void)memset_s(group, sizeof(TLS_GroupInfo), 0, sizeof(TLS_GroupInfo));
    }
    return ret;
}

static int32_t ProviderLoadGroupInfo(CRYPT_EAL_ProvMgrCtx *ctx, void *args)
{
    if (ctx == NULL || args == NULL) {
        return HITLS_INVALID_INPUT;
    }
    TLS_CapabilityData data = {
        .config = (TLS_Config *)args,
        .provMgrCtx = ctx,
    };
    return CRYPT_EAL_ProviderGetCaps(ctx, CRYPT_EAL_GET_GROUP_CAP, ProviderAddGroupInfo, &data);
}

int32_t ConfigLoadGroupInfo(HITLS_Config *config)
{
    HITLS_Lib_Ctx *libCtx = LIBCTX_FROM_CONFIG(config);
    int32_t ret = CRYPT_EAL_ProviderProcessAll(libCtx, ProviderLoadGroupInfo, config);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return HITLS_CFG_SetGroups(config, DEFAULT_GROUP_ID, sizeof(DEFAULT_GROUP_ID) / sizeof(DEFAULT_GROUP_ID[0]));
}

const TLS_GroupInfo *ConfigGetGroupInfo(const HITLS_Config *config, uint16_t groupId)
{
    for (uint32_t i = 0; i < config->groupInfolen; i++) {
        if (config->groupInfo[i].groupId == groupId) {
            return &config->groupInfo[i];
        }
    }
    return NULL;
}

const TLS_GroupInfo *ConfigGetGroupInfoList(const HITLS_Config *config, uint32_t *size)
{
    *size = config->groupInfolen;
    return config->groupInfo;
}
#endif
