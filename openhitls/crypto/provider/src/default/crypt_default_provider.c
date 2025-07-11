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
#ifdef HITLS_CRYPTO_PROVIDER

#include <stdint.h>
#include <string.h>
#include "bsl_sal.h"
#include "bsl_obj.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "bsl_err_internal.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_provider.h"
#include "crypt_default_provderimpl.h"
#include "crypt_default_provider.h"
#include "crypt_provider.h"
#include "crypt_params_key.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_type.h"

#define CRYPT_EAL_DEFAULT_ATTR "provider=default"

static const CRYPT_EAL_AlgInfo g_defMds[] = {
    {CRYPT_MD_MD5, g_defMdMd5, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA1, g_defMdSha1, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA224, g_defMdSha224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA256, g_defMdSha256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA384, g_defMdSha384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA512, g_defMdSha512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_224, g_defMdSha3224, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_256, g_defMdSha3256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_384, g_defMdSha3384, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHA3_512, g_defMdSha3512, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE128, g_defMdShake128, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SHAKE256, g_defMdShake256, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MD_SM3, g_defMdSm3, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};


static const CRYPT_EAL_AlgInfo g_defKdfs[] = {
    {CRYPT_KDF_SCRYPT, g_defKdfScrypt, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_PBKDF2, g_defKdfPBKdf2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_KDFTLS12, g_defKdfKdfTLS12, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_KDF_HKDF, g_defKdfHkdf, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defKeyMgmt[] = {
    {CRYPT_PKEY_DSA, g_defKeyMgmtDsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ED25519, g_defKeyMgmtEd25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_X25519, g_defKeyMgmtX25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_RSA, g_defKeyMgmtRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_DH, g_defKeyMgmtDh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDSA, g_defKeyMgmtEcdsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDH, g_defKeyMgmtEcdh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defKeyMgmtSm2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_PAILLIER, g_defKeyMgmtPaillier, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ELGAMAL, g_defKeyMgmtElGamal, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SLH_DSA, g_defKeyMgmtSlhDsa, CRYPT_EAL_DEFAULT_ATTR},
	{CRYPT_PKEY_ML_KEM, g_defKeyMgmtMlKem, CRYPT_EAL_DEFAULT_ATTR},
	{CRYPT_PKEY_ML_DSA, g_defKeyMgmtMlDsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_HYBRID_KEM, g_defKeyMgmtHybridKem, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defAsymCiphers[] = {
    {CRYPT_PKEY_RSA, g_defAsymCipherRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defAsymCipherSm2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_PAILLIER, g_defAsymCipherPaillier, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ELGAMAL, g_defAsymCipherElGamal, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defKeyExch[] = {
    {CRYPT_PKEY_X25519, g_defExchX25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_DH, g_defExchDh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDH, g_defExchEcdh, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defExchSm2, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defSigns[] = {
    {CRYPT_PKEY_DSA, g_defSignDsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ED25519, g_defSignEd25519, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_RSA, g_defSignRsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_ECDSA, g_defSignEcdsa, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SM2, g_defSignSm2, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_SLH_DSA, g_defSignSlhDsa, CRYPT_EAL_DEFAULT_ATTR},
	{CRYPT_PKEY_ML_DSA, g_defSignMlDsa, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defMacs[] = {
    {CRYPT_MAC_HMAC_MD5, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA1, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA224, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA256, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA384, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA512, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_224, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_256, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_384, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SHA3_512, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_HMAC_SM3, g_defMacHmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_CMAC_AES128, g_defMacCmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_CMAC_AES192, g_defMacCmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_CMAC_AES256, g_defMacCmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_CMAC_SM4, g_defMacCmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_CBC_MAC_SM4, g_defMacCbcMac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_SIPHASH64, g_defMacSiphash, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_SIPHASH128, g_defMacSiphash, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_GMAC_AES128, g_defMacGmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_GMAC_AES192, g_defMacGmac, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_MAC_GMAC_AES256, g_defMacGmac, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defRands[] = {
    {CRYPT_RAND_SHA1, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA224, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA256, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA384, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SHA512, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SM3, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA1, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA224, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA256, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA384, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_HMAC_SHA512, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES128_CTR, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES128_CTR_DF, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES192_CTR_DF, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_AES256_CTR_DF, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_RAND_SM4_CTR_DF, g_defRand, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defCiphers[] = {
    {CRYPT_CIPHER_AES128_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_CCM, g_defCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CCM, g_defCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CCM, g_defCcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_XTS, g_defXts, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_XTS, g_defXts, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_CHACHA20_POLY1305, g_defChaCha, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_XTS, g_defXts, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_CBC, g_defCbc, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_ECB, g_defEcb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_CTR, g_defCtr, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_GCM, g_defGcm, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_SM4_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_CFB, g_defCfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES128_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES192_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_CIPHER_AES256_OFB, g_defOfb, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defKems[] = {
    {CRYPT_PKEY_ML_KEM, g_defMlKem, CRYPT_EAL_DEFAULT_ATTR},
    {CRYPT_PKEY_HYBRID_KEM, g_defHybridKeyKem, CRYPT_EAL_DEFAULT_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_defDecoders[] = {
    {BSL_CID_DECODE_UNKNOWN, g_defPem2Der, "provider=default, inFormat=PEM, outFormat=ASN1"},
    {BSL_CID_DECODE_UNKNOWN, g_defPrvP8Enc2P8, "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_ENCRYPT, outFormat=ASN1, outType=PRIKEY_PKCS8_UNENCRYPT"},
    {CRYPT_PKEY_RSA, g_defRsaPrvDer2Key, "provider=default, inFormat=ASN1, inType=PRIKEY_RSA, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_RSA, g_defRsaPubDer2Key, "provider=default, inFormat=ASN1, inType=PUBKEY_RSA, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_ECDSA, g_defEcdsaPrvDer2Key, "provider=default, inFormat=ASN1, inType=PRIKEY_ECC, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_SM2, g_defSm2PrvDer2Key, "provider=default, inFormat=ASN1, inType=PRIKEY_ECC, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_RSA, g_defP8Der2RsaKey, "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_ECDSA, g_defP8Der2EcdsaKey, "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_SM2, g_defP8Der2Sm2Key, "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_ED25519, g_defP8Der2Ed25519Key, "provider=default, inFormat=ASN1, inType=PRIKEY_PKCS8_UNENCRYPT, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_RSA, g_defSubPubKeyDer2RsaKey, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_ECDSA, g_defSubPubKeyDer2EcdsaKey, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_SM2, g_defSubPubKeyDer2Sm2Key, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_ED25519, g_defSubPubKeyDer2Ed25519Key, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_RSA, g_defSubPubKeyWithoutSeqDer2RsaKey, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_ECDSA, g_defSubPubKeyWithoutSeqDer2EcdsaKey, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_SM2, g_defSubPubKeyWithoutSeqDer2Sm2Key, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
    {CRYPT_PKEY_ED25519, g_defSubPubKeyWithoutSeqDer2Ed25519Key, "provider=default, inFormat=ASN1, inType=PUBKEY_SUBKEY_WITHOUT_SEQ, outFormat=OBJECT, outType=LOW_KEY"},
    {BSL_CID_DECODE_UNKNOWN, g_defLowKeyObject2PkeyObject, "provider=default, inFormat=OBJECT, inType=LOW_KEY, outFormat=OBJECT, outType=HIGH_KEY"},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_DefaultProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            *algInfos = g_defCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_defKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = g_defSigns;
            break;
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = g_defAsymCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = g_defKeyExch;
            break;
        case CRYPT_EAL_OPERAID_KEM:
            *algInfos = g_defKems;
            break;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = g_defMds;
            break;
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = g_defMacs;
            break;
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = g_defKdfs;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = g_defRands;
            break;
        case CRYPT_EAL_OPERAID_DECODER:
            *algInfos = g_defDecoders;
            break;
        default:
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}

static void CRYPT_EAL_DefaultProvFree(void *provCtx)
{
    BSL_SAL_Free(provCtx);
}

#define TLS_GROUP_PARAM_COUNT 11
#define TLS_SIGN_SCHEME_PARAM_COUNT 18
typedef struct {
    const char *name;           // group name
    int32_t paraId;             // parameter id CRYPT_PKEY_ParaId
    int32_t algId;              // algorithm id CRYPT_PKEY_AlgId
    int32_t secBits;           // security bits
    uint16_t groupId;           // iana group id, HITLS_NamedGroup
    int32_t pubkeyLen;         // public key length(CH keyshare / SH keyshare)
    int32_t sharedkeyLen;      // shared key length
    int32_t ciphertextLen;     // ciphertext length(SH keyshare)
    uint32_t versionBits;       // TLS_VERSION_MASK
    bool isKem;                // true: KEM, false: KEX
} TLS_GroupInfo;

static const TLS_GroupInfo g_tlsGroupInfo[] = {
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

static int32_t BuildTlsGroupParam(const TLS_GroupInfo *groupInfo, BSL_Param *param)
{
    int32_t ret = BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_NAME, BSL_PARAM_TYPE_OCTETS_PTR,
        (void *)(uintptr_t)groupInfo->name, (uint32_t)strlen(groupInfo->name));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_CAP_TLS_GROUP_IANA_GROUP_ID, BSL_PARAM_TYPE_UINT16,
       (void *)(uintptr_t)&(groupInfo->groupId), sizeof(groupInfo->groupId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_CAP_TLS_GROUP_PARA_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->paraId), sizeof(groupInfo->paraId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_CAP_TLS_GROUP_ALG_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->algId), sizeof(groupInfo->algId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[4], CRYPT_PARAM_CAP_TLS_GROUP_SEC_BITS, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->secBits), sizeof(groupInfo->secBits));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[5], CRYPT_PARAM_CAP_TLS_GROUP_VERSION_BITS, BSL_PARAM_TYPE_UINT32,
        (void *)(uintptr_t)&(groupInfo->versionBits), sizeof(groupInfo->versionBits));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[6], CRYPT_PARAM_CAP_TLS_GROUP_IS_KEM, BSL_PARAM_TYPE_BOOL,
        (void *)(uintptr_t)&(groupInfo->isKem), sizeof(groupInfo->isKem));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[7], CRYPT_PARAM_CAP_TLS_GROUP_PUBKEY_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->pubkeyLen), sizeof(groupInfo->pubkeyLen));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[8], CRYPT_PARAM_CAP_TLS_GROUP_SHAREDKEY_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->sharedkeyLen), sizeof(groupInfo->sharedkeyLen));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[9], CRYPT_PARAM_CAP_TLS_GROUP_CIPHERTEXT_LEN, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(groupInfo->ciphertextLen), sizeof(groupInfo->ciphertextLen));
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    return BSL_SUCCESS;
}

static int32_t CryptGetGroupCaps(CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    for (size_t i = 0; i < sizeof(g_tlsGroupInfo) / sizeof(g_tlsGroupInfo[0]); i++) {
        BSL_Param param[TLS_GROUP_PARAM_COUNT] = {0};
        int32_t ret = BuildTlsGroupParam(&g_tlsGroupInfo[i], param);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = cb(param, args);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}
typedef struct {
    const char *name;                   // name
    uint16_t signatureScheme;           // HITLS_SignHashAlgo, IANA specified
    int32_t keyType;                    // HITLS_CERT_KeyType
    int32_t paraId;                     // CRYPT_PKEY_ParaId
    int32_t signHashAlgId;              // combined sign hash algorithm id
    int32_t signAlgId;                  // CRYPT_PKEY_AlgId
    int32_t hashAlgId;                  // CRYPT_MD_AlgId
    int32_t secBits;                    // security bits
    uint32_t certVersionBits;           // TLS_VERSION_MASK
    uint32_t chainVersionBits;          // TLS_VERSION_MASK
} TLS_SigSchemeInfo;

static const TLS_SigSchemeInfo g_signSchemeInfo[] = {
    {
        "ecdsa_secp521r1_sha512",
        CERT_SIG_SCHEME_ECDSA_SECP521R1_SHA512,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_ECC_NISTP521,
        BSL_CID_ECDSAWITHSHA512,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "ecdsa_secp384r1_sha384",
        CERT_SIG_SCHEME_ECDSA_SECP384R1_SHA384,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_ECC_NISTP384,
        BSL_CID_ECDSAWITHSHA384,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "ed25519",
        CERT_SIG_SCHEME_ED25519,
        TLS_CERT_KEY_TYPE_ED25519,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ED25519,
        HITLS_SIGN_ED25519,
        HITLS_HASH_SHA_512,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "ecdsa_secp256r1_sha256",
        CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_ECC_NISTP256,
        BSL_CID_ECDSAWITHSHA256,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "sm2_sm3",
        CERT_SIG_SCHEME_SM2_SM3,
        TLS_CERT_KEY_TYPE_SM2,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SM2DSAWITHSM3,
        HITLS_SIGN_SM2,
        HITLS_HASH_SM3,
        128,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT,
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT,
    },
    {
        "rsa_pss_pss_sha512",
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA512,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_pss_sha384",
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA384,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_pss_sha256",
        CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256,
        TLS_CERT_KEY_TYPE_RSA_PSS,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_rsae_sha512",
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_512,
        256,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_rsae_sha384",
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_384,
        192,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pss_rsae_sha256",
        CERT_SIG_SCHEME_RSA_PSS_RSAE_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_RSASSAPSS,
        HITLS_SIGN_RSA_PSS,
        HITLS_HASH_SHA_256,
        128,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "rsa_pkcs1_sha512",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA512,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA512WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "dsa_sha512",
        CERT_SIG_SCHEME_DSA_SHA512,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA512,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_512,
        256,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha384",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA384,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA384WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "dsa_sha384",
        CERT_SIG_SCHEME_DSA_SHA384,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA384,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_384,
        192,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha256",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA256,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA256WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS_VERSION_MASK | DTLS_VERSION_MASK,
    },
    {
        "dsa_sha256",
        CERT_SIG_SCHEME_DSA_SHA256,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA256,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_256,
        128,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "ecdsa_sha224",
        CERT_SIG_SCHEME_ECDSA_SHA224,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ECDSAWITHSHA224,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha224",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA224,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA224WITHRSAENCRYPTION,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "dsa_sha224",
        CERT_SIG_SCHEME_DSA_SHA224,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA224,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA_224,
        112,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "ecdsa_sha1",
        CERT_SIG_SCHEME_ECDSA_SHA1,
        TLS_CERT_KEY_TYPE_ECDSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_ECDSAWITHSHA1,
        HITLS_SIGN_ECDSA,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "rsa_pkcs1_sha1",
        CERT_SIG_SCHEME_RSA_PKCS1_SHA1,
        TLS_CERT_KEY_TYPE_RSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_SHA1WITHRSA,
        HITLS_SIGN_RSA_PKCS1_V15,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },
    {
        "dsa_sha1",
        CERT_SIG_SCHEME_DSA_SHA1,
        TLS_CERT_KEY_TYPE_DSA,
        CRYPT_PKEY_PARAID_MAX,
        BSL_CID_DSAWITHSHA1,
        HITLS_SIGN_DSA,
        HITLS_HASH_SHA1,
        -1,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
        TLS12_VERSION_BIT | DTLS12_VERSION_BIT,
    },

};

static int32_t BuildTlsSigAlgParam(const TLS_SigSchemeInfo *sigSchemeInfo, BSL_Param *param)
{
    int32_t ret = BSL_PARAM_InitValue(&param[0], CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_NAME,
        BSL_PARAM_TYPE_OCTETS_PTR, (void *)(uintptr_t)sigSchemeInfo->name, (uint32_t)strlen(sigSchemeInfo->name));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[1], CRYPT_PARAM_CAP_TLS_SIGNALG_IANA_SIGN_ID, BSL_PARAM_TYPE_UINT16,
        (void *)(uintptr_t)&(sigSchemeInfo->signatureScheme), sizeof(sigSchemeInfo->signatureScheme));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[2], CRYPT_PARAM_CAP_TLS_SIGNALG_KEY_TYPE, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->keyType), sizeof(sigSchemeInfo->keyType));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[3], CRYPT_PARAM_CAP_TLS_SIGNALG_PARA_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->paraId), sizeof(sigSchemeInfo->paraId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[4], CRYPT_PARAM_CAP_TLS_SIGNALG_SIGNWITHMD_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->signHashAlgId), sizeof(sigSchemeInfo->signHashAlgId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[5], CRYPT_PARAM_CAP_TLS_SIGNALG_SIGN_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->signAlgId), sizeof(sigSchemeInfo->signAlgId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[6], CRYPT_PARAM_CAP_TLS_SIGNALG_MD_ID, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->hashAlgId), sizeof(sigSchemeInfo->hashAlgId));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[7], CRYPT_PARAM_CAP_TLS_SIGNALG_SEC_BITS, BSL_PARAM_TYPE_INT32,
        (void *)(uintptr_t)&(sigSchemeInfo->secBits), sizeof(sigSchemeInfo->secBits));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = BSL_PARAM_InitValue(&param[8], CRYPT_PARAM_CAP_TLS_SIGNALG_CERT_VERSION_BITS,
        BSL_PARAM_TYPE_UINT32, (void *)(uintptr_t)&(sigSchemeInfo->certVersionBits),
        sizeof(sigSchemeInfo->certVersionBits));
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    return BSL_PARAM_InitValue(&param[9], CRYPT_PARAM_CAP_TLS_SIGNALG_CHAIN_VERSION_BITS,
        BSL_PARAM_TYPE_UINT32, (void *)(uintptr_t)&(sigSchemeInfo->chainVersionBits),
        sizeof(sigSchemeInfo->chainVersionBits));
}

static int32_t CryptGetSignAlgCaps(CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    for (size_t i = 0; i < sizeof(g_signSchemeInfo) / sizeof(g_signSchemeInfo[0]); i++) {
        BSL_Param param[TLS_SIGN_SCHEME_PARAM_COUNT] = {0};
        int32_t ret = BuildTlsSigAlgParam(&g_signSchemeInfo[i], param);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
        ret = cb(param, args);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}

static int32_t CRYPT_EAL_DefaultProvGetCaps(void *provCtx, int32_t cmd, CRYPT_EAL_ProcessFuncCb cb, void *args)
{
    (void)provCtx;
    if (cb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_EAL_GET_GROUP_CAP:
            return CryptGetGroupCaps(cb, args);
        case CRYPT_EAL_GET_SIGALG_CAP:
            return CryptGetSignAlgCaps(cb, args);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_NOT_SUPPORT);
            return CRYPT_NOT_SUPPORT;
    }
}

static CRYPT_EAL_Func g_defProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_DefaultProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_DefaultProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    {CRYPT_EAL_PROVCB_GETCAPS, CRYPT_EAL_DefaultProvGetCaps},
    CRYPT_EAL_FUNC_END
};

#ifdef HITLS_CRYPTO_ENTROPY
static void *g_providerSeedCtx = NULL;
static CRYPT_RandSeedMethod g_providerSeedMethod = {0};

int32_t CRYPT_EAL_ProviderGetSeed(CRYPT_RandSeedMethod **method, void **seedCtx)
{
    if (method == NULL || seedCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    *method = &g_providerSeedMethod;
    *seedCtx = g_providerSeedCtx;
    return CRYPT_SUCCESS;
}
#endif

int32_t CRYPT_EAL_DefaultProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    (void)param;
    void *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtrlCb mgrCtrl = NULL;
    int32_t index = 0;
    int32_t ret;
    while (capFuncs[index].id != 0) {
        switch (capFuncs[index].id) {
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
            case CRYPT_EAL_CAP_GETENTROPY:
                g_providerSeedMethod.getEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANENTROPY:
                g_providerSeedMethod.cleanEntropy = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_GETNONCE:
                g_providerSeedMethod.getNonce = capFuncs[index].func;
                break;
            case CRYPT_EAL_CAP_CLEANNONCE:
                g_providerSeedMethod.cleanNonce = capFuncs[index].func;
                break;
#endif
            case CRYPT_EAL_CAP_MGRCTXCTRL:
            mgrCtrl = capFuncs[index].func;
                break;
            default:
                break;
        }
        index++;
    }
    if (mgrCtrl == NULL) {
        return CRYPT_PROVIDER_NOT_SUPPORT;
    }
#ifdef HITLS_CRYPTO_ENTROPY_DEFAULT
	ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETSEEDCTX, &g_providerSeedCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
#endif
    ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETLIBCTX, &libCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    CRYPT_EAL_DefProvCtx *temp = BSL_SAL_Malloc(sizeof(CRYPT_EAL_DefProvCtx));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    temp->libCtx = libCtx;
    *provCtx = temp;
    *outFuncs = g_defProvOutFuncs;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_PROVIDER */
