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

#include "crypt_eal_implprovider.h"
#include "crypt_dsa.h"
#include "crypt_rsa.h"
#include "crypt_ecdsa.h"
#include "crypt_sm2.h"
#include "crypt_curve25519.h"
#include "crypt_slh_dsa.h"
#include "crypt_mldsa.h"

const CRYPT_EAL_Func g_defSignDsa[] = {
#ifdef HITLS_CRYPTO_DSA
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_DSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_DSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_DSA_VerifyData},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignEd25519[] = {
#ifdef HITLS_CRYPTO_ED25519
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_CURVE25519_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_CURVE25519_Verify},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignRsa[] = {
#ifdef HITLS_CRYPTO_RSA_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_RSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_RSA_SignData},
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_RSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_RSA_VerifyData},
    {CRYPT_EAL_IMPLPKEYSIGN_RECOVER, (CRYPT_EAL_ImplPkeyRecover)CRYPT_RSA_Recover},
#endif
#ifdef HITLS_CRYPTO_RSA_BSSA
#ifdef HITLS_CRYPTO_RSA_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_BLIND, (CRYPT_EAL_ImplPkeyBlind)CRYPT_RSA_Blind},
#endif
#ifdef HITLS_CRYPTO_RSA_VERIFY
    {CRYPT_EAL_IMPLPKEYSIGN_UNBLIND, (CRYPT_EAL_ImplPkeyUnBlind)CRYPT_RSA_UnBlind},
#endif
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignEcdsa[] = {
#ifdef HITLS_CRYPTO_ECDSA
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_ECDSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, (CRYPT_EAL_ImplPkeySignData)CRYPT_ECDSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_ECDSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, (CRYPT_EAL_ImplPkeyVerifyData)CRYPT_ECDSA_VerifyData},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignSm2[] = {
#ifdef HITLS_CRYPTO_SM2_SIGN
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_SM2_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_SM2_Verify},
#endif
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignSlhDsa[] = {
#ifdef HITLS_CRYPTO_SLH_DSA
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_SLH_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_SLH_DSA_Verify},
#endif
    CRYPT_EAL_FUNC_END
};

const CRYPT_EAL_Func g_defSignMlDsa[] = {
#ifdef HITLS_CRYPTO_MLDSA
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, (CRYPT_EAL_ImplPkeySign)CRYPT_ML_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, (CRYPT_EAL_ImplPkeyVerify)CRYPT_ML_DSA_Verify},
#endif
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */