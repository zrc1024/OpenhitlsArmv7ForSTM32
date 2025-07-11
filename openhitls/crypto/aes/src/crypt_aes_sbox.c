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
#if defined(HITLS_CRYPTO_AES) && !defined(HITLS_CRYPTO_AES_PRECALC_TABLES)

#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "crypt_aes.h"
#include "crypt_aes_sbox.h"

#define BYTE_BITS 8

static const uint8_t AES_S[256] = {
    0x63U, 0x7cU, 0x77U, 0x7bU, 0xf2U, 0x6bU, 0x6fU, 0xc5U, 0x30U, 0x01U, 0x67U, 0x2bU, 0xfeU, 0xd7U, 0xabU, 0x76U,
    0xcaU, 0x82U, 0xc9U, 0x7dU, 0xfaU, 0x59U, 0x47U, 0xf0U, 0xadU, 0xd4U, 0xa2U, 0xafU, 0x9cU, 0xa4U, 0x72U, 0xc0U,
    0xb7U, 0xfdU, 0x93U, 0x26U, 0x36U, 0x3fU, 0xf7U, 0xccU, 0x34U, 0xa5U, 0xe5U, 0xf1U, 0x71U, 0xd8U, 0x31U, 0x15U,
    0x04U, 0xc7U, 0x23U, 0xc3U, 0x18U, 0x96U, 0x05U, 0x9aU, 0x07U, 0x12U, 0x80U, 0xe2U, 0xebU, 0x27U, 0xb2U, 0x75U,
    0x09U, 0x83U, 0x2cU, 0x1aU, 0x1bU, 0x6eU, 0x5aU, 0xa0U, 0x52U, 0x3bU, 0xd6U, 0xb3U, 0x29U, 0xe3U, 0x2fU, 0x84U,
    0x53U, 0xd1U, 0x00U, 0xedU, 0x20U, 0xfcU, 0xb1U, 0x5bU, 0x6aU, 0xcbU, 0xbeU, 0x39U, 0x4aU, 0x4cU, 0x58U, 0xcfU,
    0xd0U, 0xefU, 0xaaU, 0xfbU, 0x43U, 0x4dU, 0x33U, 0x85U, 0x45U, 0xf9U, 0x02U, 0x7fU, 0x50U, 0x3cU, 0x9fU, 0xa8U,
    0x51U, 0xa3U, 0x40U, 0x8fU, 0x92U, 0x9dU, 0x38U, 0xf5U, 0xbcU, 0xb6U, 0xdaU, 0x21U, 0x10U, 0xffU, 0xf3U, 0xd2U,
    0xcdU, 0x0cU, 0x13U, 0xecU, 0x5fU, 0x97U, 0x44U, 0x17U, 0xc4U, 0xa7U, 0x7eU, 0x3dU, 0x64U, 0x5dU, 0x19U, 0x73U,
    0x60U, 0x81U, 0x4fU, 0xdcU, 0x22U, 0x2aU, 0x90U, 0x88U, 0x46U, 0xeeU, 0xb8U, 0x14U, 0xdeU, 0x5eU, 0x0bU, 0xdbU,
    0xe0U, 0x32U, 0x3aU, 0x0aU, 0x49U, 0x06U, 0x24U, 0x5cU, 0xc2U, 0xd3U, 0xacU, 0x62U, 0x91U, 0x95U, 0xe4U, 0x79U,
    0xe7U, 0xc8U, 0x37U, 0x6dU, 0x8dU, 0xd5U, 0x4eU, 0xa9U, 0x6cU, 0x56U, 0xf4U, 0xeaU, 0x65U, 0x7aU, 0xaeU, 0x08U,
    0xbaU, 0x78U, 0x25U, 0x2eU, 0x1cU, 0xa6U, 0xb4U, 0xc6U, 0xe8U, 0xddU, 0x74U, 0x1fU, 0x4bU, 0xbdU, 0x8bU, 0x8aU,
    0x70U, 0x3eU, 0xb5U, 0x66U, 0x48U, 0x03U, 0xf6U, 0x0eU, 0x61U, 0x35U, 0x57U, 0xb9U, 0x86U, 0xc1U, 0x1dU, 0x9eU,
    0xe1U, 0xf8U, 0x98U, 0x11U, 0x69U, 0xd9U, 0x8eU, 0x94U, 0x9bU, 0x1eU, 0x87U, 0xe9U, 0xceU, 0x55U, 0x28U, 0xdfU,
    0x8cU, 0xa1U, 0x89U, 0x0dU, 0xbfU, 0xe6U, 0x42U, 0x68U, 0x41U, 0x99U, 0x2dU, 0x0fU, 0xb0U, 0x54U, 0xbbU, 0x16U
};

#define SEARCH_SBOX(t)                                                                                  \
    ((AES_S[((t) >> 24)] << 24) | (AES_S[((t) >> 16) & 0xFF] << 16) | (AES_S[((t) >> 8) & 0xFF] << 8) | \
        (AES_S[((t) >> 0) & 0xFF] << 0))

#define SEARCH_INVSBOX(t)                                                                                              \
    ((InvSubSbox(((t) >> 24)) << 24) | (InvSubSbox(((t) >> 16) & 0xFF) << 16) | (InvSubSbox(((t) >> 8) & 0xFF) << 8) | \
        (InvSubSbox(((t) >> 0) & 0xFF) << 0))

void SetAesKeyExpansionSbox(CRYPT_AES_Key *ctx, uint32_t keyLenBits, const uint8_t *key)
{
    uint32_t *ekey = ctx->key;
    uint32_t keyLenByte = keyLenBits / (sizeof(uint32_t) * BYTE_BITS);
    uint32_t i = 0;
    for (i = 0; i < keyLenByte; ++i) {
        ekey[i] = GET_UINT32_BE(key, i * sizeof(uint32_t));
    }

    for (; i < 4 * (ctx->rounds + 1); ++i) {
        if ((i % keyLenByte) == 0) {
            ekey[i] = ekey[i - keyLenByte] ^ SEARCH_SBOX(ROTL32(ekey[i - 1], BYTE_BITS)) ^
                RoundConstArray(i / keyLenByte - 1);
        } else if (keyLenByte > 6 && (i % keyLenByte) == 4) {
            ekey[i] = ekey[i - keyLenByte] ^ SEARCH_SBOX(ekey[i - 1]);
        } else {
            ekey[i] = ekey[i - keyLenByte] ^ ekey[i - 1];
        }
    }
}

static void AesAddRoundKey(uint32_t *state, const uint32_t *round, int nr)
{
    for (int i = 0; i < 4; ++i) {
        state[i] ^= round[4 * nr + i];
    }
}

static void AesSubBytes(uint32_t *state)
{
    for (int i = 0; i < 4; ++i) {
        state[i] = SEARCH_SBOX(state[i]);
    }
}

static void AesShiftRows(uint32_t *state)
{
    uint32_t s[4] = {0};
    for (int32_t i = 0; i < 4; ++i) {
        s[i] = state[i];
    }

    state[0] = (s[0] & 0xFF000000) | (s[1] & 0xFF0000) | (s[2] & 0xFF00) | (s[3] & 0xFF);
    state[1] = (s[1] & 0xFF000000) | (s[2] & 0xFF0000) | (s[3] & 0xFF00) | (s[0] & 0xFF);
    state[2] = (s[2] & 0xFF000000) | (s[3] & 0xFF0000) | (s[0] & 0xFF00) | (s[1] & 0xFF);
    state[3] = (s[3] & 0xFF000000) | (s[0] & 0xFF0000) | (s[1] & 0xFF00) | (s[2] & 0xFF);
}

static uint8_t AesXtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static uint8_t AesXtimes(uint8_t x, int ts)
{
    uint8_t tmpX = x;
    int tmpTs = ts;
    while (tmpTs-- > 0) {
        tmpX = AesXtime(tmpX);
    }

    return tmpX;
}

static uint8_t AesMul(uint8_t x, uint8_t y)
{
    return ((((y >> 0) & 1) * AesXtimes(x, 0)) ^ (((y >> 1) & 1) * AesXtimes(x, 1)) ^
        (((y >> 2) & 1) * AesXtimes(x, 2)) ^ (((y >> 3) & 1) * AesXtimes(x, 3)) ^ (((y >> 4) & 1) * AesXtimes(x, 4)) ^
        (((y >> 5) & 1) * AesXtimes(x, 5)) ^ (((y >> 6) & 1) * AesXtimes(x, 6)) ^ (((y >> 7) & 1) * AesXtimes(x, 7)));
}

static void AesMixColumns(uint32_t *state, bool isMixColumns)
{
    uint8_t ts[16] = {0};
    for (int32_t i = 0; i < 4; ++i) {
        PUT_UINT32_BE(state[i], ts, 4 * i);
    }

    uint8_t aesY[16] = {2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2};
    uint8_t aesInvY[16] = {0x0e, 0x0b, 0x0d, 0x09, 0x09, 0x0e, 0x0b, 0x0d, 0x0d, 0x09, 0x0e, 0x0b, 0x0b, 0x0d, 0x09,
                           0x0e};
    uint8_t s[4];
    uint8_t *y = isMixColumns == true ? aesY : aesInvY;

    for (int i = 0; i < 4; ++i) {
        for (int r = 0; r < 4; ++r) {
            s[r] = 0;
            for (int j = 0; j < 4; ++j) {
                s[r] = s[r] ^ AesMul(ts[i * 4 + j], y[r * 4 + j]);
            }
        }
        for (int r = 0; r < 4; ++r) {
            ts[i * 4 + r] = s[r];
        }
    }

    for (int32_t i = 0; i < 4; ++i) {
        state[i] = GET_UINT32_BE(ts, 4 * i);
    }
}

// addRound + 9/11/13 * (sub + shiftRow + mix + addRound) + (sub + shiftRow + addRound)
void CRYPT_AES_EncryptSbox(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    (void)len;
    uint32_t s[4] = {0};

    for (int32_t i = 0; i < 4; ++i) {
        s[i] = GET_UINT32_BE(in, 4 * i);
    }
    uint32_t nr = 0;
    AesAddRoundKey(s, ctx->key, nr);
    for (nr = 1; nr < ctx->rounds; ++nr) {
        AesSubBytes(s);
        AesShiftRows(s);
        AesMixColumns(s, true);
        AesAddRoundKey(s, ctx->key, nr);
    }
    AesSubBytes(s);
    AesShiftRows(s);
    AesAddRoundKey(s, ctx->key, nr);

    for (int32_t i = 0; i < 4; ++i) {
        PUT_UINT32_BE(s[i], out, 4 * i);
    }
}

static void InvShiftRows(uint32_t *state)
{
    uint32_t s[4] = {0};
    for (int32_t i = 0; i < 4; ++i) {
        s[i] = state[i];
    }

    state[0] = (s[0] & 0xFF000000) | (s[3] & 0xFF0000) | (s[2] & 0xFF00) | (s[1] & 0xFF);
    state[1] = (s[1] & 0xFF000000) | (s[0] & 0xFF0000) | (s[3] & 0xFF00) | (s[2] & 0xFF);
    state[2] = (s[2] & 0xFF000000) | (s[1] & 0xFF0000) | (s[0] & 0xFF00) | (s[3] & 0xFF);
    state[3] = (s[3] & 0xFF000000) | (s[2] & 0xFF0000) | (s[1] & 0xFF00) | (s[0] & 0xFF);
}

static void InvSubBytes(uint32_t *state)
{
    for (int i = 0; i < 4; ++i) {
        state[i] = SEARCH_INVSBOX(state[i]);
    }
}

// (addRound + InvShiftRow + InvSub) + 9/11/13 * (addRound + invMix + InvShiftRow + InvSub) + addRound
void CRYPT_AES_DecryptSbox(const CRYPT_AES_Key *ctx, const uint8_t *in, uint8_t *out, uint32_t len)
{
    (void)len;
    uint32_t s[4] = {0};

    for (int32_t i = 0; i < 4; ++i) {
        s[i] = GET_UINT32_BE(in, 4 * i);
    }

    uint32_t nr = ctx->rounds;
    AesAddRoundKey(s, ctx->key, nr);
    InvShiftRows(s);
    InvSubBytes(s);
    for (nr = ctx->rounds - 1; nr > 0; --nr) {
        AesAddRoundKey(s, ctx->key, nr);
        AesMixColumns(s, false);
        InvShiftRows(s);
        InvSubBytes(s);
    }
    AesAddRoundKey(s, ctx->key, nr);
    for (int32_t i = 0; i < 4; ++i) {
        PUT_UINT32_BE(s[i], out, 4 * i);
    }
    BSL_SAL_CleanseData(&s, 4 * sizeof(uint32_t));
}
#endif /* HITLS_CRYPTO_AES && !HITLS_CRYPTO_AES_PRECALC_TABLES */