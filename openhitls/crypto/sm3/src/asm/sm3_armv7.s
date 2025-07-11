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
#ifdef HITLS_CRYPTO_SM3

#include "crypt_arm.h"

.syntax unified
.arch armv7-m
.thumb

// state update function for rounds 1~16
.macro RF0 a b c d e f g h i
    LDR r1, [ip], #0x04                         // r1 = w[i]
    LDR r2, [ip, #0x0C]                         // r2 = w[i+4]
    EOR r2, r1                                  // r2 = w[i] ^ w[i+4]
    ADD \h, r1                                  // h += w[i]            (r1 is free)
    ADD \d, r2                                  // d += w[i] ^ w[i + 4] (r2 is free)

	ADD r1, \e, r0, ROR #(32-\i%32)%32          // r1 = ss1 = ((a <<< 12) + e + T[i]) <<< 7
    ADD r1, r1, \a, ROR #20
    ROR r1, #25

    EOR r3, \e, \f                              // h += (e ^ f ^ g) + ss1
    EOR r3, \g
    ADD \h, r3
    ADD \h, r1

    EOR r3, \h, \h, ROR #23                     // h = h ^ （h <<< 9） ^ （h <<< 17）
    EOR \h, r3, \h, ROR #15

    EOR r2, r1, \a, ROR #20                     // r2 = ss2 = (a <<< 12) ^ ss1
    EOR r3, \a, \b                              // d += （a ^ b ^ c）+ ss2
    EOR r3, \c
    ADD \d, r3
	ADD \d, r2

    ROR \b, #23                                 // b = b <<< 9, f = f <<< 19
    ROR \f, #13
.endm

// state update function for rounds 17~64
.macro RF1 a b c d e f g h i
    LDR r1, [ip], #0x04                         // r1 = w[i]
    LDR r2, [ip, #0x0C]                         // r2 = w[i+4]
    EOR r2, r1                                  // r2 = w[i] ^ w[i+4]
    ADD \h, r1                                  // h += w[i]                (r1 is free)
    ADD \d, r2                                  // d += w[i] ^ w[i + 4]     (r2 is free)

	ADD r1, \e, r0, ROR #(32-\i%32)%32          // r1 = ss1 = ((a <<< 12) + e + T[i]) <<< 7
    ADD r1, r1, \a, ROR #20
    ROR r1, #25

	EOR r3, \f, \g                              // h += (e & f) | (~e & g) + ss1 = ((f ^ g) & e) ^ g + ss1
    AND r3, \e
    EOR r3, \g 
    ADD \h, r3
	ADD \h, r1

    EOR r3, \h, \h, ROR #23                     // h = P0(h) = h ^ （h <<< 9） ^ （h <<< 17） 
    EOR \h, r3, \h, ROR #15
	
    EOR r2, r1, \a, ROR #20                     // ss2 = (a <<< 12) ^ ss1   (r1 is free)
    EOR r3, \b, \c                              // d += ((a & b) | (a & c) | (b & c)) + ss2  = (a & (b | c)) | ((b & c)) + ss2
    AND r3, \a
    AND r1, \b, \c
    EOR r3, r1
    ADD \d, r3
    ADD \d, r2
	
    ROR \b, #23                                 // b = b <<< 9, f = f <<< 19
    ROR \f, #13
.endm

// Message scheduling: w[i+16] = P1(w[i] ^ w[i+7] ^ （w[i+13] <<< 15）) ^ （w[i+3] <<< 7） ^ w[i+10]
//                  = P1(w[i] ^ w[i+7]) ^ （w[i+3] <<< 7）    ^    P1(（w[i+13] <<< 15）) ^ w[i+10]
// P1(x) = x ^ x <<< 15 ^ x <<< 23 = x ^ x >>> 17 ^ x >>> 9

.macro MSQEXP w0 w3 w7 w10 w13 i
    LDR \w10, [lr, #((10 + \i) << 2)]
    LDR \w13, [lr, #((13 + \i) << 2)]
    EOR \w0, \w7
    EOR \w0, \w0, \w13, ROR #17
    EOR ip, \w0, \w0, ROR #17      
    EOR \w0, ip, \w0, ROR #9
    EOR \w0, \w0, \w3, ROR #25
    EOR \w0, \w10
    STR \w0, [lr, #((16 + \i) << 2)]
.endm

.section .date, "aw"
	w: .word   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

.section .text, "ax"
	.align 4
    .global sm3_compress
	.global PUT32
	.global GET32
		
.thumb_func

PUT32:
	REV r1, r1
	STR r1, [r0]
	MOV pc, lr

GET32:
	LDR r0, [r0]
	REV r0, r0
	MOV pc, lr

sm3_compress:
    PUSH {v1-ip, lr}
	.Lsm3_compress_start:
	SUBS r2, r2, 1
	BCC .Lsm3_compress_return
	PUSH {r0-r2}
	PUSH {r1}
	PUSH {r1}
    ADD r0, #0x40
    LDR lr, = w + 0x40
    LDMDB r0!, {r1-r8}
    REV r1, r1
    REV r2, r2
    REV r3, r3
    REV r4, r4
    REV r5, r5
    REV r6, r6
    REV r7, r7
    REV r8, r8
    STMDB lr!, {r1-r8}
    MOV r9, r1
    MOV r10, r2
    LDMDB r0, {r1-r8}
    REV r1, r1
    REV r2, r2
    REV r3, r3
    REV r4, r4
    REV r5, r5
    REV r6, r6
    REV r7, r7
    REV r8, r8
    STMDB lr!, {r1-r8}
    MSQEXP r1  r4  r8  r0  r11 0
    MSQEXP r2  r5  r9  r1  r11 1
    MSQEXP r3  r6  r10 r2  r11 2
    MSQEXP r4  r7  r0  r3  r11 3
    MSQEXP r5  r8  r1  r4  r11 4
    MSQEXP r6  r9  r2  r5  r11 5
    MSQEXP r7  r10 r3  r6  r11 6
    MSQEXP r8  r0  r4  r7  r11 7
    MSQEXP r9  r1  r5  r8  r11 8
    MSQEXP r10 r2  r6  r9  r11 9
    MSQEXP r0  r3  r7  r10 r11 10
    MSQEXP r1  r4  r8  r0  r11 11
    MSQEXP r2  r5  r9  r1  r11 12
    MSQEXP r3  r6  r10 r2  r11 13
    MSQEXP r4  r7  r0  r3  r11 14
    MSQEXP r5  r8  r1  r4  r11 15
    MSQEXP r6  r9  r2  r5  r11 16
    MSQEXP r7  r10 r3  r6  r11 17
    MSQEXP r8  r0  r4  r7  r11 18
    MSQEXP r9  r1  r5  r8  r11 19
    MSQEXP r10 r2  r6  r9  r11 20
    MSQEXP r0  r3  r7  r10 r11 21
    MSQEXP r1  r4  r8  r0  r11 22
    MSQEXP r2  r5  r9  r1  r11 23
    MSQEXP r3  r6  r10 r2  r11 24
    MSQEXP r4  r7  r0  r3  r11 25
    MSQEXP r5  r8  r1  r4  r11 26
    MSQEXP r6  r9  r2  r5  r11 27
    MSQEXP r7  r10 r3  r6  r11 28
    MSQEXP r8  r0  r4  r7  r11 29
    MSQEXP r9  r1  r5  r8  r11 30
    MSQEXP r10 r2  r6  r9  r11 31
    MSQEXP r0  r3  r7  r10 r11 32
    MSQEXP r1  r4  r8  r0  r11 33
    MSQEXP r2  r5  r9  r1  r11 34
    MSQEXP r3  r6  r10 r2  r11 35
    MSQEXP r4  r7  r0  r3  r11 36
    MSQEXP r5  r8  r1  r4  r11 37
    MSQEXP r6  r9  r2  r5  r11 38
    MSQEXP r7  r10 r3  r6  r11 39
    MSQEXP r8  r0  r4  r7  r11 40
    MSQEXP r9  r1  r5  r8  r11 41
    MSQEXP r10 r2  r6  r9  r11 42
    MSQEXP r0  r3  r7  r10 r11 43
    MSQEXP r1  r4  r8  r0  r11 44
    MSQEXP r2  r5  r9  r1  r11 45
    MSQEXP r3  r6  r10 r2  r11 46
    MSQEXP r4  r7  r0  r3  r11 47
    MSQEXP r5  r8  r1  r4  r11 48
    MSQEXP r6  r9  r2  r5  r11 49
    MSQEXP r7  r10 r3  r6  r11 50
    MSQEXP r8  r0  r4  r7  r11 51

	POP {r1}
    LDM r1, {v1-v8}
    LDR ip, = w
    MOVW r0, 0x4519
    MOVT r0, 0x79cc
    // 0-15
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 0
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 1
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 2
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 3
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 4
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 5
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 6
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 7
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 8
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 9
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 10
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 11
    RF0 v1 v2 v3 v4 v5 v6 v7 v8 12
    RF0 v4 v1 v2 v3 v8 v5 v6 v7 13
    RF0 v3 v4 v1 v2 v7 v8 v5 v6 14
    RF0 v2 v3 v4 v1 v6 v7 v8 v5 15
    MOVW r0, 0x9d8a
    MOVT r0, 0x7a87
    B 1f
    .ltorg
 1: // 16-31
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 16
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 17
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 18
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 19
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 20
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 21
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 22
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 23
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 24
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 25
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 26
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 27
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 28
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 29
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 30
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 31
    // 32-47
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 32
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 33
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 34
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 35
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 36
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 37
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 38
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 39
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 40
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 41
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 42
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 43
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 44
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 45
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 46
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 47
    // 48-63
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 48
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 49
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 50
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 51
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 52
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 53
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 54
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 55
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 56
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 57
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 58
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 59
    RF1 v1 v2 v3 v4 v5 v6 v7 v8 60
    RF1 v4 v1 v2 v3 v8 v5 v6 v7 61
    RF1 v3 v4 v1 v2 v7 v8 v5 v6 62
    RF1 v2 v3 v4 v1 v6 v7 v8 v5 63

    POP {r1}
	MOV ip, r1
    LDM ip!, {r0-r3}
    EOR v1, r0
    EOR v2, r1
    EOR v3, r2
    EOR v4, r3
    LDM ip!, {r0-r3}
    EOR v5, r0
    EOR v6, r1
    EOR v7, r2
    EOR v8, r3
    STMDB ip, {v1-v8}
	POP {r0-r2}
	B .Lsm3_compress_start
	.Lsm3_compress_return:
    POP {v1-ip, lr}
    MOV pc, lr
	
.end
	
