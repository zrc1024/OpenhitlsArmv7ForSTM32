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
#ifdef HITLS_CRYPTO_CURVE_SM2
.syntax unified
.thumb

// sm2_p
.equ sm2_p1, 0xFFFFFFFF
.equ sm2_p2, 0xFFFFFFFF
.equ sm2_p3, 0x00000000
.equ sm2_p4, 0xFFFFFFFF
.equ sm2_p5, 0xFFFFFFFF
.equ sm2_p6, 0xFFFFFFFF
.equ sm2_p7, 0xFFFFFFFF
.equ sm2_p8, 0xFFFFFFFE
// sm2_q = - sm2_p 
.equ sm2_q1, 0x00000001
.equ sm2_q2, 0x00000000
.equ sm2_q3, 0xFFFFFFFF
.equ sm2_q4, 0x00000000
.equ sm2_q5, 0x00000000
.equ sm2_q6, 0x00000000
.equ sm2_q7, 0x00000000
.equ sm2_q8, 0x00000001
// sm2_s = (sm2_p + 1) / 2
.equ sm2_s1, 0x00000000
.equ sm2_s2, 0x80000000
.equ sm2_s3, 0x80000000
.equ sm2_s4, 0xFFFFFFFF
.equ sm2_s5, 0xFFFFFFFF
.equ sm2_s6, 0xFFFFFFFF
.equ sm2_s7, 0x7FFFFFFF
.equ sm2_s8, 0x7FFFFFFF



// V refers specifically to the reglist {v1-v8} that stores 256-bit numbers 
// save v and return
.macro SAVE
	STM r0, {v1-v8}
	POP {v1-v8}
	MOV pc, lr
.endm

// v = v + n
.macro VADD n1 n2 n3 n4 n5 n6 n7 n8
	ADDS v1, \n1
	ADCS v2, \n2
	ADCS v3, \n3
	ADCS v4, \n4
	ADCS v5, \n5
	ADCS v6, \n6
	ADCS v7, \n7
	ADCS v8, \n8
.endm

// v = v - n
.macro VSUB n1 n2 n3 n4 n5 n6 n7 n8
	SUBS v1, \n1
	SBCS v2, \n2
	SBCS v3, \n3
	SBCS v4, \n4
	SBCS v5, \n5
	SBCS v6, \n6
	SBCS v7, \n7
	SBCS v8, \n8
.endm

// v = v - q
.macro VSUBQ
	VSUB sm2_q1, sm2_q2, sm2_q3, sm2_q4, sm2_q5, sm2_q6, sm2_q7, sm2_q8
.endm

// v = v + s
.macro VADDS
	VADD sm2_s1, sm2_s2, sm2_s3, sm2_s4, sm2_s5, sm2_s6, sm2_s7, sm2_s8
.endm

// v = v >> 1
.macro VLSR
	LSRS v1, v1, #1
	BFI v1, v2, #31, #1
	LSR v2, v2, #1
	BFI v2, v3, #31, #1
	LSR v3, v3, #1
	BFI v3, v4, #31, #1
	LSR v4, v4, #1
	BFI v4, v5, #31, #1
	LSR v5, v5, #1
	BFI v5, v6, #31, #1
	LSR v6, v6, #1
	BFI v6, v7, #31, #1
	LSR v7, v7, #1
	BFI v7, v8, #31, #1
	LSR v8, v8, #1
.endm

// v = - v mod r
.macro VNEG
	MVN v1, v1
	MVN v2, v2
	MVN v3, v3
	MVN v4, v4
	MVN v5, v5
	MVN v6, v6
	MVN v7, v7
	MVN v8, v8
	ADDS v1, #1
	ADCS v2, #0
	ADCS v3, #0
	ADCS v4, #0
	ADCS v5, #0
	ADCS v6, #0
	ADCS v7, #0
	ADCS v8, #0
.endm

// LDP ptr to r and LDM to rlist
.macro LDP r ptr rlist
    LDR \r, =\ptr
    LDM \r, \rlist
.endm

// LDP ptr to r and STM rlist
.macro STP r ptr rlist
    LDR \r, =\ptr
    STM \r, \rlist
.endm

// reg1 - reg2, using in fp_inv
.macro SUBUV reg1 reg2
	LDM \reg1!, {v1-v4}
	LDM \reg2!, {v5-v8}
	SUBS v1, v5
	SBCS v2, v6
	SBCS v3, v7
	SBCS v4, v8
	PUSH {v1-v4}
	LDM \reg1, {v5-v8}
	LDM \reg2, {v1-v4}
	SBCS v5, v1
	SBCS v6, v2
	SBCS v7, v3
	SBCS v8, v4
	SUB \reg1, #0x10
	SUB \reg2, #0x10
	POP {v1-v4}
.endm
.section .rodate, "a"
    sm2_zero: .word 0, 0, 0, 0, 0, 0, 0, 0
    sm2_one:  .word 1, 0, 0, 0, 0, 0, 0, 0
    sm2_prime: .word 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE

.section .date, "aw"
	td: .word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	tw: .word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	tu: .word 0, 0, 0, 0, 0, 0, 0, 0
	tv: .word 0, 0, 0, 0, 0, 0, 0, 0
	ta: .word 0, 0, 0, 0, 0, 0, 0, 0
	tc: .word 0, 0, 0, 0, 0, 0, 0, 0
	

.section .text, "ax"
	.global ECP_Sm2FpCmp
	.global ECP_Sm2FpAdd
	.global ECP_Sm2FpSub
	.global ECP_Sm2FpNeg
	.global ECP_Sm2FpDou
	.global ECP_Sm2FpHaf
	.global ECP_Sm2FpMul
	.global ECP_Sm2FpSqr
	.global ECP_Sm2FpInv

.thumb_func
ECP_Sm2FpCmp:
	LDR r2, [r0, #0x1C]
	LDR r3, [r1, #0x1C]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x18]
	LDR r3, [r1, #0x18]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x14]
	LDR r3, [r1, #0x14]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x10]
	LDR r3, [r1, #0x10]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x0C]
	LDR r3, [r1, #0x0C]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x08]
	LDR r3, [r1, #0x08]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x04]
	LDR r3, [r1, #0x04]
	CMP r2, r3
	BHI 1f
	BCC 0f
	LDR r2, [r0, #0x00]
	LDR r3, [r1, #0x00]
	CMP r2, r3
	BCC 0f
 1: MOV r0, 1
    MOV pc, lr
 0: MOV r0, 0
    MOV pc, lr
 
ECP_Sm2FpAdd:
	PUSH {v1-v8}
	LDM r2, {v1-v8}
	LDR r2, [r1, #0x00]
	LDR r3, [r1, #0x04]
	ADDS v1, r2
	ADCS v2, r3
	LDR r2, [r1, #0x08]
	LDR r3, [r1, #0x0C]
	ADCS v3, r2
	ADCS v4, r3
	LDR r2, [r1, #0x10]
	LDR r3, [r1, #0x14]
	ADCS v5, r2
	ADCS v6, r3
	LDR r2, [r1, #0x18]
	LDR r3, [r1, #0x1C]
	ADCS v7, r2
	ADCS v8, r3
	BCC 0f
	ADDS v1, #sm2_q1
	ADCS v2, #sm2_q2
	ADCS v3, #sm2_q3
	ADCS v4, #sm2_q4
	ADCS v5, #sm2_q5
	ADCS v6, #sm2_q6
	ADCS v7, #sm2_q7
	ADCS v8, #sm2_q8
 0: STM r0, {v1-v8}
	POP {v1-v8}
	MOV pc, lr


ECP_Sm2FpSub:
	PUSH {v1-v8}
	LDM r1, {v1-v8}
	LDR r1, [r2, #0x00]
	LDR r3, [r2, #0x04]
	SUBS v1, r1
	SBCS v2, r3
	LDR r1, [r2, #0x08]
	LDR r3, [r2, #0x0C]
	SBCS v3, r1
	SBCS v4, r3
	LDR r1, [r2, #0x10]
	LDR r3, [r2, #0x14]
	SBCS v5, r1
	SBCS v6, r3
	LDR r1, [r2, #0x18]
	LDR r3, [r2, #0x1C]
	SBCS v7, r1
	SBCS v8, r3
	BCS 0f
	SUBS v1, #sm2_q1
	SBCS v2, #sm2_q2
	SBCS v3, #sm2_q3
	SBCS v4, #sm2_q4
	SBCS v5, #sm2_q5
	SBCS v6, #sm2_q6
	SBCS v7, #sm2_q7
	SBCS v8, #sm2_q8
 0: STM r0, {v1-v8}
	POP {v1-v8}
	MOV pc, lr

ECP_Sm2FpNeg:
	PUSH {r4-r6}
	LDM  r1!, {r2-r4}
	RSB  r2, #sm2_p1
	RSB  r3, #sm2_p2
	RSBS r4, #sm2_p3
	STM  r0!, {r2-r4}
	LDM  r1, {r2-r6}
	RSB  r2, #sm2_p4
	RSB  r3, #sm2_p5
	RSB  r4, #sm2_p6
	RSB  r5, #sm2_p7
	RSB  r6, #sm2_p7
	SBCS r2, #0
	SBCS r4, #0
	SBCS r5, #0
	SBCS r6, #1
	STM  r0, {r2-r6}
	POP  {r4-r6}
	MOV  pc, lr

ECP_Sm2FpDou:
	PUSH {r4-r8}
	LDM r1, {r1-r8}
	ADDS r1, r1
	ADCS r2, r2
	ADCS r3, r3
	ADCS r4, r4
	ADCS r5, r5
	ADCS r6, r6
	ADCS r7, r7
	ADCS r8, r8
	BCC 0f
	ADDS r1, #sm2_q1
	ADCS r2, #sm2_q2
	ADCS r3, #sm2_q3
	ADCS r4, #sm2_q4
	ADCS r5, #sm2_q5
	ADCS r6, #sm2_q6
	ADCS r7, #sm2_q7
	ADCS r8, #sm2_q8
 0: STM  r0, {r1-r8}
	POP  {r4-r8}
	MOV  pc, lr

ECP_Sm2FpHaf:
	PUSH {r4-r8}
	LDM r1, {r1-r8}
	LSRS r1, r1, #1
	BFI r1, r2, #31, #1
	LSR r2, r2, #1
	BFI r2, r3, #31, #1
	LSR r3, r3, #1
	BFI r3, r4, #31, #1
	LSR r4, r4, #1
	BFI r4, r5, #31, #1
	LSR r5, r5, #1
	BFI r5, r6, #31, #1
	LSR r6, r6, #1
	BFI r6, r7, #31, #1
	LSR r7, r7, #1
	BFI r7, r8, #31, #1
	LSR r8, r8, #1
	BCC 0f
	ADDS r1, #sm2_s1
	ADCS r2, #sm2_s2
	ADCS r3, #sm2_s3
	ADCS r4, #sm2_s4
	ADCS r5, #sm2_s5
	ADCS r6, #sm2_s6
	ADCS r7, #sm2_s7
	ADCS r8, #sm2_s8
 0: STM  r0, {r1-r8}
	POP  {r4-r8}
	MOV  pc, lr

ECP_Sm2FpInv:
	PUSH {v1-v8}
	PUSH {r0}
	// u = input, v = p, a = 1, c = 0
	LDM r1, {v1-v8}
	STP r0, tu, {v1-v8}
	LDP r1, sm2_prime, {v1-v8}
	STP r1, tv, {v1-v8}
	LDP r2, sm2_one, {v1-v8}
	STP r2, ta, {v1-v8}
	LDP r3, sm2_zero, {v1-v8}
	STP r3, tc, {v1-v8}

	// while u >= 1 do inv_loop
 	inv_while:
	LDR v1, [r0]
	TEQ v1, #0
	BNE inv_loop
	LDM r0, {v1-v8}
	TEQ v2, #0
	BNE inv_loop
	TEQ v3, #0
	BNE inv_loop
	TEQ v4, #0
	BNE inv_loop
	TEQ v5, #0
	BNE inv_loop
	TEQ v6, #0
	BNE inv_loop
	TEQ v7, #0
	BNE inv_loop
	TEQ v8, #0
	BNE inv_loop
	B inv_end

	inv_loop:

	// while u is even, u = u >> 1, a = a / 2 mod p,
	inv_u_loop:
	LDR v1, [r0]
	TST v1, #1
	BNE inv_v_loop
	LDM r0, {v1-v8}
	VLSR
	STM r0, {v1-v8}
	LDM r2, {v1-v8}
	VLSR
	BCC 0f
	VADDS
 0: STM r2, {v1-v8}
	B inv_u_loop

	// while v is even, v = v >> 1, c = c / 2 mod p
	inv_v_loop:
	LDR v1, [r1]
	TST v1, #1
	BNE inv_update_uv
	LDM r1, {v1-v8}
	VLSR
	STM r1, {v1-v8}
	LDM r3, {v1-v8}
	VLSR
	BCC 1f
	VADDS
 1: STM r3, {v1-v8}
	B inv_v_loop

	// if u >= v, u = u - v, a = a - c mod p, else v = v - u, c = c - a mod p
	inv_update_uv:
	SUBUV r0, r1
	BCC v_is_bigger
	u_is_bigger:
	STM r0, {v1-v8}
	SUBUV r2, r3
	BCS 2f
	VSUBQ
 2:	STM r2, {v1-v8}
	B inv_while

	v_is_bigger:
	VNEG
	STM r1, {v1-v8}
	SUBUV r3, r2
	BCS 3f
	VSUBQ
 3:	STM r3, {v1-v8}
	B inv_while

	inv_end: // end while
	POP {r0}
	LDM r3, {v1-v8}
	SAVE



ECP_Sm2FpMul:
	PUSH {v1-v8}
	PUSH {ip, lr}
	PUSH {r0}
	
	// celar td
	LDR r0, =td
	MOV v1, #0
	MOV v2, #0
	MOV v3, #0
	MOV v4, #0
	MOV v5, #0
	MOV v6, #0
	MOV v7, #0
	MOV v8, #0
	STM r0!, {v1-v8}
	STM r0!, {v1-v8}
	SUB r0, #0x40
	
	// td = a * b
	LDM r2, {v1-v8}
	// 1
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	// 2
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	// 3
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	// 4
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	// 5
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	// 6
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	// 7
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	// 8
	MOV lr, #0
	LDM r1!, {ip}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v1
	UMAAL r3, lr, ip, v2
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v3
	UMAAL r3, lr, ip, v4
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v5
	UMAAL r3, lr, ip, v6
	STM r0!, {r2-r3}
	LDM r0, {r2-r3}
	UMAAL r2, lr, ip, v7
	UMAAL r3, lr, ip, v8
	STM r0, {r2-r3, lr}
	SUB r0, r0, #0x14
	
	//Fast modular reduction
	LDM r0, {v1-v8}
	LDR r1, = tw
	MOV ip, #1
	
	// the middle value in the fast rection
	// w0 = c[8] + c[9] + c[10] + c[11];
    // w1 = c[8] + c[13];
    // w2 = c[9] + c[14];
    // w3 = c[14] + c[15];
    // w4 = w3 + c[13];
    // w5 = w4 + c[12];
    // w0 = w0 + w5;
	UMULL r2, r3, v1, ip		//  (r2, r3)  = c[8]
	UMLAL r2, r3, v2, ip		//  (r2, r3) += c[9]
	UMLAL r2, r3, v3, ip		//  (r2, r3) += c[10]
	UMLAL r2, r3, v4, ip		//  (r2, r3) += c[11]
	STM r1!, {r2-r3} 			// 	w0 = c[8] + c[9] + c[10] + c[11];
	UMULL r2, r3, v1, ip		//  (r2, r3)  = c[8]
	UMLAL r2, r3, v6, ip		//  (r2, r3) += c[13]
	STM r1!, {r2-r3} 			// 	w1 = c[8] + c[13];
	UMULL r2, r3, v2, ip		//  (r2, r3)  = c[9]
	UMLAL r2, r3, v7, ip		//  (r2, r3) += c[14]
	STM r1!, {r2-r3} 			//  w2 = c[9] + c[14];
	UMULL r2, r3, v7, ip		//  (r2, r3)  = c[9]
	UMLAL r2, r3, v8, ip		//  (r2, r3) += c[14]
	STM r1!, {r2-r3} 			//  w3 = c[14] + c[15];
	UMLAL r2, r3, v6, ip		//  (r2, r3) += c[13]
	STM r1!, {r2-r3} 			//  w4 = w3 + c[13];
	UMLAL r2, r3, v5, ip		//  (r2, r3) += c[12]
	STM r1!, {r2-r3} 			//  w5 = w4 + c[12];
	SUB r1, r1, #0x30
	LDM r1, {v1-v2}				//  (v1, v2) = w0
	ADDS r2, r2, v1				// 	
	ADCS r3, r3, v2				//  (r2, r3) = w0 + w5
	STM r1, {r2-r3} 			//	w0 += w5

	
	// the registerlist {r2,r3,r4,r5,r6,r7} set can store three intermediate values {rw0, rw1, rw2}, rw0 = w0 now.
	LDR r4, [r1, #0x08]
	LDR r5, [r1, #0x0C]			// {rw0, rw1, rw2} = {w0, w1, -}
	LDR r6, [r1, #0x20]
	LDR r7, [r1, #0x24]			// {rw0, rw1, rw2} = {w0, w1, w4}

	//  Load c[0]-c[3], set ip = 0, carry = lr = 0
	SUB r0, r0, #0x20
	LDM r0, {v5-v8}				// (v5-v8) = (c[0]-c[3])
	MOV ip, #0					// ip = 0
	MOV lr, #0					// carry = 0

	//  c[0] += w0 + w4;
	ADDS v5, v5, r2
	ADCS lr, lr, r3  			// c[0] += w0;
	ADDS v5, v5, r6
	ADCS lr, lr, r7  			// c[0] += w4;
	

	// c[1] += w0 + w4 - w1;
	UMAAL v6, lr, r0, ip        // c[1] += carry
	ADDS v6, v6, r2
	ADCS lr, lr, r3  			// c[1] += w0;
	ADDS v6, v6, r6
	ADCS lr, lr, r7  			// c[0] += w4;
	SUBS v6, v6, r4
	SBCS lr, lr, r5  			// c[1] -= w1;

	// c[2] -= w1 + w2
	LDR r2, [r1, #0x10]
	LDR r3, [r1, #0x14]			// {rw0, rw1, rw2} = {w2, w1, w4}
	UMAAL v7, lr, r0, ip        // c[2] += carry
	SUBS v7, v7, r4
	SBCS lr, lr, r5  			// c[2] -= w1;
	SUBS v7, v7, r2
	SBCS lr, lr, r3  			// c[2] -= w2;

	// c[3] += w5 + w1;
	ADD v8, v8, lr
	MOV lr, #0					// c[3] -= brrow
	ADDS v8, r4
	ADCS lr, r5					// c[3] += w1
	LDR r4, [r1, #0x28]
	LDR r5, [r1, #0x2C]			// {rw0, rw1, rw2} = {w2, w5, w4}
	ADDS v8, r4
	ADCS lr, r5					// c[3] += w5

	// Stroe c[0]-c[3]
	// Load  c[4]-c[7]
	STM r0!, {v5-v8}
	LDM r0,  {v5-v8}
	// c[4] += w5 + w2;
	UMAAL v5, lr, r0, ip        // c[4] += carry
	ADDS v5, r2
	ADCS lr, r3					// c[4] += w2
	ADDS v5, r4
	ADCS lr, r5					// c[4] += w5

	// c[5] += w4 
	UMAAL v6, lr, r0, ip        // c[5] += carry
	ADDS v6, r6
	ADCS lr, r7					// c[5] += w4

	// c[6] += w3
	LDR r2, [r1, #0x18]
	LDR r3, [r1, #0x1C]			// {rw0, rw1, rw2} = {w3, w5, w4}
	UMAAL v7, lr, r0, ip        // c[6] += carry	
	ADDS v7, r2
	ADCS lr, r3					// c[6] += w3

	// c[7] += w0 + w5
	LDR r6, [r1, #0x00]
	LDR r7, [r1, #0x04]			// {rw0, rw1, rw2} = {w3, w5, w0}
	UMAAL v8, lr, r0, ip        // c[7] += carry	
	ADDS v8, r6
	ADCS lr, r7					// c[7] += w0
	ADDS v8, r4
	ADCS lr, r5					// c[7] += w5

	// Load c[0]-c[3] to {v1-v4}
	SUB r0, #0x10
	LDM r0, {v1-v4}
	// Load c[10] c[11] c[15]
	LDR r1, [r0, #10 << 2]
	LDR r2, [r0, #11 << 2]
	LDR r3, [r0, #15 << 2]
	
	ADDS v4, r2
	ADCS v5, #0
	ADCS v6, r1
	ADCS v7, r2
	ADCS v8, r3
	ADCS lr, #0
	ADCS v6, r3
	ADCS v7, #0
	ADCS v8, #0
	ADCS lr, #0
	ADDS v1, lr
	ADCS v2, #0
	ADCS v3, #0
	ADCS v4, lr
	ADCS v5, #0
	ADCS v6, #0
	ADCS v7, #0
	ADCS v8, lr
	SUBS v3, lr
	SBCS v4, #0
	SBCS v5, #0
	SBCS v6, #0
	SBCS v7, #0
	SBCS v8, #0
	POP {r0}
	POP {ip, lr}
 	SAVE

ECP_Sm2FpSqr:
	PUSH {v1-v8}
	PUSH {ip, lr}
	PUSH {r0}

	// celar tc
	LDR r0, =td
	MOV v1, #0
	MOV v2, #0
	MOV v3, #0
	MOV v4, #0
	MOV v5, #0
	MOV v6, #0
	MOV v7, #0
	MOV v8, #0
	STM r0!, {v1-v8}
	STM r0!, {v1-v8}
	SUB r0, #0x40
	
	// tc = a * b
	MOV ip, r0
	LDM r1, {v1-v8}
	// 1
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v1, v1
	UMAAL r1, lr, v1, v2
	UMAAL r2, lr, v1, v3
	UMAAL r3, lr, v1, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v1, v5
	UMAAL r1, lr, v1, v6
	UMAAL r2, lr, v1, v7
	UMAAL r3, lr, v1, v8
	STM ip, {r0-r3, lr}
	SUB ip, ip, #0x0C
	// 2
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v2, v1
	UMAAL r1, lr, v2, v2
	UMAAL r2, lr, v2, v3
	UMAAL r3, lr, v2, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v2, v5
	UMAAL r1, lr, v2, v6
	UMAAL r2, lr, v2, v7
	UMAAL r3, lr, v2, v8
	STM ip, {r0-r3, lr}
	SUB ip, ip, #0x0C
	// 3
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v3, v1
	UMAAL r1, lr, v3, v2
	UMAAL r2, lr, v3, v3
	UMAAL r3, lr, v3, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v3, v5
	UMAAL r1, lr, v3, v6
	UMAAL r2, lr, v3, v7
	UMAAL r3, lr, v3, v8
	STM ip, {r0-r3, lr}
	SUB ip, ip, #0x0C
	// 4
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v4, v1
	UMAAL r1, lr, v4, v2
	UMAAL r2, lr, v4, v3
	UMAAL r3, lr, v4, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v4, v5
	UMAAL r1, lr, v4, v6
	UMAAL r2, lr, v4, v7
	UMAAL r3, lr, v4, v8
	STM ip, {r0-r3, lr}
	SUB ip, ip, #0x0C
	// 5
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v5, v1
	UMAAL r1, lr, v5, v2
	UMAAL r2, lr, v5, v3
	UMAAL r3, lr, v5, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v5, v5
	UMAAL r1, lr, v5, v6
	UMAAL r2, lr, v5, v7
	UMAAL r3, lr, v5, v8
	STM ip, {r0-r3, lr}
	SUB ip, ip, #0x0C
	// 6
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v6, v1
	UMAAL r1, lr, v6, v2
	UMAAL r2, lr, v6, v3
	UMAAL r3, lr, v6, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v6, v5
	UMAAL r1, lr, v6, v6
	UMAAL r2, lr, v6, v7
	UMAAL r3, lr, v6, v8
	STM ip, {r0-r3, lr}
	SUB ip, ip, #0x0C
	// 7
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v7, v1
	UMAAL r1, lr, v7, v2
	UMAAL r2, lr, v7, v3
	UMAAL r3, lr, v7, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v7, v5
	UMAAL r1, lr, v7, v6
	UMAAL r2, lr, v7, v7
	UMAAL r3, lr, v7, v8
	STM ip, {r0-r3, lr}
	SUB ip, ip, #0x0C
	// 8
	MOV lr, #0
	LDM ip, {r0-r3}
	UMAAL r0, lr, v8, v1
	UMAAL r1, lr, v8, v2
	UMAAL r2, lr, v8, v3
	UMAAL r3, lr, v8, v4
	STM ip!, {r0-r3}
	LDM ip, {r0-r3}
	UMAAL r0, lr, v8, v5
	UMAAL r1, lr, v8, v6
	UMAAL r2, lr, v8, v7
	UMAAL r3, lr, v8, v8
	STM ip, {r0-r3, lr}
	SUB r0, ip, #0x0C
	
	//Fast modular reduction
	LDM r0, {v1-v8}
	MOV ip, #1
	LDR r1, = tw
	// the middle value in the fast rection
	// w0 = c[8] + c[9] + c[10] + c[11];
    // w1 = c[8] + c[13];
    // w2 = c[9] + c[14];
    // w3 = c[14] + c[15];
    // w4 = w3 + c[13];
    // w5 = w4 + c[12];
    // w0 = w0 + w5;
	UMULL r2, r3, v1, ip		//  (r2, r3)  = c[8]
	UMLAL r2, r3, v2, ip		//  (r2, r3) += c[9]
	UMLAL r2, r3, v3, ip		//  (r2, r3) += c[10]
	UMLAL r2, r3, v4, ip		//  (r2, r3) += c[11]
	STM r1!, {r2-r3} 			// 	w0 = c[8] + c[9] + c[10] + c[11];
	UMULL r2, r3, v1, ip		//  (r2, r3)  = c[8]
	UMLAL r2, r3, v6, ip		//  (r2, r3) += c[13]
	STM r1!, {r2-r3} 			// 	w1 = c[8] + c[13];
	UMULL r2, r3, v2, ip		//  (r2, r3)  = c[9]
	UMLAL r2, r3, v7, ip		//  (r2, r3) += c[14]
	STM r1!, {r2-r3} 			//  w2 = c[9] + c[14];
	UMULL r2, r3, v7, ip		//  (r2, r3)  = c[9]
	UMLAL r2, r3, v8, ip		//  (r2, r3) += c[14]
	STM r1!, {r2-r3} 			//  w3 = c[14] + c[15];
	UMLAL r2, r3, v6, ip		//  (r2, r3) += c[13]
	STM r1!, {r2-r3} 			//  w4 = w3 + c[13];
	UMLAL r2, r3, v5, ip		//  (r2, r3) += c[12]
	STM r1!, {r2-r3} 			//  w5 = w4 + c[12];
	SUB r1, r1, #0x30
	LDM r1, {v1-v2}				//  (v1, v2) = w0
	ADDS r2, r2, v1				// 	
	ADCS r3, r3, v2				//  (r2, r3) = w0 + w5
	STM r1, {r2-r3} 			//	w0 += w5

	
	// the registerlist {r2,r3,r4,r5,r6,r7} set can store three intermediate values {rw0, rw1, rw2}, rw0 = w0 now.
	LDR r4, [r1, #0x08]
	LDR r5, [r1, #0x0C]			// {rw0, rw1, rw2} = {w0, w1, -}
	LDR r6, [r1, #0x20]
	LDR r7, [r1, #0x24]			// {rw0, rw1, rw2} = {w0, w1, w4}

	//  Load c[0]-c[3], set ip = 0, carry = lr = 0
	SUB r0, r0, #0x20
	LDM r0, {v5-v8}				// (v5-v8) = (c[0]-c[3])
	MOV ip, #0					// ip = 0
	MOV lr, #0					// carry = 0

	//  c[0] += w0 + w4;
	ADDS v5, v5, r2
	ADCS lr, lr, r3  			// c[0] += w0;
	ADDS v5, v5, r6
	ADCS lr, lr, r7  			// c[0] += w4;
	

	// c[1] += w0 + w4 - w1;
	UMAAL v6, lr, r0, ip        // c[1] += carry
	ADDS v6, v6, r2
	ADCS lr, lr, r3  			// c[1] += w0;
	ADDS v6, v6, r6
	ADCS lr, lr, r7  			// c[0] += w4;
	SUBS v6, v6, r4
	SBCS lr, lr, r5  			// c[1] -= w1;

	// c[2] -= w1 + w2
	LDR r2, [r1, #0x10]
	LDR r3, [r1, #0x14]			// {rw0, rw1, rw2} = {w2, w1, w4}
	UMAAL v7, lr, r0, ip        // c[2] += carry
	SUBS v7, v7, r4
	SBCS lr, lr, r5  			// c[2] -= w1;
	SUBS v7, v7, r2
	SBCS lr, lr, r3  			// c[2] -= w2;

	// c[3] += w5 + w1;
	ADD v8, v8, lr
	MOV lr, #0					// c[3] -= brrow
	ADDS v8, r4
	ADCS lr, r5					// c[3] += w1
	LDR r4, [r1, #0x28]
	LDR r5, [r1, #0x2C]			// {rw0, rw1, rw2} = {w2, w5, w4}
	ADDS v8, r4
	ADCS lr, r5					// c[3] += w5

	// Stroe c[0]-c[3]
	// Load  c[4]-c[7]
	STM r0!, {v5-v8}
	LDM r0,  {v5-v8}
	// c[4] += w5 + w2;
	UMAAL v5, lr, r0, ip        // c[4] += carry
	ADDS v5, r2
	ADCS lr, r3					// c[4] += w2
	ADDS v5, r4
	ADCS lr, r5					// c[4] += w5

	// c[5] += w4 
	UMAAL v6, lr, r0, ip        // c[5] += carry
	ADDS v6, r6
	ADCS lr, r7					// c[5] += w4

	// c[6] += w3
	LDR r2, [r1, #0x18]
	LDR r3, [r1, #0x1C]			// {rw0, rw1, rw2} = {w3, w5, w4}
	UMAAL v7, lr, r0, ip        // c[6] += carry	
	ADDS v7, r2
	ADCS lr, r3					// c[6] += w3

	// c[7] += w0 + w5
	LDR r6, [r1, #0x00]
	LDR r7, [r1, #0x04]			// {rw0, rw1, rw2} = {w3, w5, w0}
	UMAAL v8, lr, r0, ip        // c[7] += carry	
	ADDS v8, r6
	ADCS lr, r7					// c[7] += w0
	ADDS v8, r4
	ADCS lr, r5					// c[7] += w5

	// Load c[0]-c[3] to {v1-v4}
	SUB r0, #0x10
	LDM r0, {v1-v4}
	// Load c[10] c[11] c[15]
	LDR r1, [r0, #10 << 2]
	LDR r2, [r0, #11 << 2]
	LDR r3, [r0, #15 << 2]

	ADDS v4, r2
	ADCS v5, #0
	ADCS v6, r1
	ADCS v7, r2
	ADCS v8, r3
	ADCS lr, #0
	ADCS v6, r3
	ADCS v7, #0
	ADCS v8, #0
	ADCS lr, #0
	ADDS v1, lr
	ADCS v2, #0
	ADCS v3, #0
	ADCS v4, lr
	ADCS v5, #0
	ADCS v6, #0
	ADCS v7, #0
	ADCS v8, lr
	SUBS v3, lr
	SBCS v4, #0
	SBCS v5, #0
	SBCS v6, #0
	SBCS v7, #0
	SBCS v8, #0
	POP {r0}
	POP {ip, lr}
 	SAVE
.end
#endif