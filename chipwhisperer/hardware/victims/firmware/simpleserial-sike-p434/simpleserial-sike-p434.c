/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "api.h"
#include "P434_internal.h"

/* ========================================================================== */
/*                                  CONSTANTS                                 */
/* ========================================================================== */

/* Radixes in 8 bits */
#define UINT8_RADIX 8
#define UINT8_LOG2RADIX 3

/* SIKEp434 constants */
#define SIKE_BOBSK3_P434_BYTES SECRETKEY_B_BYTES /* ((218 - 1 + 7) / 8) = 28 bytes */
#define SIKE_ALICEPK_P434_BYTES 346 /* 2*3*434 bits (R0->x[0], R0->x[1], R->x[0], R->x[1], R2->x[0], R2->x[1]) + 16 bytes (MSG) */

/* ChaCha seed length */
#define SEED_BYTES 16

/* Z = 0x0000ECEEA7BD2EDAE93254545F77410CD801A4FB559FACD4B90FF404FC00000000000000000000000000000000000000000000000000742C */
const digit_t custom_Montgomery_one[NWORDS_FIELD] = {
   0x0000742C, 0x00000000,
   0x00000000, 0x00000000,
   0x00000000, 0x00000000,
   0xFC000000, 0xB90FF404,
   0x559FACD4, 0xD801A4FB, 
   0x5F77410C, 0xE9325454,
   0xA7BD2EDA, 0x0000ECEE
};

/* ========================================================================== */
/*                                   CHACHA                                   */
/* ========================================================================== */

/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.
*/

#define U8V(v) ((uint8_t) ((v) & 0XFF))
#define U32V(v) ((uint32_t) ((v) & 0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define ROTL32(v, n) \
    (U32V((v) << (n)) | ((v) >> (32 - (n))))

/* 
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
  uint32_t input[16]; /* could be compressed */
} ECRYPT_ctx;

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
    x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
    x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
    x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
    x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void salsa20_wordtobyte(uint8_t output[64], const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    for (i = 0;i < 16;++i) x[i] = input[i];
    for (i = 8;i > 0;i -= 2) {
        QUARTERROUND( 0, 4, 8,12)
        QUARTERROUND( 1, 5, 9,13)
        QUARTERROUND( 2, 6,10,14)
        QUARTERROUND( 3, 7,11,15)
        QUARTERROUND( 0, 5,10,15)
        QUARTERROUND( 1, 6,11,12)
        QUARTERROUND( 2, 7, 8,13)
        QUARTERROUND( 3, 4, 9,14)
    }
    for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
    /*
     * there is absolutely no way of making the following line compile,
    for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
     */
    for (i = 0;i < 16;++i)
    {
        output[4*i + 0] = U8V(x[i] >> 0);
        output[4*i + 1] = U8V(x[i] >> 8);
        output[4*i + 2] = U8V(x[i] >> 16);
        output[4*i + 3] = U8V(x[i] >> 24);
    }
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void ECRYPT_keysetup(ECRYPT_ctx *x, const uint8_t *k, uint32_t kbits, uint32_t ivbits)
{
    const char *constants;

    x->input[4] = U8TO32_LITTLE(k + 0);
    x->input[5] = U8TO32_LITTLE(k + 4);
    x->input[6] = U8TO32_LITTLE(k + 8);
    x->input[7] = U8TO32_LITTLE(k + 12);
    if (kbits == 256) { /* recommended */
        k += 16;
        constants = sigma;
    } else { /* kbits == 128 */
        constants = tau;
    }
    x->input[8] = U8TO32_LITTLE(k + 0);
    x->input[9] = U8TO32_LITTLE(k + 4);
    x->input[10] = U8TO32_LITTLE(k + 8);
    x->input[11] = U8TO32_LITTLE(k + 12);
    x->input[0] = U8TO32_LITTLE(constants + 0);
    x->input[1] = U8TO32_LITTLE(constants + 4);
    x->input[2] = U8TO32_LITTLE(constants + 8);
    x->input[3] = U8TO32_LITTLE(constants + 12);
}

void ECRYPT_ivsetup(ECRYPT_ctx *x, const uint8_t *iv)
{
    x->input[12] = 0;
    x->input[13] = 0;
    x->input[14] = U8TO32_LITTLE(iv + 0);
    x->input[15] = U8TO32_LITTLE(iv + 4);
}

void ECRYPT_encrypt_bytes(ECRYPT_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes)
{
    uint8_t output[64] = { 0x00 };
    int i = 0;

    if (!bytes) return;
    for (;;) {
        salsa20_wordtobyte(output,x->input);
        x->input[12] = PLUSONE(x->input[12]);
        if (!x->input[12]) {
            x->input[13] = PLUSONE(x->input[13]);
            /* stopping at 2^70 bytes per nonce is user's responsibility */
        }
        if (bytes <= 64) {
            for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
            return;
        }
        for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
        bytes -= 64;
        c += 64;
        m += 64;
    }
}

void ECRYPT_keystream_bytes(ECRYPT_ctx *x, uint8_t *stream, uint32_t bytes)
{
    uint32_t i;
    for (i = 0; i < bytes; ++i) stream[i] = 0;
    ECRYPT_encrypt_bytes(x, stream, stream, bytes);
}

/* ========================================================================== */
/*                                  GLOBALS                                   */
/* ========================================================================== */

/* Bob's private key involved in LADDER3PT */
uint8_t sk[SIKE_BOBSK3_P434_BYTES] = { 0x00 };

/* ChaCha context */
ECRYPT_ctx chacha_ctx;

/* LADDER3PT variables */
int prevbit = 0;
int iteration = 0;
f2elm_t A24 = {0};
point_proj_t R = {0};
point_proj_t R2 = {0};
point_proj_t R0 = {0};

/* ========================================================================== */
/*                             INTERNAL FUNCTIONS                             */
/* ========================================================================== */

static void fp2_decode(const unsigned char *enc, f2elm_t x)
{ // Parse byte sequence back into GF(p^2) element, and conversion to Montgomery representation
    unsigned int i;

    for (i = 0; i < 2*(MAXBITS_FIELD / 8); i++) ((unsigned char *)x)[i] = 0;
    for (i = 0; i < FP2_ENCODED_BYTES / 2; i++) {
        ((unsigned char*)x)[i] = enc[i];
        ((unsigned char*)x)[i + MAXBITS_FIELD / 8] = enc[i + FP2_ENCODED_BYTES / 2];
    }
    to_fp2mont(x, x);
}

static void custom_swap_points(point_proj_t P, point_proj_t Q, const digit_t option)
{ // Swap points.
  // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
    digit_t temp = 0;
    unsigned int i = 0;

    trigger_high();

    for (i = 0; i < NWORDS_FIELD; i++) {
        temp = option & (P->X[0][i] ^ Q->X[0][i]);
        P->X[0][i] = temp ^ P->X[0][i];
        Q->X[0][i] = temp ^ Q->X[0][i];
        temp = option & (P->Z[0][i] ^ Q->Z[0][i]);
        P->Z[0][i] = temp ^ P->Z[0][i];
        Q->Z[0][i] = temp ^ Q->Z[0][i];
        temp = option & (P->X[1][i] ^ Q->X[1][i]);
        P->X[1][i] = temp ^ P->X[1][i];
        Q->X[1][i] = temp ^ Q->X[1][i];
        temp = option & (P->Z[1][i] ^ Q->Z[1][i]);
        P->Z[1][i] = temp ^ P->Z[1][i];
        Q->Z[1][i] = temp ^ Q->Z[1][i];
    }

    trigger_low();

}

static void custom_prng_nextbytes(uint8_t* output, const uint32_t bytes)
{ // Draw next random bytes
    ECRYPT_keystream_bytes(&chacha_ctx, output, bytes);
}

static void randomize_coordinates(void)
{ // Implement coordinate randomization
    f2elm_t rand_R  = {0}, rand_R0 = {0}, rand_R2 = {0};
    uint8_t randbytes[3*FP2_ENCODED_BYTES] = {0}; /* 6*110 = 660 */

    /* Draw random bytes */
    custom_prng_nextbytes(randbytes, 3*FP2_ENCODED_BYTES);

    /* Decode random bytes in element of GF(p^2) */
    fp2_decode(randbytes + 0*FP2_ENCODED_BYTES, rand_R);  /*   0:110 */
    fp2_decode(randbytes + 1*FP2_ENCODED_BYTES, rand_R0); /* 110:220 */
    fp2_decode(randbytes + 2*FP2_ENCODED_BYTES, rand_R2); /* 220:330 */

    /* Mask coordinates with randomly drawn elements */
    fp2mul434_mont(R->X, rand_R, R->X);
    fp2mul434_mont(R->Z, rand_R, R->Z);
    fp2mul434_mont(R0->X, rand_R0, R0->X);
    fp2mul434_mont(R0->Z, rand_R0, R0->Z);
    fp2mul434_mont(R2->X, rand_R2, R2->X);
    fp2mul434_mont(R2->Z, rand_R2, R2->Z);
}

void ladderstep(void)
{ // Perform one step of the LADDER3PT (used in run_safeswap)
    xDBLADD(R0, R2, R->X, A24);
    fp2mul434_mont(R2->X, R->Z, R2->X);
    randomize_coordinates();
}

/* ========================================================================== */
/*                             EXTERNAL FUNCTIONS                             */
/* ========================================================================== */

uint8_t get_seed(uint8_t* s, uint8_t len)
{ // Set ChaCha seed (and IV to zero)
    int i = 0;
    uint8_t iv[8] = { 0x00 };

    for (i = 0; i < 8; ++i) {
        iv[i] = 0x00;
    }

    ECRYPT_keysetup(&chacha_ctx, s, 128, 0);
    ECRYPT_ivsetup(&chacha_ctx, iv);

    return 0x00;
}

uint8_t get_key(uint8_t* k, uint8_t len)
{ // Set private key involved in LADDER3PT
    int i = 0;
    for (i=0; i < SIKE_BOBSK3_P434_BYTES; ++i)
    {
        sk[i] = k[i];
    }
    for (i=0; i < SIKE_BOBSK3_P434_BYTES/4; ++i)
    {
        extsk[i] = U8TO32_LITTLE((sk+4*i));
    }
    return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{ // Initialize LADDER3PT without performing for-loop
    f2elm_t A = {0};

    // Initialize images of Alice's basis
    fp2_decode(pt, R->X); /* 0:110 */
    fp2_decode(pt + FP2_ENCODED_BYTES, R0->X); /* 110:220 */
    fp2_decode(pt + 2*FP2_ENCODED_BYTES, R2->X); /* 220:330 */

    // Initialize constants: A24plus = A+2C, A24minus = A-2C, where C=1
    get_A(R->X, R0->X, R2->X, A);

    fpcopy434((digit_t*)&custom_Montgomery_one, A24[0]);
    fp2add434(A24, A24, A24);
    fp2add434(A, A24, A24);
    fp2div2_434(A24, A24);
    fp2div2_434(A24, A24);

    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R2->Z);
    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R->Z);
    fpcopy434((digit_t*)&custom_Montgomery_one, (digit_t*)R0->Z);
    fpzero434((digit_t*)(R->Z)[1]);
    fpzero434((digit_t*)(R0->Z)[1]);
    fpzero434((digit_t*)(R2->Z)[1]);

    /* Reset LADDER3PT state */
    prevbit = 0;
    iteration = 0;

    /* Randomize coordinates (put at last to avoid side effects) */
    randomize_coordinates();

    return 0x00;
}

uint8_t run_safeswap(uint8_t* unused, uint8_t len)
{ // Run LADDER3PT loop iteration with countermeasure
    uint8_t rand[8];
    register uint32_t r1 asm("r4") = 0x00000000;
    register uint32_t r2 asm("r5") = 0x00000000;
    register uint32_t m1 asm("r6") = 0x00000000;
    register uint32_t m2 asm("r7") = 0x00000000;
    register uint32_t bit asm("r8") = 0x00000000;
    register uint32_t swap asm("r9") = 0x00000000;

    (void) unused;

    custom_prng_nextbytes(rand, 8);
    r1 = U8TO32_LITTLE((rand+0));
    r2 = U8TO32_LITTLE((rand+4));

    trigger_high();

    bit = (sk[iteration >> UINT8_LOG2RADIX] >> (iteration & (UINT8_RADIX - 1))) & 1;
    swap = bit ^ prevbit;

    /* Secure masks generation */
    asm volatile(
        "and.w %[u1], %[u1], #0xFFFFFFFD    \n\t" /* u1 = randombytes(4) & 0xFFFFFFFD */
        "and.w %[m1], %[u2], #0xFFFFFFFE    \n\t" /* m1 = randombytes(4) & 0xFFFFFFFE */
        "add.w %[u2], %[u1], %[s]           \n\t" /* u2 = u1 + swap */
        "add.w %[m2], %[m1], %[s]           \n\t" /* r  = m1 + swap */
        "add.w %[u1], %[u1], #1             \n\t" /* u1 = u1 + 1 */
        "mul.w %[u1], %[u1], %[m2]          \n\t" /* u1 = u1*r */
        "add.w %[u2], %[u2], %[s]           \n\t" /* u2 = u2 + swap */
        "mul.w %[u2], %[u2], %[m2]          \n\t" /* u2 = u2*r */
        "sub.w %[m2], %[u1], %[u2]          \n\t" /* m2 = u1 - u2 */
        : [s]"+r" (swap),
          [u1]"+r" (r1), [u2]"+r" (r2),
          [m1]"+r" (m1), [m2]"+r" (m2)
        :
        :);

    /* Secure swapping operation */
    asm volatile(
        /* The following is repeated for each word of R and R2 */
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t" /* tmp1 <- a ^ b */
        "and.w %[tmp1], %[mask1]   \n\t" /* tmp1 <- tmp1 & mask1 */
        "eor.w r11, r11, %[tmp1]   \n\t" /* b <-  b ^ tmp1 */
        "eor.w r10, r10, %[tmp1]   \n\t" /* a <- a ^ tmp1 */
        "eor.w %[tmp2], r10, r11   \n\t" /* tmp2 <- a ^ b */
        "str.w r11, [%[Q]]         \n\t" /* Q->X <- b */
        "and.w %[tmp2], %[mask2]   \n\t" /* tmp2 <- tmp2 & mask2 */
        "str.w r10, [%[P]]         \n\t" /* P->X <- a */
        "eor.w r11, r11, %[tmp2]   \n\t" /* b <- b ^ tmp2 */
        "eor.w r10, r10, %[tmp2]   \n\t" /* a <- a ^ tmp2 */
        "str.w r10, [%[P]], #4     \n\t" /* P->X <- a */
        "str.w r11, [%[Q]], #4     \n\t" /* Q->X <- b */

        /* Repeat above for a total of 56 times */
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"
        "ldr.w r10, [%[P]]         \n\t"
        "ldr.w r11, [%[Q]]         \n\t"
        "eor.w %[tmp1], r10, r11   \n\t"
        "and.w %[tmp1], %[mask1]   \n\t"
        "eor.w r11, r11, %[tmp1]   \n\t"
        "eor.w r10, r10, %[tmp1]   \n\t"
        "eor.w %[tmp2], r10, r11   \n\t"
        "str.w r11, [%[Q]]         \n\t"
        "and.w %[tmp2], %[mask2]   \n\t"
        "str.w r10, [%[P]]         \n\t"
        "eor.w r11, r11, %[tmp2]   \n\t"
        "eor.w r10, r10, %[tmp2]   \n\t"
        "str.w r10, [%[P]], #4     \n\t"
        "str.w r11, [%[Q]], #4     \n\t"

        : [tmp1]"+r" (r1), [tmp2]"+r" (r2), [mask1]"+r" (m1), [mask2]"+r" (m2)
        : [P]"r" (R), [Q]"r" (R2)
        : "r10", "r11");

    /*
     * IMPORTANT NOTE:
     *  The ladder step was put as a no-argument function because the assembly
     *  code would mess up the passing of arguments (i.e., in r0, r1, r2).
     *
     *  However, calling a function pushes registers onto the stack which
     *  creates a leakage that is STILL unable to exploit with respect to the
     *  clustering power analysis of the project.
     *
     *  Particular care should be brought in an actual implementation of SIKE.
     */
    ladderstep();

    /* Lowers trigger as far as possible from the assembly code */
    trigger_low();

    /* Update loop iteration */
    prevbit = bit;
    iteration = (iteration < OBOB_BITS - 1 ? iteration + 1 : 0);

    return (uint8_t) swap;
}
#endif

uint8_t run_loop_iteration(uint8_t* unused, uint8_t len)
{ // Run LADDER3PT loop iteration
    int bit = 0, swap = 0;
    digit_t mask;

    (void) unused;

    bit = (sk[iteration >> UINT8_LOG2RADIX] >> (iteration & (UINT8_RADIX - 1))) & 1;
    swap = bit ^ prevbit;
    mask = 0 - (digit_t)swap;

    custom_swap_points(R, R2, mask); /* This is the procedure attacked */

    xDBLADD(R0, R2, R->X, A24);
    fp2mul434_mont(R2->X, R->Z, R2->X);

    /* Update loop iteration */
    prevbit = bit;
    iteration = (iteration < OBOB_BITS - 1 ? iteration + 1 : 0);

    /* Randomize coordinates (put at last to avoid side effects) */
    randomize_coordinates();

    return (uint8_t) swap;
}

uint8_t test_trig(uint8_t* x, uint8_t len)
{ // Test trigger
    trigger_high();
    while (x[0]-- != 0);
    trigger_low();

    return 0x00;
}

#define PUTCHPOINT(P, i) do { for (i = 0; i < NWORDS_FIELD; ++i) putch((P)[i]); } while (0)

uint8_t retrieve_values(uint8_t* x, uint8_t len)
{ // Retrieve the current values of each elliptic curve point
  // This was used to manually test the correctness of the swapping operation
    size_t i = 0;

    switch (x[0]) {
        case 0x00:
            PUTCHPOINT(R0->X[0], i);
            PUTCHPOINT(R0->X[1], i);
            break;
        case 0x01:
            PUTCHPOINT(R0->Z[0], i);
            PUTCHPOINT(R0->Z[1], i);
            break;
        case 0x02:
            PUTCHPOINT(R->X[0], i);
            PUTCHPOINT(R->X[1], i);
            break;
        case 0x03:
            PUTCHPOINT(R->Z[0], i);
            PUTCHPOINT(R->Z[1], i);
            break;
        case 0x04:
            PUTCHPOINT(R2->X[0], i);
            PUTCHPOINT(R2->X[1], i);
            break;
        case 0x05:
            PUTCHPOINT(R2->Z[0], i);
            PUTCHPOINT(R2->Z[1], i);
        default:
            break;
    }

    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Prints "SIKE-p434" */
    putch('S');
    putch('I');
    putch('K');
    putch('E');
    putch('-');
    putch('p');
    putch('4');
    putch('3');
    putch('4');

    simpleserial_init();

    /* Functions programmed to attack SIKEp434 */
    simpleserial_addcmd('s', SEED_BYTES, get_seed);
    simpleserial_addcmd('k', SIKE_BOBSK3_P434_BYTES, get_key);
    simpleserial_addcmd('p', SIKE_ALICEPK_P434_BYTES, get_pt);
    simpleserial_addcmd('n', 0, run_loop_iteration);
    simpleserial_addcmd('m', 0, run_safeswap);
    /* Additional (optional) functions for testing purpose */
    simpleserial_addcmd('t', 1, test_trig);
    simpleserial_addcmd('r', 1, retrieve_values);

    while(1)
        simpleserial_get();
}
