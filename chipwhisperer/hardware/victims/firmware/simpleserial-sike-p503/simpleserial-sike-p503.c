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
#include "P503_internal.h"

/* ========================================================================== */
/*                                  CONSTANTS                                 */
/* ========================================================================== */

/* Radixes in 8 bits */
#define UINT8_RADIX 8
#define UINT8_LOG2RADIX 3

/* SIKEp503 constants */
#define SIKE_BOBSK3_P503_BYTES SECRETKEY_B_BYTES /* ((252 - 1 + 7) / 8) = 32 bytes */
#define SIKE_ALICEPK_P503_BYTES 402 /* 2*3*503 bits (R0->x[0], R0->x[1], R->x[0], R->x[1], R2->x[0], R2->x[1]) + 16 bytes (MSG) */

/* ChaCha seed length */
#define SEED_BYTES 16

/* Z = 0x0000ECEEA7BD2EDAE93254545F77410CD801A4FB559FACD4B90FF404FC00000000000000000000000000000000000000000000000000742C */
const digit_t custom_Montgomery_one[NWORDS_FIELD]  = {
    0x000003F9, 0x00000000,
    0x00000000, 0x00000000,
    0x00000000, 0x00000000,
    0x00000000, 0xB4000000,
    0xA6DED2B4, 0x63CB1A6E,
    0x667EB37D, 0x51689D8D,
    0x1AB24142, 0x8ACD77C7,
    0xC60F5953, 0x0026FBAE
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
uint8_t sk[SIKE_BOBSK3_P503_BYTES] = { 0x00 };

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
    fp2mul503_mont(R->X, rand_R, R->X);
    fp2mul503_mont(R->Z, rand_R, R->Z);
    fp2mul503_mont(R0->X, rand_R0, R0->X);
    fp2mul503_mont(R0->Z, rand_R0, R0->Z);
    fp2mul503_mont(R2->X, rand_R2, R2->X);
    fp2mul503_mont(R2->Z, rand_R2, R2->Z);
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
    for (int i=0; i < SIKE_BOBSK3_P503_BYTES; ++i)
    {
        sk[i] = k[i];
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

    fpcopy503((digit_t*)&custom_Montgomery_one, A24[0]);
    fp2add503(A24, A24, A24);
    fp2add503(A, A24, A24);
    fp2div2_503(A24, A24);
    fp2div2_503(A24, A24);

    fpcopy503((digit_t*)&custom_Montgomery_one, (digit_t*)R2->Z);
    fpcopy503((digit_t*)&custom_Montgomery_one, (digit_t*)R->Z);
    fpcopy503((digit_t*)&custom_Montgomery_one, (digit_t*)R0->Z);
    fpzero503((digit_t*)(R->Z)[1]);
    fpzero503((digit_t*)(R0->Z)[1]);
    fpzero503((digit_t*)(R2->Z)[1]);

    /* Reset LADDER3PT state */
    prevbit = 0;
    iteration = 0;

    /* Randomize coordinates (put at last to avoid side effects) */
    randomize_coordinates();

    return 0x00;
}

uint8_t run_loop_iteration(uint8_t* unused)
{ // Run LADDER3PT loop iteration
    int bit = 0, swap = 0;
    digit_t mask;

    (void) unused;

    bit = (sk[iteration >> UINT8_LOG2RADIX] >> (iteration & (UINT8_RADIX - 1))) & 1;
    swap = bit ^ prevbit;
    mask = 0 - (digit_t)swap;

    custom_swap_points(R, R2, mask);
    xDBLADD(R0, R2, R->X, A24);
    fp2mul503_mont(R2->X, R->Z, R2->X);

    /* Update loop iteration */
    prevbit = bit;
    iteration = (iteration < OBOB_BITS - 1 ? iteration + 1 : 0);

    /* Randomize coordinates (put at last to avoid side effects) */
    randomize_coordinates();

    return (uint8_t) swap;
}

uint8_t test_trig(uint8_t* x)
{ // Test trigger
    trigger_high();
    while (x[0]-- != 0);
    trigger_low();

    return 0x00;
}

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Prints "SIKE-p503" */
    putch('S');
    putch('I');
    putch('K');
    putch('E');
    putch('-');
    putch('p');
    putch('5');
    putch('0');
    putch('3');

    simpleserial_init();

    /* Functions programmed to attack SIKEp503 */
    simpleserial_addcmd('s', SEED_BYTES, get_seed);
    simpleserial_addcmd('k', SIKE_BOBSK3_P503_BYTES, get_key);
    simpleserial_addcmd('p', SIKE_ALICEPK_P503_BYTES, get_pt);
    simpleserial_addcmd('n', 0, run_loop_iteration);
    /* Additional (optional) functions for testing purpose */
    simpleserial_addcmd('t', 1, test_trig);

    while(1)
        simpleserial_get();
}
