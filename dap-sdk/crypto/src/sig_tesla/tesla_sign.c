/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: high-level functions of the signature scheme
**************************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "KeccakHash.h"
#include "SimpleFIPS202.h"
#include "tesla_params.h"

static void pack_sk(unsigned char *sk, poly *s, poly_k *e, unsigned char *seeds, tesla_param_t *p)
{    
    // Pack secret key sk. It does not apply full compression
    unsigned int i, k;
    if(p->kind <= 2) {
        int16_t *isk = (int16_t *)sk;

        for (i = 0; i < p->PARAM_N; i++)
            isk[i] = s[i];

        isk += p->PARAM_N;
        for (k = 0; k < p->PARAM_K; k++)
            for (i = 0; i < p->PARAM_N; i++)
                isk[k * p->PARAM_N + i] = e[k * p->PARAM_N + i];

        memcpy(&isk[p->PARAM_K * p->PARAM_N], seeds, 2 * CRYPTO_SEEDBYTES);
    }
    else {
        int8_t *isk = (int8_t *)sk;

        for (i = 0; i < p->PARAM_N; i++)
            isk[i] = s[i];

        isk += p->PARAM_N;
        for (k = 0; k < p->PARAM_K; k++)
            for (i = 0; i < p->PARAM_N; i++)
                isk[k * p->PARAM_N + i] = e[k * p->PARAM_N + i];

        memcpy(&isk[p->PARAM_K * p->PARAM_N], seeds, 2 * CRYPTO_SEEDBYTES);
    }
} 


static void encode_pk(unsigned char *pk, const poly_k *t, const unsigned char *seedA, tesla_param_t *p)
{   
    // Encode public key pk
    unsigned int i, j = 0;
    uint32_t *pt = (uint32_t*)pk;

    if(p->kind <= 1) {
        for (i = 0; i < (p->PARAM_N * p->PARAM_K * p->PARAM_Q_LOG/32); i += p->PARAM_Q_LOG) {
            pt[i   ] = t[j] | (t[j+1] << 23);
            pt[i+ 1] = (t[j+ 1] >>  9) | (t[j+ 2] << 14); pt[i+ 2] = (t[j+ 2] >> 18) | (t[j+ 3] <<  5) | (t[j+ 4] << 28);
            pt[i+ 3] = (t[j+ 4] >>  4) | (t[j+ 5] << 19);
            pt[i+ 4] = (t[j+ 5] >> 13) | (t[j+ 6] << 10); pt[i+ 5] = (t[j+ 6] >> 22) | (t[j+ 7] <<  1) | (t[j+ 8] << 24);
            pt[i+ 6] = (t[j+ 8] >>  8) | (t[j+ 9] << 15); pt[i+ 7] = (t[j+ 9] >> 17) | (t[j+10] <<  6) | (t[j+11] << 29);
            pt[i+ 8] = (t[j+11] >>  3) | (t[j+12] << 20);
            pt[i+ 9] = (t[j+12] >> 12) | (t[j+13] << 11); pt[i+10] = (t[j+13] >> 21) | (t[j+14] <<  2) | (t[j+15] << 25);
            pt[i+11] = (t[j+15] >>  7) | (t[j+16] << 16); pt[i+12] = (t[j+16] >> 16) | (t[j+17] <<  7) | (t[j+18] << 30);
            pt[i+13] = (t[j+18] >>  2) | (t[j+19] << 21);
            pt[i+14] = (t[j+19] >> 11) | (t[j+20] << 12); pt[i+15] = (t[j+20] >> 20) | (t[j+21] <<  3) | (t[j+22] << 26);
            pt[i+16] = (t[j+22] >>  6) | (t[j+23] << 17); pt[i+17] = (t[j+23] >> 15) | (t[j+24] <<  8) | (t[j+25] << 31);
            pt[i+18] = (t[j+25] >>  1) | (t[j+26] << 22);
            pt[i+19] = (t[j+26] >> 10) | (t[j+27] << 13); pt[i+20] = (t[j+27] >> 19) | (t[j+28] <<  4) | (t[j+29] << 27);
            pt[i+21] = (t[j+29] >>  5) | (t[j+30] << 18);
            pt[i+22] = (t[j+30] >> 14) | (t[j+31] <<  9);
            j += 32;
        }
    }
    if(p->kind == 2) {
        for (i = 0; i < (p->PARAM_N * p->PARAM_Q_LOG/32); i += (p->PARAM_Q_LOG/8)) {
            pt[i  ] = t[j] | (t[j+1] << 24);
            pt[i+1] = (t[j+1] >>  8) | (t[j+2] << 16);
            pt[i+2] = (t[j+2] >> 16) | (t[j+3] <<  8);
            j += 4;
        }
    }
    if(p->kind == 3) {
        for (i = 0; i < (p->PARAM_N * p->PARAM_K * p->PARAM_Q_LOG/32); i += p->PARAM_Q_LOG) {
            pt[i   ] = t[j] | (t[j+1] << 29);             pt[i+ 1] = (t[j+ 1] >>  3) | (t[j+ 2] << 26);
            pt[i+ 2] = (t[j+ 2] >>  6) | (t[j+ 3] << 23); pt[i+ 3] = (t[j+ 3] >>  9) | (t[j+ 4] << 20);
            pt[i+ 4] = (t[j+ 4] >> 12) | (t[j+ 5] << 17); pt[i+ 5] = (t[j+ 5] >> 15) | (t[j+ 6] << 14);
            pt[i+ 6] = (t[j+ 6] >> 18) | (t[j+ 7] << 11); pt[i+ 7] = (t[j+ 7] >> 21) | (t[j+ 8] <<  8);
            pt[i+ 8] = (t[j+ 8] >> 24) | (t[j+ 9] <<  5); pt[i+ 9] = (t[j+ 9] >> 27) | (t[j+10] <<  2) | (t[j+11] << 31);
            pt[i+10] = (t[j+11] >>  1) | (t[j+12] << 28); pt[i+11] = (t[j+12] >>  4) | (t[j+13] << 25);
            pt[i+12] = (t[j+13] >>  7) | (t[j+14] << 22); pt[i+13] = (t[j+14] >> 10) | (t[j+15] << 19);
            pt[i+14] = (t[j+15] >> 13) | (t[j+16] << 16); pt[i+15] = (t[j+16] >> 16) | (t[j+17] << 13);
            pt[i+16] = (t[j+17] >> 19) | (t[j+18] << 10); pt[i+17] = (t[j+18] >> 22) | (t[j+19] <<  7);
            pt[i+18] = (t[j+19] >> 25) | (t[j+20] <<  4); pt[i+19] = (t[j+20] >> 28) | (t[j+21] <<  1) | (t[j+22] << 30);
            pt[i+20] = (t[j+22] >>  2) | (t[j+23] << 27); pt[i+21] = (t[j+23] >>  5) | (t[j+24] << 24);
            pt[i+22] = (t[j+24] >>  8) | (t[j+25] << 21); pt[i+23] = (t[j+25] >> 11) | (t[j+26] << 18);
            pt[i+24] = (t[j+26] >> 14) | (t[j+27] << 15); pt[i+25] = (t[j+27] >> 17) | (t[j+28] << 12);
            pt[i+26] = (t[j+28] >> 20) | (t[j+29] <<  9); pt[i+27] = (t[j+29] >> 23) | (t[j+30] <<  6);
            pt[i+28] = (t[j+30] >> 26) | (t[j+31] <<  3);
            j += 32;
        }
    }
    if(p->kind == 4) {
        for (i = 0; i < p->PARAM_N * p->PARAM_K * p->PARAM_Q_LOG/32; i += p->PARAM_Q_LOG) {
            pt[i   ] = t[j] | (t[j+1] << 31);
            pt[i+ 1] = (t[j+ 1] >>  1) | (t[j+ 2] << 30); pt[i+ 2] = (t[j+ 2] >>  2) | (t[j+ 3] << 29);
            pt[i+ 3] = (t[j+ 3] >>  3) | (t[j+ 4] << 28); pt[i+ 4] = (t[j+ 4] >>  4) | (t[j+ 5] << 27);
            pt[i+ 5] = (t[j+ 5] >>  5) | (t[j+ 6] << 26); pt[i+ 6] = (t[j+ 6] >>  6) | (t[j+ 7] << 25);
            pt[i+ 7] = (t[j+ 7] >>  7) | (t[j+ 8] << 24); pt[i+ 8] = (t[j+ 8] >>  8) | (t[j+ 9] << 23);
            pt[i+ 9] = (t[j+ 9] >>  9) | (t[j+10] << 22); pt[i+10] = (t[j+10] >> 10) | (t[j+11] << 21);
            pt[i+11] = (t[j+11] >> 11) | (t[j+12] << 20); pt[i+12] = (t[j+12] >> 12) | (t[j+13] << 19);
            pt[i+13] = (t[j+13] >> 13) | (t[j+14] << 18); pt[i+14] = (t[j+14] >> 14) | (t[j+15] << 17);
            pt[i+15] = (t[j+15] >> 15) | (t[j+16] << 16); pt[i+16] = (t[j+16] >> 16) | (t[j+17] << 15);
            pt[i+17] = (t[j+17] >> 17) | (t[j+18] << 14); pt[i+18] = (t[j+18] >> 18) | (t[j+19] << 13);
            pt[i+19] = (t[j+19] >> 19) | (t[j+20] << 12); pt[i+20] = (t[j+20] >> 20) | (t[j+21] << 11);
            pt[i+21] = (t[j+21] >> 21) | (t[j+22] << 10); pt[i+22] = (t[j+22] >> 22) | (t[j+23] <<  9);
            pt[i+23] = (t[j+23] >> 23) | (t[j+24] <<  8); pt[i+24] = (t[j+24] >> 24) | (t[j+25] <<  7);
            pt[i+25] = (t[j+25] >> 25) | (t[j+26] <<  6); pt[i+26] = (t[j+26] >> 26) | (t[j+27] <<  5);
            pt[i+27] = (t[j+27] >> 27) | (t[j+28] <<  4); pt[i+28] = (t[j+28] >> 28) | (t[j+29] <<  3);
            pt[i+29] = (t[j+29] >> 29) | (t[j+30] <<  2); pt[i+30] = (t[j+30] >> 30) | (t[j+31] <<  1);
            j += 32;
        }
    }

    memcpy(&pk[p->PARAM_N * p->PARAM_K * p->PARAM_Q_LOG/8], seedA, CRYPTO_SEEDBYTES);
}


static void decode_pk(uint32_t *pk, unsigned char *seedA, const unsigned char *pk_in, tesla_param_t *p)
{    
    // Decode public key pk
    unsigned int i, j = 0;
    uint32_t *pt = (uint32_t*)pk_in, *pp = (uint32_t*)pk;
    uint32_t mask31 = (uint32_t)(1 << p->PARAM_Q_LOG) - 1;
    uint32_t mask23 = (uint32_t)(1 << p->PARAM_Q_LOG) - 1;
    uint32_t mask24 = (uint32_t)(1 << p->PARAM_Q_LOG) - 1;
    uint32_t mask29 = (uint32_t)(1 << p->PARAM_Q_LOG) - 1;

    if(p->kind <= 1) {
        for (i = 0; i < p->PARAM_N * p->PARAM_K; i += 32) {
            pp[i   ] = pt[j] & mask23;
            pp[i+ 1] = ((pt[j+ 0] >> 23) | (pt[j+ 1] <<  9)) & mask23;
            pp[i+ 2] = ((pt[j+ 1] >> 14) | (pt[j+ 2] << 18)) & mask23; pp[i+ 3] = (pt[j+ 2] >> 5) & mask23;
            pp[i+ 4] = ((pt[j+ 2] >> 28) | (pt[j+ 3] <<  4)) & mask23;
            pp[i+ 5] = ((pt[j+ 3] >> 19) | (pt[j+ 4] << 13)) & mask23;
            pp[i+ 6] = ((pt[j+ 4] >> 10) | (pt[j+ 5] << 22)) & mask23; pp[i+ 7] = (pt[j+ 5] >> 1) & mask23;
            pp[i+ 8] = ((pt[j+ 5] >> 24) | (pt[j+ 6] <<  8)) & mask23;
            pp[i+ 9] = ((pt[j+ 6] >> 15) | (pt[j+ 7] << 17)) & mask23; pp[i+10] = (pt[j+ 7] >> 6) & mask23;
            pp[i+11] = ((pt[j+ 7] >> 29) | (pt[j+ 8] <<  3)) & mask23;
            pp[i+12] = ((pt[j+ 8] >> 20) | (pt[j+ 9] << 12)) & mask23;
            pp[i+13] = ((pt[j+ 9] >> 11) | (pt[j+10] << 21)) & mask23; pp[i+14] = (pt[j+10] >> 2) & mask23;
            pp[i+15] = ((pt[j+10] >> 25) | (pt[j+11] <<  7)) & mask23;
            pp[i+16] = ((pt[j+11] >> 16) | (pt[j+12] << 16)) & mask23; pp[i+17] = (pt[j+12] >> 7) & mask23;
            pp[i+18] = ((pt[j+12] >> 30) | (pt[j+13] <<  2)) & mask23;
            pp[i+19] = ((pt[j+13] >> 21) | (pt[j+14] << 11)) & mask23;
            pp[i+20] = ((pt[j+14] >> 12) | (pt[j+15] << 20)) & mask23; pp[i+21] = (pt[j+15] >> 3) & mask23;
            pp[i+22] = ((pt[j+15] >> 26) | (pt[j+16] <<  6)) & mask23;
            pp[i+23] = ((pt[j+16] >> 17) | (pt[j+17] << 15)) & mask23; pp[i+24] = (pt[j+17] >> 8) & mask23;
            pp[i+25] = ((pt[j+17] >> 31) | (pt[j+18] <<  1)) & mask23;
            pp[i+26] = ((pt[j+18] >> 22) | (pt[j+19] << 10)) & mask23;
            pp[i+27] = ((pt[j+19] >> 13) | (pt[j+20] << 19)) & mask23; pp[i+28] = (pt[j+20] >> 4) & mask23;
            pp[i+29] = ((pt[j+20] >> 27) | (pt[j+21] <<  5)) & mask23;
            pp[i+30] = ((pt[j+21] >> 18) | (pt[j+22] << 14)) & mask23;
            pp[i+31] = pt[j+22] >> 9;
            j += 23;
        }
    }
    if(p->kind == 2) {
        for (i = 0; i < p->PARAM_N; i += 4) {
            pp[i  ] = pt[j] & mask24;
            pp[i+1] = ((pt[j  ] >> 24) | (pt[j+1] <<  8)) & mask24;
            pp[i+2] = ((pt[j+1] >> 16) | (pt[j+2] << 16)) & mask24;
            pp[i+3] = pt[j+2] >> 8;
            j += 3;
        }
    }
    if(p->kind == 3) {
        for (i = 0; i < p->PARAM_N * p->PARAM_K; i += 32) {
            pp[i   ] = pt[j] & mask29;
            pp[i+ 1] = ((pt[j+ 0] >> 29) | (pt[j+ 1] <<  3)) & mask29;
            pp[i+ 2] = ((pt[j+ 1] >> 26) | (pt[j+ 2] <<  6)) & mask29;
            pp[i+ 3] = ((pt[j+ 2] >> 23) | (pt[j+ 3] <<  9)) & mask29;
            pp[i+ 4] = ((pt[j+ 3] >> 20) | (pt[j+ 4] << 12)) & mask29;
            pp[i+ 5] = ((pt[j+ 4] >> 17) | (pt[j+ 5] << 15)) & mask29;
            pp[i+ 6] = ((pt[j+ 5] >> 14) | (pt[j+ 6] << 18)) & mask29;
            pp[i+ 7] = ((pt[j+ 6] >> 11) | (pt[j+ 7] << 21)) & mask29;
            pp[i+ 8] = ((pt[j+ 7] >>  8) | (pt[j+ 8] << 24)) & mask29;
            pp[i+ 9] = ((pt[j+ 8] >>  5) | (pt[j+ 9] << 27)) & mask29;
            pp[i+10] = (pt[j+ 9] >> 2) & mask29;
            pp[i+11] = ((pt[j+ 9] >> 31) | (pt[j+10] <<  1)) & mask29;
            pp[i+12] = ((pt[j+10] >> 28) | (pt[j+11] <<  4)) & mask29;
            pp[i+13] = ((pt[j+11] >> 25) | (pt[j+12] <<  7)) & mask29;
            pp[i+14] = ((pt[j+12] >> 22) | (pt[j+13] << 10)) & mask29;
            pp[i+15] = ((pt[j+13] >> 19) | (pt[j+14] << 13)) & mask29;
            pp[i+16] = ((pt[j+14] >> 16) | (pt[j+15] << 16)) & mask29;
            pp[i+17] = ((pt[j+15] >> 13) | (pt[j+16] << 19)) & mask29;
            pp[i+18] = ((pt[j+16] >> 10) | (pt[j+17] << 22)) & mask29;
            pp[i+19] = ((pt[j+17] >>  7) | (pt[j+18] << 25)) & mask29;
            pp[i+20] = ((pt[j+18] >>  4) | (pt[j+19] << 28)) & mask29;
            pp[i+21] = (pt[j+19] >> 1) & mask29;
            pp[i+22] = ((pt[j+19] >> 30) | (pt[j+20] <<  2)) & mask29;
            pp[i+23] = ((pt[j+20] >> 27) | (pt[j+21] <<  5)) & mask29;
            pp[i+24] = ((pt[j+21] >> 24) | (pt[j+22] <<  8)) & mask29;
            pp[i+25] = ((pt[j+22] >> 21) | (pt[j+23] << 11)) & mask29;
            pp[i+26] = ((pt[j+23] >> 18) | (pt[j+24] << 14)) & mask29;
            pp[i+27] = ((pt[j+24] >> 15) | (pt[j+25] << 17)) & mask29;
            pp[i+28] = ((pt[j+25] >> 12) | (pt[j+26] << 20)) & mask29;
            pp[i+29] = ((pt[j+26] >>  9) | (pt[j+27] << 23)) & mask29;
            pp[i+30] = ((pt[j+27] >>  6) | (pt[j+28] << 26)) & mask29;
            pp[i+31] = pt[j+28] >> 3;
            j += 29;
        }
    }
    if(p->kind == 4) {
        for (i = 0; i < p->PARAM_N * p->PARAM_K; i += 32) {
            pp[i   ] = pt[j] & mask31;
            pp[i+ 1] = ((pt[j+ 0] >> 31) | (pt[j+ 1] <<  1)) & mask31;  pp[i+ 2] = ((pt[j+ 1] >> 30) | (pt[j+ 2] <<  2)) & mask31;
            pp[i+ 3] = ((pt[j+ 2] >> 29) | (pt[j+ 3] <<  3)) & mask31;  pp[i+ 4] = ((pt[j+ 3] >> 28) | (pt[j+ 4] <<  4)) & mask31;
            pp[i+ 5] = ((pt[j+ 4] >> 27) | (pt[j+ 5] <<  5)) & mask31;  pp[i+ 6] = ((pt[j+ 5] >> 26) | (pt[j+ 6] <<  6)) & mask31;
            pp[i+ 7] = ((pt[j+ 6] >> 25) | (pt[j+ 7] <<  7)) & mask31;  pp[i+ 8] = ((pt[j+ 7] >> 24) | (pt[j+ 8] <<  8)) & mask31;
            pp[i+ 9] = ((pt[j+ 8] >> 23) | (pt[j+ 9] <<  9)) & mask31;  pp[i+10] = ((pt[j+ 9] >> 22) | (pt[j+10] << 10)) & mask31;
            pp[i+11] = ((pt[j+10] >> 21) | (pt[j+11] << 11)) & mask31;  pp[i+12] = ((pt[j+11] >> 20) | (pt[j+12] << 12)) & mask31;
            pp[i+13] = ((pt[j+12] >> 19) | (pt[j+13] << 13)) & mask31;  pp[i+14] = ((pt[j+13] >> 18) | (pt[j+14] << 14)) & mask31;
            pp[i+15] = ((pt[j+14] >> 17) | (pt[j+15] << 15)) & mask31;  pp[i+16] = ((pt[j+15] >> 16) | (pt[j+16] << 16)) & mask31;
            pp[i+17] = ((pt[j+16] >> 15) | (pt[j+17] << 17)) & mask31;  pp[i+18] = ((pt[j+17] >> 14) | (pt[j+18] << 18)) & mask31;
            pp[i+19] = ((pt[j+18] >> 13) | (pt[j+19] << 19)) & mask31;  pp[i+20] = ((pt[j+19] >> 12) | (pt[j+20] << 20)) & mask31;
            pp[i+21] = ((pt[j+20] >> 11) | (pt[j+21] << 21)) & mask31;  pp[i+22] = ((pt[j+21] >> 10) | (pt[j+22] << 22)) & mask31;
            pp[i+23] = ((pt[j+22] >>  9) | (pt[j+23] << 23)) & mask31;  pp[i+24] = ((pt[j+23] >>  8) | (pt[j+24] << 24)) & mask31;
            pp[i+25] = ((pt[j+24] >>  7) | (pt[j+25] << 25)) & mask31;  pp[i+26] = ((pt[j+25] >>  6) | (pt[j+26] << 26)) & mask31;
            pp[i+27] = ((pt[j+26] >>  5) | (pt[j+27] << 27)) & mask31;  pp[i+28] = ((pt[j+27] >>  4) | (pt[j+28] << 28)) & mask31;
            pp[i+29] = ((pt[j+28] >>  3) | (pt[j+29] << 29)) & mask31;  pp[i+30] = ((pt[j+29] >>  2) | (pt[j+30] << 30)) & mask31;
            pp[i+31] = pt[j+30] >> 1;
            j += 31;
        }
    }

    memcpy(seedA, &pk_in[p->PARAM_N * p->PARAM_K * p->PARAM_Q_LOG/8], CRYPTO_SEEDBYTES);
}


static void encode_sig(unsigned char *sm, unsigned char *c, poly *z, tesla_param_t *p)
{
    // Encode signature sm
    unsigned int i, j = 0;
    uint64_t *t = (uint64_t*)z;
    uint32_t *pt = (uint32_t*)sm;

    if(p->kind <= 1) {
        for (i = 0; i < (p->PARAM_N * p->PARAM_D/32); i += (p->PARAM_D)) {
            pt[i   ] = (t[j] & ((1<<21)-1)) | (t[j+1] << 21);
            pt[i+ 1] = ((t[j+ 1] >> 11) & ((1<<10)-1)) | ((t[j+ 2] & ((1<<21)-1)) << 10) | (t[j+ 3] << 31);
            pt[i+ 2] = ((t[j+ 3] >>  1) & ((1<<20)-1)) | (t[j+4] << 20);
            pt[i+ 3] = ((t[j+ 4] >> 12) & ((1<<9)-1 )) | ((t[j+ 5] & ((1<<21)-1)) <<  9) | (t[j+ 6] << 30);
            pt[i+ 4] = ((t[j+ 6] >>  2) & ((1<<19)-1)) | (t[j+7] << 19);
            pt[i+ 5] = ((t[j+ 7] >> 13) & ((1<<8)-1 )) | ((t[j+ 8] & ((1<<21)-1)) <<  8) | (t[j+ 9] << 29);
            pt[i+ 6] = ((t[j+ 9] >>  3) & ((1<<18)-1)) | (t[j+10] << 18);
            pt[i+ 7] = ((t[j+10] >> 14) & ((1<<7)-1 )) | ((t[j+11] & ((1<<21)-1)) <<  7) | (t[j+12] << 28);
            pt[i+ 8] = ((t[j+12] >>  4) & ((1<<17)-1)) | (t[j+13] << 17);
            pt[i+ 9] = ((t[j+13] >> 15) & ((1<<6)-1 )) | ((t[j+14] & ((1<<21)-1)) <<  6) | (t[j+15] << 27);
            pt[i+10] = ((t[j+15] >>  5) & ((1<<16)-1)) | (t[j+16] << 16);
            pt[i+11] = ((t[j+16] >> 16) & ((1<<5)-1 )) | ((t[j+17] & ((1<<21)-1)) <<  5) | (t[j+18] << 26);
            pt[i+12] = ((t[j+18] >>  6) & ((1<<15)-1)) | (t[j+19] << 15);
            pt[i+13] = ((t[j+19] >> 17) & ((1<<4)-1 )) | ((t[j+20] & ((1<<21)-1)) <<  4) | (t[j+21] << 25);
            pt[i+14] = ((t[j+21] >>  7) & ((1<<14)-1)) | (t[j+22] << 14);
            pt[i+15] = ((t[j+22] >> 18) & ((1<<3)-1 )) | ((t[j+23] & ((1<<21)-1)) <<  3) | (t[j+24] << 24);
            pt[i+16] = ((t[j+24] >>  8) & ((1<<13)-1)) | (t[j+25] << 13);
            pt[i+17] = ((t[j+25] >> 19) & ((1<<2)-1 )) | ((t[j+26] & ((1<<21)-1)) <<  2) | (t[j+27] << 23);
            pt[i+18] = ((t[j+27] >>  9) & ((1<<12)-1)) | (t[j+28] << 12);
            pt[i+19] = ((t[j+28] >> 20) & ((1<<1)-1 )) | ((t[j+29] & ((1<<21)-1)) <<  1) | (t[j+30] << 22);
            pt[i+20] = ((t[j+30] >> 10) & ((1<<11)-1)) | (t[j+31] << 11);
            j += 32;
        }
    }
    if(p->kind == 2 || p->kind == 3) {
        for (i = 0; i < (p->PARAM_N * p->PARAM_D/32); i += (p->PARAM_D/2)) {
            pt[i   ] = (t[j] & ((1<<22)-1)) | (t[j+1] << 22);
            pt[i+ 1] = ((t[j+ 1] >> 10) & ((1<<12)-1)) | (t[j+2] << 12);
            pt[i+ 2] = ((t[j+ 2] >> 20) & ((1<< 2)-1)) | ((t[j+ 3] & ((1<<22)-1)) << 2) | (t[j+ 4] << 24);
            pt[i+ 3] = ((t[j+ 4] >>  8) & ((1<<14)-1)) | (t[j+5] << 14);
            pt[i+ 4] = ((t[j+ 5] >> 18) & ((1<<4)-1 )) | ((t[j+ 6] & ((1<<22)-1)) << 4) | (t[j+ 7] << 26);
            pt[i+ 5] = ((t[j+ 7] >>  6) & ((1<<16)-1)) | (t[j+8] << 16);
            pt[i+ 6] = ((t[j+ 8] >> 16) & ((1<<6)-1 )) | ((t[j+ 9] & ((1<<22)-1)) << 6) | (t[j+10] << 28);
            pt[i+ 7] = ((t[j+10] >>  4) & ((1<<18)-1)) | (t[j+11] << 18);
            pt[i+ 8] = ((t[j+11] >> 14) & ((1<<8)-1 )) | ((t[j+12] & ((1<<22)-1)) << 8) | (t[j+13] << 30);
            pt[i+ 9] = ((t[j+13] >>  2) & ((1<<20)-1)) | (t[j+14] << 20);
            pt[i+10] = ((t[j+14] >> 12) & ((1<<10)-1)) | (t[j+15] << 10);
            j += 16;
        }
    }
    if(p->kind == 4) {
        for (i = 0; i < (p->PARAM_N * p->PARAM_D/32); i += (p->PARAM_D/8)) {
            pt[i  ] = (t[j] & ((1<<24)-1)) | (t[j+1] << 24);
            pt[i+1] = ((t[j+1] >>  8) & ((1<<16)-1)) | (t[j+2] << 16);
            pt[i+2] = ((t[j+2] >> 16) & ((1<< 8)-1)) | (t[j+3] <<  8);
            j += 4;
        }
    }

    memcpy(&sm[p->PARAM_N * p->PARAM_D/8], c, CRYPTO_C_BYTES);
}


static void decode_sig(unsigned char *c, poly *z, const unsigned char *sm, tesla_param_t *p)
{
    // Decode signature sm
    unsigned int i, j = 0;
    uint32_t *pt = (uint32_t*)sm;

    if(p->kind <= 1) {
        for (i = 0; i < p->PARAM_N; i += 32) {
            z[i   ] = ((int32_t)pt[j+ 0] << 11) >> 11; z[i+ 1] = (int32_t)(pt[j+ 0] >> 21) | ((int32_t)(pt[j+ 1] << 22) >> 11);
            z[i+ 2] = ((int32_t)pt[j+ 1] <<  1) >> 11; z[i+ 3] = (int32_t)(pt[j+ 1] >> 31) | ((int32_t)(pt[j+ 2] << 12) >> 11);
            z[i+ 4] = (int32_t)(pt[j+ 2] >> 20) | ((int32_t)(pt[j+ 3] << 23) >> 11);
            z[i+ 5] = (int32_t)(pt[j+ 3] <<  2) >> 11; z[i+ 6] = (int32_t)(pt[j+ 3] >> 30) | ((int32_t)(pt[j+ 4] << 13) >> 11);
            z[i+ 7] = (int32_t)(pt[j+ 4] >> 19) | ((int32_t)(pt[j+ 5] << 24) >> 11);
            z[i+ 8] = (int32_t)(pt[j+ 5] <<  3) >> 11; z[i+ 9] = (int32_t)(pt[j+ 5] >> 29) | ((int32_t)(pt[j+ 6] << 14) >> 11);
            z[i+10] = (int32_t)(pt[j+ 6] >> 18) | ((int32_t)(pt[j+ 7] << 25) >> 11);
            z[i+11] = (int32_t)(pt[j+ 7] <<  4) >> 11; z[i+12] = (int32_t)(pt[j+ 7] >> 28) | ((int32_t)(pt[j+ 8] << 15) >> 11);
            z[i+13] = (int32_t)(pt[j+ 8] >> 17) | ((int32_t)(pt[j+ 9] << 26) >> 11);
            z[i+14] = (int32_t)(pt[j+ 9] <<  5) >> 11; z[i+15] = (int32_t)(pt[j+ 9] >> 27) | ((int32_t)(pt[j+10] << 16) >> 11);
            z[i+16] = (int32_t)(pt[j+10] >> 16) | ((int32_t)(pt[j+11] << 27) >> 11);
            z[i+17] = (int32_t)(pt[j+11] <<  6) >> 11; z[i+18] = (int32_t)(pt[j+11] >> 26) | ((int32_t)(pt[j+12] << 17) >> 11);
            z[i+19] = (int32_t)(pt[j+12] >> 15) | ((int32_t)(pt[j+13] << 28) >> 11);
            z[i+20] = (int32_t)(pt[j+13] <<  7) >> 11; z[i+21] = (int32_t)(pt[j+13] >> 25) | ((int32_t)(pt[j+14] << 18) >> 11);
            z[i+22] = (int32_t)(pt[j+14] >> 14) | ((int32_t)(pt[j+15] << 29) >> 11);
            z[i+23] = (int32_t)(pt[j+15] <<  8) >> 11; z[i+24] = (int32_t)(pt[j+15] >> 24) | ((int32_t)(pt[j+16] << 19) >> 11);
            z[i+25] = (int32_t)(pt[j+16] >> 13) | ((int32_t)(pt[j+17] << 30) >> 11);
            z[i+26] = (int32_t)(pt[j+17] <<  9) >> 11; z[i+27] = (int32_t)(pt[j+17] >> 23) | ((int32_t)(pt[j+18] << 20) >> 11);
            z[i+28] = (int32_t)(pt[j+18] >> 12) | ((int32_t)(pt[j+19] << 31) >> 11);
            z[i+29] = (int32_t)(pt[j+19] << 10) >> 11; z[i+30] = (int32_t)(pt[j+19] >> 22) | ((int32_t)(pt[j+20] << 21) >> 11);
            z[i+31] = (int32_t)pt[j+20] >> 11;
            j += 21;
        }
    }
    if(p->kind == 2 || p->kind == 3) {
        for (i = 0; i < p->PARAM_N; i += 16) {
            z[i   ] = ((int32_t)pt[j+ 0] << 10) >> 10;
            z[i+ 1] = (int32_t)(pt[j+ 0] >> 22) | ((int32_t)(pt[j+ 1] << 20) >> 10);
            z[i+ 2] = (int32_t)(pt[j+ 1] >> 12) | ((int32_t)(pt[j+ 2] << 30) >> 10);
            z[i+ 3] = (int32_t)(pt[j+ 2] <<  8) >> 10;
            z[i+ 4] = (int32_t)(pt[j+ 2] >> 24) | ((int32_t)(pt[j+ 3] << 18) >> 10);
            z[i+ 5] = (int32_t)(pt[j+ 3] >> 14) | ((int32_t)(pt[j+ 4] << 28) >> 10);
            z[i+ 6] = (int32_t)(pt[j+ 4] <<  6) >> 10;
            z[i+ 7] = (int32_t)(pt[j+ 4] >> 26) | ((int32_t)(pt[j+ 5] << 16) >> 10);
            z[i+ 8] = (int32_t)(pt[j+ 5] >> 16) | ((int32_t)(pt[j+ 6] << 26) >> 10);
            z[i+ 9] = (int32_t)(pt[j+ 6] <<  4) >> 10;
            z[i+10] = (int32_t)(pt[j+ 6] >> 28) | ((int32_t)(pt[j+ 7] << 14) >> 10);
            z[i+11] = (int32_t)(pt[j+ 7] >> 18) | ((int32_t)(pt[j+ 8] << 24) >> 10);
            z[i+12] = (int32_t)(pt[j+ 8] <<  2) >> 10;
            z[i+13] = (int32_t)(pt[j+ 8] >> 30) | ((int32_t)(pt[j+ 9] << 12) >> 10);
            z[i+14] = (int32_t)(pt[j+ 9] >> 20) | ((int32_t)(pt[j+10] << 22) >> 10);
            z[i+15] = (int32_t)pt[j+10] >> 10;
            j += 11;
        }
    }
    if(p->kind == 4) {
        for (i = 0; i < p->PARAM_N; i += 4) {
            z[i  ] = ((int32_t)pt[j+0] << 8) >> 8;
            z[i+1] = (int32_t)((pt[j+0] >> 24) & ((1<< 8)-1)) | ((int32_t)(pt[j+1] << 16) >> 8);
            z[i+2] = (int32_t)((pt[j+1] >> 16) & ((1<<16)-1)) | ((int32_t)(pt[j+2] << 24) >> 8);
            z[i+3] = (int32_t)(pt[j+2]) >> 8;
            j += 3;
        }
    }

    memcpy(c, &sm[p->PARAM_N * p->PARAM_D/8], CRYPTO_C_BYTES);
}


void hash_vm(unsigned char *c_bin, poly_k *v, const unsigned char *m, unsigned long long mlen, tesla_param_t *p)
{
    // Hash to generate c'
    unsigned char *t = malloc((p->PARAM_K * p->PARAM_N + mlen) * sizeof(unsigned char));
    int64_t mask, cL, temp;
    unsigned int i, k, index;

    for (k = 0; k < p->PARAM_K; k++) {
        index = k * p->PARAM_N;
        for (i = 0; i < p->PARAM_N; i++) {
            temp = v[index];
            // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
            mask = ((int64_t)(p->PARAM_Q/2) - temp) >> 63;
            temp = ((temp - (int64_t)(p->PARAM_Q)) & mask) | (temp & ~mask);

            cL = temp & ((1 << (int64_t)(p->PARAM_D)) - 1);
            // If cL > 2^(d-1) then cL -= 2^d
            mask = (int64_t)((1 << ((int64_t)(p->PARAM_D) - 1)) - cL) >> 63;
            cL = ((cL - (1 << (int64_t)(p->PARAM_D))) & mask) | (cL & ~mask);
            t[index] = (unsigned char)((temp - cL) >> (int64_t)(p->PARAM_D));
            index += 1;
        }
    }
    memcpy(&t[p->PARAM_K * p->PARAM_N], m, mlen);

    if(p->kind == 0 || p->kind == 3)
        SHAKE128(c_bin, CRYPTO_C_BYTES, t, p->PARAM_K * p->PARAM_N + mlen);
    else
        SHAKE256(c_bin, CRYPTO_C_BYTES, t, p->PARAM_K * p->PARAM_N + mlen);

    free(t);
    t = NULL;
}


static __inline uint64_t Abs(int64_t value)
{ // Compute absolute value

    uint64_t mask = (uint64_t)(value >> 63);
    return ((mask ^ value) - mask);
}


static int test_rejection(poly *z, tesla_param_t *p)
{ // Check bounds for signature vector z during signing. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
  // This function leaks the position of the coefficient that fails the test (but this is independent of the secret data). 
  // It does not leak the sign of the coefficients.
    unsigned int i;

    for (i = 0; i < p->PARAM_N; i++) {
        if ((int64_t)Abs(z[i]) > ((int64_t)(p->PARAM_B) - (int64_t)(p->PARAM_U)))
            return 1;
    }
    return 0;
}


static int test_v(poly *v, tesla_param_t *p)
{ // Check bounds for w = v - ec during signature verification. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
  // This function leaks the position of the coefficient that fails the test (but this is independent of the secret data). 
  // It does not leak the sign of the coefficients.
    unsigned int i;
    int64_t mask, left, val;
    uint64_t t0, t1;

    for (i = 0; i < p->PARAM_N; i++) {
        // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
        mask = ((int64_t)(p->PARAM_Q/2) - v[i]) >> 63;
        val = ((v[i] - (int64_t)(p->PARAM_Q)) & mask) | (v[i] & ~mask);
        // If (Abs(val) < PARAM_Q/2 - PARAM_REJECTION) then t0 = 0, else t0 = 1
        t0 = (uint64_t)(~((int64_t)Abs(val) - ((int64_t)(p->PARAM_Q/2) - (int64_t)(p->PARAM_REJECTION)))) >> 63;

        left = val;
        val = (int32_t)((val + (1 << (p->PARAM_D - 1)) - 1) >> p->PARAM_D);
        val = left - (val << p->PARAM_D);
        // If (Abs(val) < (1<<(PARAM_D-1))-PARAM_REJECTION) then t1 = 0, else t1 = 1
        t1 = (uint64_t)(~((int64_t)Abs(val) - (int64_t)((1 << ((int64_t)(p->PARAM_D) - 1)) - (int64_t)(p->PARAM_REJECTION)))) >> 63;

        if ((t0 | t1) == 1)  // Returns 1 if any of the two tests failed
            return 1;
    }
    return 0;
}


static int test_z(poly *z, tesla_param_t *p)
{ // Check bounds for signature vector z during signature verification
  // Returns 0 if valid, otherwise outputs 1 if invalid (rejected)
    unsigned int i;

    for (i = 0; i < p->PARAM_N; i++) {
        if (z[i] < -(((int64_t)(p->PARAM_B) - (int64_t)(p->PARAM_U))) || z[i] > (((int64_t)(p->PARAM_B) - (int64_t)(p->PARAM_U))))
            return 1;
    }
    return 0;
}


static int check_ES(poly *z, int bound, tesla_param_t *p)
{    
    // Checks the generated polynomial e or s
    // Returns 0 if ok, otherwise returns 1
    unsigned int i, j, sum = 0, limit = p->PARAM_N;
    int16_t temp, mask;
    int16_t *list = malloc(p->PARAM_N * sizeof(int16_t));

    for (j = 0; j < p->PARAM_N; j++)
        list[j] = (int16_t)(Abs(z[j]));

    for (j = 0; j < p->PARAM_W; j++) {
        for (i = 0; i < limit - 1; i++) {
            // If list[i+1] > list[i] then exchange contents
            mask = (list[i+1] - list[i]) >> 15;
            temp = (list[i+1] & mask) | (list[i] & ~mask);
            list[i+1] = (list[i] & mask) | (list[i+1] & ~mask);
            list[i] = temp;
        }
        sum += list[limit-1];
        limit -= 1;
    }
    free(list);
    list = NULL;

    if (sum > (unsigned int)bound)
        return 1;
    return 0;
}

/********************************************************************************************
* Name:        sparse_mul16
* Description: performs sparse polynomial multiplication
* Parameters:  inputs:
*              - const unsigned char* sk: part of the secret key
*              - const uint32_t pos_list[PARAM_W]: list of indices of nonzero elements in c
*              - const int16_t sign_list[PARAM_W]: list of signs of nonzero elements in c
*              outputs:
*              - poly prod: product of 2 polynomials
*
* Note: pos_list[] and sign_list[] contain public information since c is public
*********************************************************************************************/
static void sparse_mul16(poly *prod, const unsigned char *sk, const uint32_t *pos_list, const int16_t *sign_list, tesla_param_t *p)
{
    unsigned int i, j, pos;
    int16_t *t = (int16_t*)sk;

    for (i = 0; i < p->PARAM_N; i++)
        prod[i] = 0;

    for (i = 0; i < p->PARAM_W; i++) {
        pos = pos_list[i];
        for (j = 0; j < pos; j++) {
            prod[j] = prod[j] - sign_list[i] * t[j + p->PARAM_N - pos];
        }
        for (j = pos; j < p->PARAM_N; j++) {
            prod[j] = prod[j] + sign_list[i] * t[j - pos];
        }
    }
}

/********************************************************************************************
* Name:        sparse_mul8
* Description: performs sparse polynomial multiplication
* Parameters:  inputs:
*              - const unsigned char* sk: part of the secret key
*              - const uint32_t pos_list[PARAM_W]: list of indices of nonzero elements in c
*              - const int16_t sign_list[PARAM_W]: list of signs of nonzero elements in c
*              outputs:
*              - poly prod: product of 2 polynomials
*
* Note: pos_list[] and sign_list[] contain public information since c is public
*********************************************************************************************/
static void sparse_mul8(poly *prod, const unsigned char *sk, const uint32_t *pos_list, const int16_t *sign_list, tesla_param_t *p)
{
    unsigned int i, j, pos;
    int8_t *t = (int8_t*)sk;

    for (i = 0; i < p->PARAM_N; i++)
        prod[i] = 0;

    for (i = 0; i < p->PARAM_W; i++) {
        pos = pos_list[i];
        for (j = 0; j < pos; j++) {
            prod[j] = prod[j] - sign_list[i] * t[j + p->PARAM_N - pos];
        }
        for (j = pos; j < p->PARAM_N; j++) {
            prod[j] = prod[j] + sign_list[i] * t[j - pos];
        }
    }
}

/********************************************************************************************
* Name:        sparse_mul32
* Description: performs sparse polynomial multiplication 
* Parameters:  inputs:
*              - const int32_t* pk: part of the public key
*              - const uint32_t pos_list[PARAM_W]: list of indices of nonzero elements in c
*              - const int16_t sign_list[PARAM_W]: list of signs of nonzero elements in c
*              outputs:
*              - poly prod: product of 2 polynomials
*********************************************************************************************/
static void sparse_mul32(poly *prod, const int32_t *pk, const uint32_t *pos_list, const int16_t *sign_list, tesla_param_t *p)
{   
    unsigned int i, j, pos;

    for (i = 0; i < p->PARAM_N; i++)
        prod[i] = 0;

    for (i = 0; i < p->PARAM_W; i++) {
        pos = pos_list[i];
        for (j = 0; j < pos; j++) {
            prod[j] = prod[j] - sign_list[i] * pk[j + p->PARAM_N - pos];
        }
        for (j = pos; j < p->PARAM_N; j++) {
            prod[j] = prod[j] + sign_list[i] * pk[j-pos];
        }
    }
    for (i = 0; i < p->PARAM_N; i++)
        prod[i] = barr_reduce(prod[i], p);
}

/********************************************************************************************/
void tesla_private_key_delete(tesla_private_key_t *private_key)
{

    if(private_key) {
        free(private_key->data);
        private_key->data = NULL;
        free(private_key);
    }
}

void tesla_public_key_delete(tesla_public_key_t *public_key)
{
    if(public_key) {
        free(public_key->data);
        public_key->data = NULL;
        free(public_key);
    }
}

void tesla_private_and_public_keys_delete(tesla_private_key_t *private_key, tesla_public_key_t *public_key){
    if(private_key) {
        free(private_key->data);
        private_key->data = NULL;
    }
    if(public_key) {
        free(public_key->data);
        public_key->data = NULL;
    }
}

/********************************************************************************************/
static int32_t tesla_private_and_public_keys_init(tesla_private_key_t *private_key, tesla_public_key_t *public_key, tesla_param_t *p){

    unsigned char *f = NULL, *g = NULL;    

    f = calloc(p->CRYPTO_PUBLICKEYBYTES, sizeof(unsigned char));
    if (f == NULL) {
        free(f);
        free(g);
        return -1;
    }
    public_key->kind = p->kind;
    public_key->data = f;

    g = calloc(p->CRYPTO_SECRETKEYBYTES, sizeof(unsigned char));
    if (g == NULL) {
        free(f);
        free(g);
        return -1;
    }

    private_key->kind = p->kind;
    private_key->data = g;

    return 0;
}

/*********************************************************
* Name:        crypto_sign_keypair
* Description: generates a public and private key pair
* Parameters:  inputs:  none
*              outputs:
*              - tesla_private_key_t *sk: struct secret key
*              - tesla_public_key_t *pk: struct public key
*              - tesla_param_t *params: struct of TESLA parametrs
* Returns:     0 for successful execution
**********************************************************/
int tesla_crypto_sign_keypair(tesla_public_key_t *public_key, tesla_private_key_t *private_key, tesla_kind_t kind, const void * seed, size_t seed_size)
{
    tesla_param_t *p = malloc(sizeof(tesla_param_t));
    if (! tesla_params_init( p, kind)) return -1;

    assert(private_key != NULL);

    if(tesla_private_and_public_keys_init( private_key, public_key, p) != 0) return -1;

    unsigned char *randomness = malloc(CRYPTO_RANDOMBYTES * sizeof(unsigned char));
    unsigned char *randomness_extended = malloc((p->PARAM_K + 3) * CRYPTO_SEEDBYTES * sizeof(unsigned char));

    // Get randomness_extended <- seed_e, seed_s, seed_a, seed_y
    if(seed && seed_size>0){
        assert(CRYPTO_RANDOMBYTES==32);
        SHA3_256((unsigned char *)randomness, (const unsigned char *)seed, seed_size);
    }
    else{
        randombytes(randomness, CRYPTO_RANDOMBYTES);
    }

    if(p->kind == 0 || p->kind == 3)
        SHAKE128(randomness_extended, ((p->PARAM_K) + 3) * CRYPTO_SEEDBYTES, randomness, CRYPTO_RANDOMBYTES);
    else
        SHAKE256(randomness_extended, ((p->PARAM_K) + 3) * CRYPTO_SEEDBYTES, randomness, CRYPTO_RANDOMBYTES);

    poly *s = malloc(p->PARAM_N * sizeof(int64_t));
    poly *s_ntt = malloc(p->PARAM_N * sizeof(int64_t));
    poly_k *e = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));
    poly_k *a = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));
    poly_k *t = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));

    int nonce = 0;

    if(p->kind <= 2) {
        // Sample the secret polynomial
        do {
            sample_gauss_poly(e, randomness_extended, ++nonce, p);
        } while(check_ES(e, (int)p->PARAM_KEYGEN_BOUND_E, p) != 0);

        do {
            sample_gauss_poly(s, &randomness_extended[CRYPTO_SEEDBYTES], ++nonce, p);
        } while(check_ES(s, (int)p->PARAM_KEYGEN_BOUND_S, p) != 0);

        // Generate uniform polynomial "a"
        poly_uniform(a, &randomness_extended[2*CRYPTO_SEEDBYTES], p);

        // Compute the public key t = as+e
        poly_mul(t, a, s, p);
        poly_add(t, t, e, p);        
  }
  else {
        unsigned int k;        
        int64_t mask;

        for (k = 0; k < p->PARAM_K; k++) {
            // Sample the error polynomials
            do {
                sample_gauss_poly(&e[k * (p->PARAM_N)], &randomness_extended[k * CRYPTO_SEEDBYTES], ++nonce, p);
            } while(check_ES(&e[k * (p->PARAM_N)], (int)(p->PARAM_KEYGEN_BOUND_E), p) != 0);
        }

        // Sample the secret polynomial
        do {
            sample_gauss_poly(s, &randomness_extended[(p->PARAM_K) * CRYPTO_SEEDBYTES], ++nonce, p);
        } while(check_ES(s, (int)(p->PARAM_KEYGEN_BOUND_S), p) != 0);

        // Generate uniform polynomial "a"
        poly_uniform( a, &randomness_extended[((p->PARAM_K) + 1) * CRYPTO_SEEDBYTES], p);
        poly_ntt(s_ntt, s, p);

        // Compute the public key t = as+e
        for (k = 0; k < p->PARAM_K; k++) {
            poly_mul(&t[k * p->PARAM_N], &a[k * p->PARAM_N], s_ntt, p);
            poly_add(&t[k * p->PARAM_N], &t[k * p->PARAM_N], &e[k * p->PARAM_N], p);
            unsigned int i;
            for ( i = 0; i < p->PARAM_N; i++) {  // Correction
                mask = (p->PARAM_Q - t[k * p->PARAM_N + i]) >> 63;
                t[k * p->PARAM_N + i] -= (p->PARAM_Q & mask);
            }
        }
    }

    // Pack public and private keys
    pack_sk(private_key->data, s, e, &randomness_extended[(p->PARAM_K + 1) * CRYPTO_SEEDBYTES], p);
    encode_pk( public_key->data, t, &randomness_extended[(p->PARAM_K + 1) * CRYPTO_SEEDBYTES], p);

    free(s);
    free(s_ntt);
    free(e);
    free(a);
    free(t);
    free(p);
    free(randomness);
    free(randomness_extended);

    return 0;
}

/***************************************************************
* Name:        crypto_sign
* Description: outputs a signature for a given message m
* Parameters:  inputs:
*              - const unsigned char *m: message to be signed
*              - unsigned long long mlen: message length
*              - const tesla_private_key_t * sk: struct of private key
*              outputs:
*              - tesla_signature_t *sig: struct of signature
* Returns:     0 for successful execution
***************************************************************/
int tesla_crypto_sign( tesla_signature_t *sig, const unsigned char *m, unsigned long long mlen, const tesla_private_key_t *private_key)
{    
    tesla_param_t *p = malloc(sizeof(tesla_param_t));
    if (! tesla_params_init( p, private_key->kind))  return 1;

    unsigned char *c = malloc(CRYPTO_C_BYTES);
    unsigned char *randomness = malloc(CRYPTO_SEEDBYTES);
    unsigned char *randomness_input = malloc(CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + mlen);

    randombytes(randomness_input + CRYPTO_RANDOMBYTES, CRYPTO_RANDOMBYTES);
    memcpy(randomness_input, &private_key->data[p->CRYPTO_SECRETKEYBYTES - CRYPTO_SEEDBYTES], CRYPTO_SEEDBYTES);
    memcpy(randomness_input + CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES, m, mlen);

    if(p->kind == 0 || p->kind == 3)
        SHAKE128(randomness, CRYPTO_SEEDBYTES, randomness_input, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + mlen);
    else
        SHAKE256(randomness, CRYPTO_SEEDBYTES, randomness_input, CRYPTO_RANDOMBYTES + CRYPTO_SEEDBYTES + mlen);

    uint32_t *pos_list = malloc(p->PARAM_W * sizeof(uint32_t));
    int16_t *sign_list = malloc(p->PARAM_W * sizeof(uint16_t));

    poly *y = malloc(p->PARAM_N * sizeof(int64_t));
    poly *y_ntt = malloc(p->PARAM_N * sizeof(int64_t));
    poly *Sc = malloc(p->PARAM_N * sizeof(int64_t));
    poly *z = malloc(p->PARAM_N * sizeof(int64_t));
    poly_k *v = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));
    poly_k *Ec = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));
    poly_k *a = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));

    unsigned int k;
    int rsp = 0, nonce = 0;

    poly_uniform(a, &private_key->data[p->CRYPTO_SECRETKEYBYTES - 2 * CRYPTO_SEEDBYTES], p);

    if(p->kind <= 2) {
        while (1) {
            sample_y(y, randomness, ++nonce, p);
            poly_mul(v, a, y, p);
            hash_vm(c, v, m, mlen, p);
            encode_c(pos_list, sign_list, c, p);
            sparse_mul16(Sc, private_key->data, pos_list, sign_list, p);
            poly_add(z, y, Sc, p);

            if (test_rejection(z, p) != 0)
                continue;

            sparse_mul16(Ec, private_key->data + (sizeof(int16_t) * p->PARAM_N), pos_list, sign_list, p);
            poly_sub(v, v, Ec, p);

            if (test_v(v, p) != 0)
                continue;

            break;
        }
    }
    else {
        while (1) {
            sample_y(y, randomness, ++nonce, p);

            poly_ntt (y_ntt, y, p);
            for (k = 0; k < p->PARAM_K; k++)
                poly_mul(&v[k * p->PARAM_N], &a[k * p->PARAM_N], y_ntt, p);

            hash_vm(c, v, m, mlen, p);
            encode_c(pos_list, sign_list, c, p);
            sparse_mul8(Sc, private_key->data, pos_list, sign_list, p);
            poly_add(z, y, Sc, p);

            if (test_rejection(z, p) != 0)
                continue;

            for (k = 0; k < p->PARAM_K; k++) {
                sparse_mul8(&Ec[k * p->PARAM_N], private_key->data + (sizeof(int8_t) * p->PARAM_N * (k + 1)), pos_list, sign_list, p);
                poly_sub(&v[k * p->PARAM_N], &v[k * p->PARAM_N], &Ec[k * p->PARAM_N], p);
                rsp = test_v(&v[k * p->PARAM_N], p);
                if (rsp != 0)
                    break;
            }
            if (rsp != 0)
                continue;

            break;
        }
    }

    // Pack signature
    sig->sig_len = p->CRYPTO_BYTES;
    sig->sig_data = malloc( sig->sig_len);
    encode_sig(sig->sig_data, c, z, p);
    sig->kind = p->kind;

    free(p);
    free(c);
    free(randomness);
    free(randomness_input);
    free(pos_list);
    free(sign_list);
    free(y);
    free(y_ntt);
    free(Sc);
    free(z);
    free(v);
    free(Ec);
    free(a);

    return 0;
}


/************************************************************
* Name:        crypto_sign_open
* Description: verification of a signature sig
* Parameters:  inputs:
*              - tesla_signature_t *sig: struct of signature
*              - const tesla_public_key_t * pk: struct of public Key
*              outputs:
*              - unsigned char *m: original (signed) message
*              - unsigned long long *mlen: message length*
* Returns:     0 for valid signature
*              <0 for invalid signature
************************************************************/
int tesla_crypto_sign_open( tesla_signature_t *sig, const unsigned char *m, unsigned long long mlen, const tesla_public_key_t * public_key)
{
    assert(public_key->kind == sig->kind);

    tesla_param_t *p = malloc(sizeof(tesla_param_t));;
    if (! tesla_params_init( p, public_key->kind))  return -1;

    if (sig->sig_len < p->CRYPTO_BYTES) {
        free(p);
        return -1;
    }

    unsigned char *c = malloc(CRYPTO_C_BYTES);
    unsigned char *c_sig = malloc(CRYPTO_C_BYTES);
    unsigned char *seed = malloc(CRYPTO_SEEDBYTES);
    uint32_t *pos_list = malloc(p->PARAM_W * sizeof(uint32_t));
    int16_t *sign_list = malloc(p->PARAM_W * sizeof(int16_t));
    int32_t *pk_t = malloc(p->PARAM_N * p->PARAM_K * sizeof(int32_t));
    unsigned int k;    
    poly_k *w = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));
    poly_k *a = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));
    poly_k *Tc = malloc(p->PARAM_K * p->PARAM_N * sizeof(int64_t));
    poly *z = malloc(p->PARAM_N * sizeof(int64_t));
    poly *z_ntt = malloc(p->PARAM_N * sizeof(int64_t));

    decode_sig(c, z, sig->sig_data, p);

    if (test_z(z, p) != 0) {
        free(c);
        free(c_sig);
        free(p);
        free(seed);
        free(pos_list);
        free(sign_list);
        free(pk_t);
        free(w);
        free(a);
        free(Tc);
        free(z);
        free(z_ntt);
        return -2;
    }

    decode_pk((uint32_t*)pk_t, seed, public_key->data, p);
    poly_uniform(a, seed, p);
    encode_c(pos_list, sign_list, c, p);

    if(p->kind <= 2) {
        poly_mul(w, a, z, p);
        sparse_mul32(Tc, pk_t, pos_list, sign_list, p);
        poly_sub(w, w, Tc, p);
    }
    else {
        poly_ntt(z_ntt, z, p);

        for (k = 0; k < p->PARAM_K; k++) {
            poly_mul(&w[k * p->PARAM_N], &a[k * p->PARAM_N], z_ntt, p);
            sparse_mul32(&Tc[k * p->PARAM_N], pk_t + (k * p->PARAM_N), pos_list, sign_list, p);
            poly_sub(&w[k * p->PARAM_N], &w[k * p->PARAM_N], &Tc[k * p->PARAM_N], p);
        }        
    }
    hash_vm(c_sig, w, m, mlen, p);

    free(p);
    free(seed);
    free(pos_list);
    free(sign_list);
    free(pk_t);
    free(w);
    free(a);
    free(Tc);
    free(z);
    free(z_ntt);

    // Check if the calculated c matches c from the signature
    if (memcmp(c, c_sig, CRYPTO_C_BYTES)) {
        free(c);
        free(c_sig);
        return -3;
    }

    free(c);
    free(c_sig);

    return 0;
}

void tesla_signature_delete(tesla_signature_t *signature){
    assert(signature != NULL);

    free(signature->sig_data);
    signature->sig_data = NULL;    
}
