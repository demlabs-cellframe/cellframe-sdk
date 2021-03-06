/*
version 20140420
D. J. Bernstein
Public domain.
*/

#include <stdint.h>

#include "crypto_core_salsa2012.h"
#include "crypto_stream_salsa2012.h"

/**
 * @brief generate gamma bytes
 * @param gamma bytes array
 * @param gamma_len
 * @param n nonce
 * @param k key
 * @return
 */

int
crypto_stream_salsa2012(unsigned char *gamma, unsigned long long gamma_len,
                        const unsigned char *n, const unsigned char *k)
{
    unsigned char in[16];
    unsigned char block[64];
    unsigned char kcopy[32];
    unsigned int  i;
    unsigned int  u;

    if (!gamma_len) {
        return 0;
    }
    for (i = 0; i < 32; ++i) {
        kcopy[i] = k[i];
    }
    for (i = 0; i < 8; ++i) {
        in[i] = n[i];
    }
    for (i = 8; i < 16; ++i) {
        in[i] = 0;
    }
    while (gamma_len >= 64) {
        crypto_core_salsa2012(gamma, in, kcopy, NULL);
        u = 1;
        for (i = 8; i < 16; ++i) {
            u += (unsigned int)in[i];
            in[i] = u;
            u >>= 8;
        }
        gamma_len -= 64;
        gamma += 64;
    }
    if (gamma_len) {
        crypto_core_salsa2012(block, in, kcopy, NULL);
        for (i = 0; i < (unsigned int)gamma_len; ++i) {
            gamma[i] = block[i];
        }
    }
//    sodium_memzero(block, sizeof block);//TODO
//    sodium_memzero(kcopy, sizeof kcopy);

    return 0;
}
/**
 * @brief c = m ^ gamma
 * @param c
 * @param m
 * @param mlen
 * @param n nonce 8 bytes
 * @param k
 * @return
 */
int
crypto_stream_salsa2012_xor(unsigned char *c, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k)
{
    unsigned char in[16];
    unsigned char block[64];
    unsigned char kcopy[32];
    unsigned int  i;
    unsigned int  u;

    if (!mlen) {
        return 0;
    }
    for (i = 0; i < 32; ++i) {
        kcopy[i] = k[i];
    }
    for (i = 0; i < 8; ++i) {
        in[i] = n[i];
    }
    for (i = 8; i < 16; ++i) {
        in[i] = 0;
    }
    while (mlen >= 64) {
        crypto_core_salsa2012(block, in, kcopy, NULL);
        for (i = 0; i < 64; ++i) {
            c[i] = m[i] ^ block[i];
        }
        u = 1;
        for (i = 8; i < 16; ++i) {
            u += (unsigned int)in[i];
            in[i] = u;
            u >>= 8;
        }
        mlen -= 64;
        c += 64;
        m += 64;
    }
    if (mlen) {
        crypto_core_salsa2012(block, in, kcopy, NULL);
        for (i = 0; i < (unsigned int)mlen; ++i) {
            c[i] = m[i] ^ block[i];
        }
    }
//    sodium_memzero(block, sizeof block);//TODO
//    sodium_memzero(kcopy, sizeof kcopy);

    return 0;
}
