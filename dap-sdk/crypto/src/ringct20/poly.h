#ifndef POLY_RINGCT20_H
#define POLY_RINGCT20_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"

/* 
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1] 
 */
typedef struct {
    uint16_t coeffs[NEWHOPE_RINGCT20_N];
} poly_ringct20

#if !defined(_WIN32)
    __attribute__((aligned(32)));
#else
    ;
#endif

uint16_t coeff_freeze(uint16_t x);
uint16_t coeff_freeze2Q(uint16_t x);
void poly_init(poly_ringct20 *r);
void poly_setValue(poly_ringct20 *r, uint16_t v);
void poly_uniform_ringct20(poly_ringct20 *a, const unsigned char *seed);
void poly_sample(poly_ringct20 *r, const unsigned char *seed, unsigned char nonce);
void poly_add_ringct20(poly_ringct20 *r, const poly_ringct20 *a, const poly_ringct20 *b);

void poly_ntt_ringct20(poly_ringct20 *r);
void poly_invntt(poly_ringct20 *r);
void poly_mul_pointwise(poly_ringct20 *r, const poly_ringct20 *a, const poly_ringct20 *b);

void poly_frombytes(poly_ringct20 *r, const unsigned char *a);
void poly_tobytes(unsigned char *r, const poly_ringct20 *p);
void poly_compress(unsigned char *r, const poly_ringct20 *p);
void poly_decompress(poly_ringct20 *r, const unsigned char *a);

void poly_frommsg(poly_ringct20 *r, const unsigned char *msg);
void poly_tomsg(unsigned char *msg, const poly_ringct20 *x);
void poly_sub_ringct20(poly_ringct20 *r, const poly_ringct20 *a, const poly_ringct20 *b);

void poly_print(const poly_ringct20 *r);
int poly_equal(const poly_ringct20 *a, const poly_ringct20 *b);
//
void poly_constmul(poly_ringct20 *r, const poly_ringct20 *a, uint16_t cof);
void poly_serial(poly_ringct20 *r);
void poly_cofcopy(poly_ringct20 *des, const poly_ringct20 *sour);
void poly_copy(poly_ringct20 *des, const poly_ringct20 *sour, const int mLen);
void poly_shift(poly_ringct20 *des, const poly_ringct20 *r, int iNumber);
#endif
