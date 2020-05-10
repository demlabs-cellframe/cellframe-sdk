#ifndef poly_newhope_H
#define poly_newhope_H

#include <stdint.h>
#include "newhope_params.h"

/* 
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1] 
 */
typedef struct {
  uint16_t coeffs[NEWHOPE_N];
} poly_newhope __attribute__ ((aligned (32)));

void poly_newhope_uniform(poly_newhope *a, const unsigned char *seed);
void poly_newhope_sample(poly_newhope *r, const unsigned char *seed, unsigned char nonce);
void poly_newhope_add(poly_newhope *r, const poly_newhope *a, const poly_newhope *b);

void poly_newhope_ntt_newhope(poly_newhope *r);
void poly_newhope_invntt_newhope(poly_newhope *r);
void poly_newhope_mul_pointwise(poly_newhope *r, const poly_newhope *a, const poly_newhope *b);

void poly_newhope_frombytes(poly_newhope *r, const unsigned char *a);
void poly_newhope_tobytes(unsigned char *r, const poly_newhope *p);
void poly_newhope_compress(unsigned char *r, const poly_newhope *p);
void poly_newhope_decompress(poly_newhope *r, const unsigned char *a);

void poly_newhope_frommsg(poly_newhope *r, const unsigned char *msg);
void poly_newhope_tomsg(unsigned char *msg, const poly_newhope *x);
void poly_newhope_sub(poly_newhope *r, const poly_newhope *a, const poly_newhope *b);

#endif
