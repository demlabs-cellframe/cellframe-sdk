#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "dilithium_params.h"
#include "dilithium_rounding_reduce.h"

typedef struct {
  uint32_t coeffs[NN];
} poly __attribute__((aligned(32)));

void poly_reduce(poly *a);
void poly_csubq(poly *a);
void poly_freeze(poly *a);

void dilithium_poly_add(poly *c, const poly *a, const poly *b);
void dilithium_poly_sub(poly *c, const poly *a, const poly *b);
void poly_neg(poly *a);
void poly_shiftl(poly *a, unsigned int k);

void dilithium_poly_ntt(poly *a);
void poly_invntt_montgomery(poly *a);
void poly_pointwise_invmontgomery(poly *c, const poly *a, const poly *b);

void poly_power2round(poly *a1, poly *a0, const poly *a);
void poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int poly_make_hint(poly *h, const poly *a, const poly *b);
void poly_use_hint(poly *a, const poly *b, const poly *h);

int  poly_chknorm(const poly *a, uint32_t B);
void dilithium_poly_uniform(poly *a, const unsigned char *buf);
void poly_uniform_eta(poly *a, const unsigned char seed[SEEDBYTES], unsigned char nonce, dilithium_param_t *p);
void poly_uniform_gamma1m1(poly *a, const unsigned char seed[SEEDBYTES + CRHBYTES], uint16_t nonce);

void polyeta_pack(unsigned char *r, const poly *a, dilithium_param_t *p);
void polyeta_unpack(poly *r, const unsigned char *a, dilithium_param_t *p);

void polyt1_pack(unsigned char *r, const poly *a);
void polyt1_unpack(poly *r, const unsigned char *a);

void polyt0_pack(unsigned char *r, const poly *a);
void polyt0_unpack(poly *r, const unsigned char *a);

void polyz_pack(unsigned char *r, const poly *a);
void polyz_unpack(poly *r, const unsigned char *a);

void polyw1_pack(unsigned char *r, const poly *a);

void dilithium_ntt(uint32_t pp[NN]);
void invntt_frominvmont(uint32_t pp[NN]);

#endif
