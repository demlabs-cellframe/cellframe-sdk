#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "dilithium_poly.h"

typedef struct {
  poly vec[5];
} polyvecl;

void polyvecl_freeze(polyvecl *v, dilithium_param_t *p);

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v, dilithium_param_t *p);

void polyvecl_ntt(polyvecl *v, dilithium_param_t *p);
void polyvecl_pointwise_acc_invmontgomery(poly *w, const polyvecl *u, const polyvecl *v, dilithium_param_t *p);

int polyvecl_chknorm(const polyvecl *v, uint32_t B, dilithium_param_t *p);


typedef struct {
  poly vec[6];
} polyveck;

void polyveck_reduce(polyveck *v, dilithium_param_t *p);
void polyveck_csubq(polyveck *v, dilithium_param_t *p);
void polyveck_freeze(polyveck *v, dilithium_param_t *p);

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v, dilithium_param_t *p);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v, dilithium_param_t *p);
void polyveck_shiftl(polyveck *v, unsigned int k, dilithium_param_t *p);

void polyveck_ntt(polyveck *v, dilithium_param_t *p);
void polyveck_invntt_montgomery(polyveck *v, dilithium_param_t *p);

int polyveck_chknorm(const polyveck *v, uint32_t B, dilithium_param_t *p);

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v, dilithium_param_t *p);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v, dilithium_param_t *p);
unsigned int polyveck_make_hint(polyveck *h, const polyveck *u, const polyveck *v, dilithium_param_t *p);
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h, dilithium_param_t *p);

#endif
