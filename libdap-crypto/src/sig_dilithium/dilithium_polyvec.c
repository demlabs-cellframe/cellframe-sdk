#include <stdint.h>

#include "dilithium_poly.h"
#include "dilithium_polyvec.h"

/*************************************************/
void polyvecl_freeze(polyvecl *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_L; ++i)
    poly_freeze(v->vec + i);
}

/*************************************************/
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_L; ++i)
    dilithium_poly_add(w->vec+i, u->vec+i, v->vec+i);
}

/*************************************************/
void polyvecl_ntt(polyvecl *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_L; ++i)
    dilithium_poly_ntt(v->vec+i);
}

/*************************************************/
void polyvecl_pointwise_acc_invmontgomery(poly *w, const polyvecl *u, const polyvecl *v, dilithium_param_t *p)
{
  unsigned int i;
  poly t;

  poly_pointwise_invmontgomery(w, u->vec+0, v->vec+0);

  for(i = 1; i < p->PARAM_L; ++i) {
    poly_pointwise_invmontgomery(&t, u->vec+i, v->vec+i);
    dilithium_poly_add(w, w, &t);
  }
}

/*************************************************/
int polyvecl_chknorm(const polyvecl *v, uint32_t bound, dilithium_param_t *p)  {
  unsigned int i;
  int ret = 0;

  for(i = 0; i < p->PARAM_L; ++i)
    ret |= poly_chknorm(v->vec+i, bound);

  return ret;
}

/*************************************************/
void polyveck_reduce(polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_reduce(v->vec+i);
}

/*************************************************/
void polyveck_csubq(polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_csubq(v->vec+i);
}

/*************************************************/
void polyveck_freeze(polyveck *v, dilithium_param_t *p)  {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_freeze(v->vec+i);
}

/*************************************************/
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    dilithium_poly_add(w->vec+i, u->vec+i, v->vec+i);
}

/*************************************************/
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    dilithium_poly_sub(w->vec+i, u->vec+i, v->vec+i);
}

/*************************************************/
void polyveck_shiftl(polyveck *v, unsigned int k, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_shiftl(v->vec + i, k);
}

/*************************************************/
void polyveck_ntt(polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    dilithium_poly_ntt(v->vec + i);
}

/*************************************************/
void polyveck_invntt_montgomery(polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_invntt_montgomery(v->vec + i);
}

/*************************************************/
int polyveck_chknorm(const polyveck *v, uint32_t bound, dilithium_param_t *p) {
  unsigned int i;
  int ret = 0;

  for(i = 0; i < p->PARAM_K; ++i)
    ret |= poly_chknorm(v->vec+i, bound);

  return ret;
}

/*************************************************/
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_power2round(v1->vec+i, v0->vec+i, v->vec+i);
}

/*************************************************/
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_decompose(v1->vec+i, v0->vec+i, v->vec+i);
}

/*************************************************/
unsigned int polyveck_make_hint(polyveck *h, const polyveck *u, const polyveck *v, dilithium_param_t *p)
{
  unsigned int i, s = 0;

  for(i = 0; i < p->PARAM_K; ++i)
    s += poly_make_hint(h->vec+i, u->vec+i, v->vec+i);

  return s;
}

/*************************************************/
void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h, dilithium_param_t *p) {
  unsigned int i;

  for(i = 0; i < p->PARAM_K; ++i)
    poly_use_hint(w->vec+i, u->vec+i, h->vec+i);
}
