#ifndef SIGN_H
#define SIGN_H

#include "dilithium_packing.h"

void expand_mat(polyvecl [], const unsigned char rho[SEEDBYTES], dilithium_param_t *);
void challenge(poly *, const unsigned char mu[CRHBYTES], const polyveck *, dilithium_param_t *p);

#endif
