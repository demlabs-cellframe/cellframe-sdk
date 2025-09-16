#ifndef PACKING_H
#define PACKING_H

#include "dilithium_polyvec.h"

void dilithium_pack_pk(unsigned char [], const unsigned char [], const polyveck *, dilithium_param_t *);
void dilithium_pack_sk(unsigned char [], const unsigned char [], const unsigned char [], const unsigned char [],
             const polyvecl *, const polyveck *, const polyveck *, dilithium_param_t *);

void dilithium_pack_sig(unsigned char [], const polyvecl *, const polyveck *, const poly *, dilithium_param_t *);

void dilithium_unpack_pk(unsigned char [], polyveck *, const unsigned char [], dilithium_param_t *);

void dilithium_unpack_sk(unsigned char [], unsigned char [], unsigned char [],
               polyvecl *, polyveck *, polyveck *, const unsigned char [], dilithium_param_t *);

int dilithium_unpack_sig(polyvecl *, polyveck *, poly *, const unsigned char [], dilithium_param_t *);

#endif
