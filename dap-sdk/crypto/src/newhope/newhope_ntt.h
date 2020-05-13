#pragma once

#include "inttypes.h"

extern uint16_t omegas_inv_bitrev_montgomery_newhope[];
extern uint16_t gammas_bitrev_montgomery[];
extern uint16_t gammas_inv_montgomery[];

void bitrev_vector_newhope(uint16_t* poly_newhope);
void mul_coefficients_newhope(uint16_t* poly_newhope, const uint16_t* factors);
void ntt_newhope(uint16_t* poly_newhope, const uint16_t* omegas);

