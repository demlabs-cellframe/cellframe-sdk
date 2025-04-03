#ifndef NTT_RINGCT20_H
#define NTT_RINGCT20_H

#include "inttypes.h"

extern uint16_t omegas_bitrev_montgomery[];
extern uint16_t omegas_inv_bitrev_montgomery[];

extern uint16_t psis_bitrev_montgomery[];
extern uint16_t psis_inv_montgomery[];

void bitrev_vector(uint16_t *poly_ringct20);
void mul_coefficients(uint16_t *poly_ringct20, const uint16_t *factors);
void ntt_ringct20(uint16_t *poly_ringct20, const uint16_t *omegas);



#endif
