#ifndef __DAP_RAND_H__
#define __DAP_RAND_H__
#include "inttypes.h"
#include "dap_enc_base64.h"
#include "dap_math_ops.h"

// Generate random bytes and output the result to random_array
int randombytes(void* random_array, unsigned int nbytes);
int randombase64(void*random_array, unsigned int size);
uint32_t random_uint32_t(const uint32_t MAX_NUMBER);
byte_t dap_random_byte();
uint16_t dap_random_uint16();

void dap_pseudo_random_seed(uint256_t a_seed);
uint256_t dap_pseudo_random_get(uint256_t a_rand_max, uint256_t *a_raw_result);

#endif
