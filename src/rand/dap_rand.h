#ifndef __DAP_RAND_H__
#define __DAP_RAND_H__
#include "inttypes.h"

// Generate random bytes and output the result to random_array
int randombytes(void* random_array, unsigned int nbytes);
uint32_t random_uint32_t(const uint32_t MAX_NUMBER);

#endif
