#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "dilithium_params.h"

#define MONT 4193792U
#define QINV 4236238847U

uint32_t montgomery_reduce(uint64_t a);

uint32_t reduce32(uint32_t a);

uint32_t csubq(uint32_t a);

uint32_t freeze(uint32_t a);

uint32_t power2round(const uint32_t a, uint32_t *a0);
uint32_t decompose(uint32_t a, uint32_t *a0);
unsigned int make_hint(const uint32_t a, const uint32_t b);
uint32_t use_hint(const uint32_t a, const unsigned int hint);

#endif
