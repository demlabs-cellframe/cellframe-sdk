#pragma once

#include "dap_math_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

void dap_pseudo_random_seed(uint256_t a_seed);
uint256_t dap_pseudo_random_get(uint256_t a_rand_max, uint256_t *a_raw_result);

#ifdef __cplusplus
}
#endif
