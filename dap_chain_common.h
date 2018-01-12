#ifndef _DAP_CHAIN_COMMON_H_
#define _DAP_CHAIN_COMMON_H_
#include <stdint.h>

#include "dap_common.h"
#include "dap_math_ops.h"

#define DAP_CHAIN_HASH_SIZE 32

typedef union dap_chain_hash{
    uint8_t data[DAP_CHAIN_HASH_SIZE];
} dap_chain_hash_t;

#endif
