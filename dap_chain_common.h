#ifndef _DAP_CHAIN_COMMON_H_
#define _DAP_CHAIN_COMMON_H_
#include <stdint.h>

#include "dap_common.h"
#include "dap_math_ops.h"

#define DAP_CHAIN_HASH_SIZE 64

typedef union dap_chain_hash{
    uint8_t data[DAP_CHAIN_HASH_SIZE];
} dap_chain_hash_t;

typedef union dap_chain_sig_type{
   uint16_t raw;
   enum {
     SIG_TYPE_NEWHOPE = 0x0000,
     SIG_TYPE_MULTI = 0xffff ///  @brief Has inside subset of different signatures and sign composed with all of them
   } type;
} dap_chain_sig_type_t;

#endif
