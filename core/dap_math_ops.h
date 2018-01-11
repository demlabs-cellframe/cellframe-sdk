#ifndef _DAP_MATH_OPS_H_
#define _DAP_MATH_OPS_H_

#include <stdint.h>

#if defined(__GNUC__) ||defined (__clang__)

#if __SIZEOF_INT128__ == 16

#define DAP_GLOBAL_IS_INT128
typedef __int128 _dap_int128_t;

#endif
#endif

typedef union dap_uint128{
    uint8_t data_raw[16];
#if defined(DAP_GLOBAL_IS_INT128)
    _dap_int128_t data_int128;
#endif
} dap_uint128_t;

#endif
