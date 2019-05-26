#pragma once
#include <stdint.h>
//#include "common/int-util.h"

#if defined(__GNUC__) ||defined (__clang__)

#if __SIZEOF_INT128__ == 16

#define DAP_GLOBAL_IS_INT128
typedef __int128 _dap_int128_t;

#if !defined (int128_t)
typedef __int128 int128_t;
#endif
#if !defined (uint128_t)
typedef unsigned __int128 uint128_t;
#endif
#endif
#endif

typedef union dap_uint128{
    uint8_t data_raw[16];
#if defined(DAP_GLOBAL_IS_INT128)
    _dap_int128_t data_int128;
#endif
} dap_uint128_t;

