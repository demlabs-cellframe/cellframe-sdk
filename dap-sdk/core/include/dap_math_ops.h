#pragma once
#include <stdint.h>

#include "dap_common.h"

#if defined(__GNUC__) || defined (__clang__)

#if __SIZEOF_INT128__ == 16

#define DAP_GLOBAL_IS_INT128
typedef __int128 _dap_int128_t;

#if !defined (int128_t)
typedef __int128 int128_t;
#endif

#if !defined (uint128_t)
typedef unsigned __int128 uint128_t;
#endif

#else // __SIZEOF_INT128__ == 16

typedef union uint128 {
    struct{
         uint64_t lo;
         uint64_t hi;
    } DAP_ALIGN_PACKED;
    struct{
        uint32_t c;
        uint32_t d;
        uint32_t a;
        uint32_t b;
    } DAP_ALIGN_PACKED u32;
} uint128_t;


typedef union int128 {
    int64_t i64[2];
    int32_t i32[4];
} int128_t;

typedef int128_t _dap_int128_t;

#endif // __SIZEOF_INT128__ == 16

#endif //defined(__GNUC__) || defined (__clang__)

uint128_t dap_uint128_substract(uint128_t a, uint128_t b);
uint128_t dap_uint128_add(uint128_t a, uint128_t b);
bool dap_uint128_check_equal(uint128_t a, uint128_t b);

