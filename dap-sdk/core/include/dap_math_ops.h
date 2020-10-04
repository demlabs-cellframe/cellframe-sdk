#pragma once
#include <stdint.h>

#include "dap_common.h"
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

#if __SIZEOF_INT128__ != 16
typedef union uint128{uint64_t u64[2];} uint128_t;
typedef union int128{int64_t i64[2];} int128_t;

#endif


#endif
