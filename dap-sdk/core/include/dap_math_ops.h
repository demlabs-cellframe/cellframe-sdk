#pragma once
#include <stdint.h>
#include "dap_common.h"
#include <stdio.h>


#ifdef DAP_GLOBAL_IS_INT128
typedef __int128 int128_t;
typedef __uint128 uint128_t;
#else
typedef union uint128 {
    struct {
        uint64_t hi;
        uint64_t lo;
    } DAP_ALIGN_PACKED;
    uint64_t u64[2];
    uint32_t u32[4];
} DAP_ALIGN_PACKED uint128_t;
#endif

typedef struct unsign256 {
    uint128_t hi;
    uint128_t lo;
} DAP_ALIGN_PACKED uint256_t;

static const  uint128_t two_power_64={ .hi = 1, .lo = 0};

static const uint64_t lo_32=0xffffffff;
static const uint64_t hi_32=0xffffffff00000000;
static const uint64_t ones_64=0xffffffffffffffff;

/**
 * @brief SUM_64_64
 * @param a_arg1
 * @param a_arg2
 * @param a_result
 * @return
 */
static inline int SUM_64_64(uint64_t a_arg1,uint64_t a_arg2,uint64_t* a_result )
{
    int overflow_flag;
    *a_result=a_arg1+a_arg2;
    overflow_flag=(*a_result<a_arg1);
    return overflow_flag;
}

/**
 * @brief SUM_64_128
 * @details !!! This function returns void because THERE CANNOT BE OVERFLOW IN A (64,64)->128 SUM!!!!
 * @param a_arg1
 * @param a_arg2
 * @param a_result
 */
static inline void SUM_64_128(uint64_t a_arg1,uint64_t a_arg2,uint128_t* a_result )
{
    int overflow_flag;
    a_result->lo=a_arg1+a_arg2;
    a_result->hi=(a_result->lo<a_arg1);
}

/**
 * @brief ADD_64_INTO_128
 * @details Mixed precision: add a uint64_t into a unsign128_t
 * @param a_arg
 * @param a_proc_value
 * @return
 */
static inline int ADD_64_INTO_128(uint64_t a_arg,uint128_t* a_proc_value )
{
    int overflow_flag;
    uint64_t overflow_64;
    uint64_t temp;
    temp=a_proc_value->lo;
    overflow_flag=SUM_64_64(a_arg,temp,&a_proc_value->lo);
    overflow_64=overflow_flag;
    temp=a_proc_value->hi;
    overflow_flag=SUM_64_64(overflow_64,temp,&a_proc_value->hi);
    return overflow_flag;
}

/**
 * @brief SUM_128_128
 * @param a_arg1
 * @param a_arg2
 * @param a_result
 * @return
 */
static inline int  SUM_128_128(uint128_t a_arg1,uint128_t a_arg2,uint128_t* a_result)
{
    int overflow_flag;
    overflow_flag=SUM_64_64(a_arg1.lo,a_arg2.lo,&a_result->lo);
    uint64_t carry_in_64=overflow_flag;
    uint64_t intermediate_value=0;
    overflow_flag=0;
    overflow_flag=SUM_64_64(a_arg1.hi,a_arg2.hi,&intermediate_value);
    carry_in_64=overflow_flag;
    overflow_flag=0;
    overflow_flag=SUM_64_64(carry_in_64,intermediate_value,&a_result->hi);
    return overflow_flag;
}

/**
 * @brief SUM_256_256
 * @param a_arg1
 * @param a_arg2
 * @param a_result
 * @return
 */
static inline int  SUM_256_256(uint256_t a_arg1,uint256_t a_arg2,uint256_t* a_result)
{
    int overflow_flag;
    overflow_flag=SUM_128_128(a_arg1.lo,a_arg2.lo,&a_result->lo);
    uint128_t carry_in_128;
    carry_in_128.hi=0;
    carry_in_128.lo=overflow_flag;
    uint128_t intermediate_value;
    intermediate_value.hi=0;
    intermediate_value.lo=0;
    overflow_flag=0;
    overflow_flag=SUM_128_128(carry_in_128,a_arg1.hi,&intermediate_value);
    
    //we store overflow_flag in case there is already overflow
    int overflow_flag_bis=0; 
    
    overflow_flag_bis=SUM_128_128(intermediate_value,a_arg2.hi,&a_result->hi);
    overflow_flag=overflow_flag||overflow_flag_bis;
    return overflow_flag;
}

/**
 * @brief dap_uint128_add
 * @param a_arg1
 * @param a_arg2
 * @return
 */
static inline uint128_t dap_uint128_add (uint128_t a_arg1, uint128_t a_arg2)
{
    uint128_t l_ret;
    memset(&l_ret,0,sizeof(l_ret));

    SUM_128_128(a_arg1, a_arg2, & l_ret);
    return l_ret;
}

/**
 * @brief dap_uint128_substract
 * @param a
 * @param b
 * @return
 */
static inline uint128_t dap_uint128_substract(uint128_t a, uint128_t b)
{
#ifdef DAP_GLOBAL_IS_INT128
    if (a < b) {
        _log_it("dap_math_ops",L_WARNING, "Substract result overflow");
        return 0;
    }
    return a - b;
#else
    uint128_t l_ret = {};
    if (a.u64[0] < b.u64[0] || (a.u64[0] == b.u64[0] && a.u64[1] < b.u64[1])) {
        _log_it("dap_math_ops",L_WARNING, "Substract result overflow");
        return l_ret;
    }
    l_ret.u64[0] = a.u64[0] - b.u64[0];
    l_ret.u64[1] = a.u64[1] - b.u64[1];
    if (a.u64[1] < b.u64[1])
        l_ret.u64[0]--;
    return l_ret;
#endif

}


/**
 * @brief dap_uint128_check_equal
 * @param a_arg1
 * @param a_arg2
 * @return
 */
static inline bool dap_uint128_check_equal(uint128_t a_arg1, uint128_t a_arg2)
{
#ifdef DAP_GLOBAL_IS_INT128
    return a_128_bit == b_128_bit;
#else
    return a_arg1.lo==a_arg2.lo && a_arg1.hi==a_arg2.hi;
#endif
}

/**
 * @brief dap_unsign256_t_check_equal
 * @param a_arg1
 * @param a_arg2
 * @return
 */
static inline bool dap_unsign256_t_check_equal(uint256_t a_arg1, uint256_t a_arg2)
{
    return a_arg1.lo.lo==a_arg2.lo.lo &&
           a_arg1.lo.hi==a_arg2.lo.hi &&
           a_arg1.hi.lo==a_arg2.hi.lo &&
           a_arg1.hi.hi==a_arg2.hi.hi;
}
