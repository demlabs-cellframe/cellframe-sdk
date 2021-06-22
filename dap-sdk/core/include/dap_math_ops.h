#pragma once
#include <stdint.h>
#include "dap_common.h"
#include <stdint.h>


typedef struct unsign128_t {
    uint64_t hi;
    uint64_t lo;
    
    } unsign128_t;

typedef struct unsign256_t {
    unsign128_t hi;
    unsign128_t lo;

    } unsign256_t;

const  unsign128_t two_power_64={ .hi = 1, .lo = 0};

const uint64_t lo_32=0xffffffff;
const uint64_t hi_32=0xffffffff00000000;
const uint64_t ones_64=0xffffffffffffffff;


static inline int SUM_64_64(uint64_t a_64_bit,uint64_t b_64_bit,uint64_t* c_64_bit ) {

int overflow_flag;
*c_64_bit=a_64_bit+b_64_bit;
overflow_flag=(*c_64_bit<a_64_bit);
return overflow_flag;}

//!!!!This function returns void because THERE CANNOT BE OVERFLOW IN A (64,64)->128 SUM!!!!
static inline void SUM_64_128(uint64_t a_64_bit,uint64_t b_64_bit,unsign128_t* c_128_bit ) {
int overflow_flag;
c_128_bit->lo=a_64_bit+b_64_bit;
c_128_bit->hi=(c_128_bit->lo<a_64_bit);}

//Mixed precision: add a uint64_t into a unsign128_t
static inline int ADD_64_INTO_128(uint64_t a_64_bit,unsign128_t* c_128_bit ) {
    int overflow_flag;
    uint64_t overflow_64;
    uint64_t temp;
    temp=c_128_bit->lo;
    overflow_flag=SUM_64_64(a_64_bit,temp,&c_128_bit->lo);
    overflow_64=overflow_flag;
    temp=c_128_bit->hi;
    overflow_flag=SUM_64_64(overflow_64,temp,&c_128_bit->hi);
    return overflow_flag;}

static inline int  SUM_128_128(unsign128_t a_128_bit,unsign128_t b_128_bit,unsign128_t* c_128_bit){
    int overflow_flag;
    overflow_flag=SUM_64_64(a_128_bit.lo,b_128_bit.lo,&c_128_bit->lo);
    uint64_t carry_in_64=overflow_flag;
    uint64_t intermediate_value=0;
    overflow_flag=0;
    overflow_flag=SUM_64_64(a_128_bit.hi,b_128_bit.hi,&intermediate_value);
    carry_in_64=overflow_flag;
    overflow_flag=0;
    overflow_flag=SUM_64_64(carry_in_64,intermediate_value,&c_128_bit->hi);
    return overflow_flag;}


static inline int  SUM_256_256(unsign256_t a_256_bit,unsign256_t b_256_bit,unsign256_t* c_256_bit){
    int overflow_flag;
    overflow_flag=SUM_128_128(a_256_bit.lo,b_256_bit.lo,&c_256_bit->lo);
    unsign128_t carry_in_128;
    carry_in_128.hi=0;
    carry_in_128.lo=overflow_flag;
    unsign128_t intermediate_value;
    intermediate_value.hi=0;
    intermediate_value.lo=0;
    overflow_flag=0;
    overflow_flag=SUM_128_128(carry_in_128,a_256_bit.hi,&intermediate_value);
    
    //we store overflow_flag in case there is already overflow
    int overflow_flag_bis=0; 
    
    overflow_flag_bis=SUM_128_128(intermediate_value,b_256_bit.hi,&c_256_bit->hi);
    overflow_flag=overflow_flag||overflow_flag_bis;
    return overflow_flag;}


static inline bool dap_unsign128_t_check_equal(unsign128_t a_128_bit, unsign128_t b_128_bit)
{
#ifdef DAP_GLOBAL_IS_INT128
    return a_128_bit == b_128_bit;
#else
    return a_128_bit.lo==b_128_bit.lo && a_128_bit.hi==b_128_bit.hi;
#endif
}


static inline bool dap_unsign256_t_check_equal(unsign256_t a_256_bit, unsign256_t b_256_bit)
{
    return a_256_bit.lo.lo==b_256_bit.lo.lo &&
           a_256_bit.lo.hi==b_256_bit.lo.hi &&
           a_256_bit.hi.lo==b_256_bit.hi.lo &&
           a_256_bit.hi.hi==b_256_bit.hi.hi;
}


