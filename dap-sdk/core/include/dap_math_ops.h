#pragma once
#include <stdint.h>
#include <stdio.h>
#include "assert.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

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

typedef struct uint256_t {
    uint128_t hi;
    uint128_t lo;

    } uint256_t;

typedef struct uint512_t {
    uint256_t hi;
    uint256_t lo;

    } uint512_t;





#endif //defined(__GNUC__) || defined (__clang__)

////////////////////////////////////////////////////////////////////////////////////////////////

#if 0

const  uint128_t two_power_64={ .hi = 1, .lo = 0};
const  uint128_t lo_64={ .hi = 0, .lo = 0xffffffffffffffff};
const  uint128_t hi_64={ .hi = 0xffffffffffffffff, .lo = 0};
const  uint128_t zero_128={.hi=0,.lo=0};

const  uint256_t zero_256={.hi=zero_128,.lo=zero_128};

const uint64_t lo_32=0xffffffff;
const uint64_t hi_32=0xffffffff00000000;
const uint64_t ones_64=0xffffffffffffffff;

#endif

static inline bool EQUAL_128(uint128_t a_128_bit, uint128_t b_128_bit){
#ifdef DAP_GLOBAL_IS_INT128
    return a_128_bit == b_128_bit;
#else
    return a_128_bit.lo==b_128_bit.lo && a_128_bit.hi==b_128_bit.hi;
#endif
}
    
static inline bool EQUAL_256(uint256_t a_256_bit, uint256_t b_256_bit){

#ifdef DAP_GLOBAL_IS_INT128
    return a_256_bit.lo==b_256_bit.lo && a_256_bit.hi==b_256_bit.hi;

#else
    return a_256_bit.lo.lo==b_256_bit.lo.lo &&
           a_256_bit.lo.hi==b_256_bit.lo.hi &&
           a_256_bit.hi.lo==b_256_bit.hi.lo &&
           a_256_bit.hi.hi==b_256_bit.hi.hi;
#endif
}

static inline uint128_t AND_128(uint128_t a_128_bit,uint128_t b_128_bit){

#ifdef DAP_GLOBAL_IS_INT128
    return a_128_bit&b_128_bit;
    
#else    
    uint128_t output={ .hi = 0, .lo = 0};
    output.hi= a_128_bit.hi & b_128_bit.hi;  
    output.lo= a_128_bit.lo & b_128_bit.lo;
    return output;

#endif
}

static inline uint128_t OR_128(uint128_t a_128_bit,uint128_t b_128_bit){

#ifdef DAP_GLOBAL_IS_INT128
    return a_128_bit|b_128_bit;

#else    
    uint128_t output={ .hi = 0, .lo = 0};
    output.hi= a_128_bit.hi | b_128_bit.hi;  
    output.lo= a_128_bit.lo | b_128_bit.lo;
    return output;

#endif
}

static inline uint256_t AND_256(uint256_t a_256_bit,uint256_t b_256_bit){

#ifdef DAP_GLOBAL_IS_INT128
    uint256_t output = {};
    output.hi= a_256_bit.hi | b_256_bit.hi;  
    output.lo= a_256_bit.lo | b_256_bit.lo;
    return output;

#else 
    uint256_t output={ .hi = {}, .lo = {}};
    output.hi= AND_128(a_256_bit.hi, b_256_bit.hi);  
    output.lo= AND_128(a_256_bit.lo, b_256_bit.lo);
    return output;

#endif
}

static inline uint256_t OR_256(uint256_t a_256_bit,uint256_t b_256_bit){

#ifdef DAP_GLOBAL_IS_INT128
    uint256_t output= {};
    output.hi= a_256_bit.hi | b_256_bit.hi;  
    output.lo= a_256_bit.lo | b_256_bit.lo;
    return output;

#else 
    uint256_t output={ .hi = {}, .lo = {}};
    output.hi= OR_128(a_256_bit.hi, b_256_bit.hi); 
    output.lo= OR_128(a_256_bit.lo, b_256_bit.lo); 
    return output;

#endif
}

static inline void LEFT_SHIFT_128(uint128_t a_128_bit,uint128_t* b_128_bit,int n){
    assert (n <= 128);

#ifdef DAP_GLOBAL_IS_INT128
    *b_128_bit=a_128_bit<<n;

#else 
    if (n >= 64) // shifting 64-bit integer by more than 63 bits is not defined
    {   
        a_128_bit.hi=a_128_bit.lo;
        a_128_bit.lo=0;
        LEFT_SHIFT_128(a_128_bit,b_128_bit,n-64);
    }
    if (n == 0)
    {
       b_128_bit->hi=a_128_bit.hi;
       b_128_bit->lo=a_128_bit.lo;
    } 
    else
    {   uint64_t shift_temp;
        shift_temp=a_128_bit.lo<<n;
        b_128_bit->lo=shift_temp;
        b_128_bit->hi=(a_128_bit.hi<<n)|(a_128_bit.lo>>(64-n));
    }

#endif
}

static inline void RIGHT_SHIFT_128(uint128_t a_128_bit,uint128_t* b_128_bit,int n){
    assert (n <= 128);

#ifdef DAP_GLOBAL_IS_INT128
    (*b_128_bit) = a_128_bit >> n;

#else 
    
    if (n >= 64) // shifting 64-bit integer by more than 63 bits is not defined
    {   
        a_128_bit.lo=a_128_bit.hi;
        a_128_bit.hi=0;
        RIGHT_SHIFT_128(a_128_bit,b_128_bit,n-64);
    }
    if (n == 0)
    {
       b_128_bit->hi=a_128_bit.hi;
       b_128_bit->lo=a_128_bit.lo;
    } 
    else
    {   uint64_t shift_temp;
        shift_temp=a_128_bit.hi>>n;
        b_128_bit->hi=shift_temp;
        b_128_bit->lo=(a_128_bit.lo>>n)|(a_128_bit.hi<<(64-n));
    }
#endif
}


static inline void LEFT_SHIFT_256(uint256_t a_256_bit,uint256_t* b_256_bit,int n){
 
    assert (n <= 256);

#ifdef DAP_GLOBAL_IS_INT128

    if (n >= 128) 
    {   
        a_256_bit.hi=a_256_bit.lo;
        a_256_bit.lo=0;
        LEFT_SHIFT_256(a_256_bit,b_256_bit,n-128);
    }
    if (n == 0)
    {
       b_256_bit->hi=a_256_bit.hi;
       b_256_bit->lo=a_256_bit.lo;
    } 
    else
    {   uint128_t shift_temp;
        shift_temp=a_256_bit.lo<<n;
        b_256_bit->lo=shift_temp;
        b_256_bit->hi=(a_256_bit.hi<<n)|(a_256_bit.lo>>(128-n));
    }

#else 
    if (n >= 128) // shifting 64-bit integer by more than 63 bits is not defined
    {   
        uint128_t zero_128 = {};
        a_256_bit.hi=a_256_bit.lo;
        a_256_bit.lo=zero_128;
        LEFT_SHIFT_256(a_256_bit,b_256_bit,n-128);
    }
    if (n == 0)
    {
       b_256_bit->hi=a_256_bit.hi;
       b_256_bit->lo=a_256_bit.lo;
    } 
    if (n<128)
    {   uint128_t shift_temp={.hi=0, .lo=0};
        LEFT_SHIFT_128(a_256_bit.lo,&shift_temp,n);
        b_256_bit->lo=shift_temp;   
        uint128_t shift_temp_or_left={.hi=0, .lo=0};
        uint128_t shift_temp_or_right={.hi=0, .lo=0};
        LEFT_SHIFT_128(a_256_bit.hi,&shift_temp_or_left,n);
        RIGHT_SHIFT_128(a_256_bit.lo,&shift_temp_or_right,128-n);
        b_256_bit->hi=OR_128(shift_temp_or_left,shift_temp_or_right);
    }
#endif
}

static inline void RIGHT_SHIFT_256(uint256_t a_256_bit,uint256_t* b_256_bit,int n){
    assert (n <= 256);

#ifdef DAP_GLOBAL_IS_INT128

    if (n >= 128) 
    {   
        a_256_bit.lo=a_256_bit.hi;
        a_256_bit.hi=0;
        RIGHT_SHIFT_256(a_256_bit,b_256_bit,n-128);
    }
    if (n == 0)
    {
       b_256_bit->hi=a_256_bit.hi;
       b_256_bit->lo=a_256_bit.lo;
    } 
    else
    {   uint64_t shift_temp;
        shift_temp=a_256_bit.hi>>n;
        b_256_bit->hi=shift_temp;
        b_256_bit->lo=(a_256_bit.lo>>n)|(a_256_bit.hi<<(128-n));
    }

#else 
    if (n >= 128) // shifting 64-bit integer by more than 63 bits is not defined
    {
        uint128_t zero_128 = {};
        a_256_bit.lo=a_256_bit.hi;
        a_256_bit.hi=zero_128;
        RIGHT_SHIFT_256(a_256_bit,b_256_bit,n-128);
    }
    if (n == 0)
    {
       b_256_bit->hi=a_256_bit.hi;
       b_256_bit->lo=a_256_bit.lo;
    } 
    if (n<128)
    {   uint128_t shift_temp={.hi=0, .lo=0};
        RIGHT_SHIFT_128(a_256_bit.hi,&shift_temp,n);
        b_256_bit->hi=shift_temp;   
        uint128_t shift_temp_or_left={.hi=0, .lo=0};
        uint128_t shift_temp_or_right={.hi=0, .lo=0};
        RIGHT_SHIFT_128(a_256_bit.lo,&shift_temp_or_left,n);
        LEFT_SHIFT_128(a_256_bit.hi,&shift_temp_or_right,128-n);
        b_256_bit->lo=OR_128(shift_temp_or_left,shift_temp_or_right);
    }
#endif
}

static inline void INCR_128(uint128_t *a_128_bit){

#ifdef DAP_GLOBAL_IS_INT128
    (*a_128_bit)++;

#else 
    a_128_bit->lo++;
    if(a_128_bit->lo == 0)
    {
        a_128_bit->hi++;
    }  
#endif
}

//static inline void DECR_128(uint128_t* a_128_bit){
//
//#ifdef DAP_GLOBAL_IS_INT128
//    *a_128_bit--;
//
//#else 
//    a_128_bit->lo--;
//    if(a_128_bit->hi == 0)
//    {
//        a_128_bit->hi--;
//    }  
//#endif
//}
//
static inline void INCR_256(uint256_t* a_256_bit){

#ifdef DAP_GLOBAL_IS_INT128
    a_256_bit->lo++;
    if(a_256_bit->lo == 0)
    {
        a_256_bit->hi++;
    }  

#else 
    INCR_128(&a_256_bit->lo);
    uint128_t zero_128 = {};
    if(EQUAL_128(a_256_bit->lo, zero_128))
    {
        INCR_128(&a_256_bit->hi);
    }  
#endif
}

static inline int SUM_64_64(uint64_t a_64_bit,uint64_t b_64_bit,uint64_t* c_64_bit ) {

int overflow_flag;
*c_64_bit=a_64_bit+b_64_bit;
overflow_flag=(*c_64_bit<a_64_bit);
return overflow_flag;}



static inline int OVERFLOW_SUM_64_64(uint64_t a_64_bit,uint64_t b_64_bit) {

int overflow_flag;
overflow_flag=(a_64_bit+b_64_bit<a_64_bit);
return overflow_flag;}

static inline int OVERFLOW_MULT_64_64(uint64_t a_64_bit,uint64_t b_64_bit) { return (a_64_bit>((uint64_t)-1)/b_64_bit); }

static inline int MULT_64_64(uint64_t a_64_bit,uint64_t b_64_bit,uint64_t* c_64_bit ) {

int overflow_flag;
*c_64_bit=a_64_bit*b_64_bit;
overflow_flag=OVERFLOW_MULT_64_64(a_64_bit, b_64_bit);
return overflow_flag;}

//
//static inline void SUM_64_128(uint64_t a_64_bit,uint64_t b_64_bit,uint128_t* c_128_bit ) {
//int overflow_flag;
//c_128_bit->lo=a_64_bit+b_64_bit;
//c_128_bit->hi=(c_128_bit->lo<a_64_bit);}

#if 0
//Mixed precision: add a uint64_t into a uint128_t
static inline int ADD_64_INTO_128(uint64_t a_64_bit,uint128_t* c_128_bit ) {
    int overflow_flag=0;
    uint64_t overflow_64=0;
    uint64_t temp=0;
    temp=c_128_bit->lo;
    overflow_flag=SUM_64_64(a_64_bit,temp,&c_128_bit->lo);
    overflow_64=overflow_flag;
    temp=c_128_bit->hi;
    overflow_flag=SUM_64_64(overflow_64,temp,&c_128_bit->hi);
    return overflow_flag;}

static inline int  SUM_128_128(uint128_t a_128_bit,uint128_t b_128_bit,uint128_t* c_128_bit){
    int overflow_flag;
    int overflow_flag_intermediate;
    overflow_flag=SUM_64_64(a_128_bit.lo,b_128_bit.lo,&c_128_bit->lo);
    uint64_t carry_in_64=overflow_flag;
    uint64_t intermediate_value=0;
    overflow_flag=0;
    overflow_flag=SUM_64_64(carry_in_64,a_128_bit.hi,&intermediate_value);
    overflow_flag_intermediate=SUM_64_64(intermediate_value,b_128_bit.hi,&c_128_bit->hi);
    int return_overflow=overflow_flag|overflow_flag_intermediate;
    return return_overflow;}

static inline int SUBTRACT_128_128(uint128_t a_128_bit, uint128_t b_128_bit,uint128_t* c_128_bit)
{
    c_128_bit->lo = a_128_bit.lo - b_128_bit.lo;
    uint64_t carry = (((c_128_bit->lo & b_128_bit.lo) & 1) + (b_128_bit.lo >> 1) + (c_128_bit->lo >> 1)) >> 63;
    c_128_bit->hi = a_128_bit.hi - (b_128_bit.hi + carry);
    int underflow_flag=carry;
    return underflow_flag;
}

//static inline int SUBTRACT_256_256(uint256_t a_256_bit, uint256_t b_256_bit,uint256_t* c_256_bit){
//
//    if 
//  int carry=0;
//    carry=SUBTRACT_128_128(a_256_bit.lo, b_256_bit.lo,&c_256_bit->lo);
//    uint64_t carry_64=carry;
//    uint128_t carry_128{.hi=0,.lo=carry_64};
//    uint128_t intermediate_val{.hi=0,.lo=0};
//    int dummy_overflow=0;
//    dummy_overflow=SUM_128_128(b_256_bit.hi,carry_128,&intermediate_val);
//    carry=SUBTRACT_128_128(a_256_bit.hi, intermediate_val,&c_256_bit->hi );
//    return carry;
//}
//
//Mixed precision: add a uint128_t into a uint256_t
static inline int ADD_128_INTO_256(uint128_t a_128_bit,uint256_t* c_256_bit) {
    int overflow_flag=0;
    uint128_t overflow_128={.hi=0,.lo=0};
    uint128_t temp={.hi=0,.lo=0};
    temp=c_256_bit->lo;
    overflow_flag=SUM_128_128(a_128_bit,temp,&c_256_bit->lo);
    overflow_128.lo=overflow_flag;
    temp=c_256_bit->hi;
    overflow_flag=SUM_128_128(overflow_128,temp,&c_256_bit->hi);
    return overflow_flag;}


static inline int  SUM_256_256(uint256_t a_256_bit,uint256_t b_256_bit,uint256_t* c_256_bit){
    int overflow_flag;
    overflow_flag=SUM_128_128(a_256_bit.lo,b_256_bit.lo,&c_256_bit->lo);
    uint128_t carry_in_128;
    carry_in_128.hi=0;
    carry_in_128.lo=overflow_flag;
    uint128_t intermediate_value;
    intermediate_value.hi=0;
    intermediate_value.lo=0;
    overflow_flag=0;
    overflow_flag=SUM_128_128(carry_in_128,a_256_bit.hi,&intermediate_value);
    
    //we store overflow_flag in case there is already overflow
    int overflow_flag_bis=0; 
    
    overflow_flag_bis=SUM_128_128(intermediate_value,b_256_bit.hi,&c_256_bit->hi);
    overflow_flag=overflow_flag||overflow_flag_bis;
    return overflow_flag;}

static inline int  SUBTRACT_256_256(uint256_t a_256_bit,uint256_t b_256_bit,uint256_t* c_256_bit){
    
//(u64 rd[4], const u64 ad[4], const u64 bd[4])
    uint64_t t, r, borrow;

    t = a_256_bit.lo.lo;
    r = t - b_256_bit.lo.lo;
    borrow = (r > t);
    c_256_bit->lo.lo = r;

    t = a_256_bit.lo.hi;
    t -= borrow;
    borrow = (t > a_256_bit.lo.hi);
    r = t - b_256_bit.lo.hi;
    borrow |= (r > t);
    c_256_bit->lo.hi = r;

    t = a_256_bit.hi.lo;
    t -= borrow;
    borrow = (t > a_256_bit.hi.lo);
    r = t - b_256_bit.hi.lo;
    borrow |= (r > t);
    c_256_bit->hi.lo = r;

    t = a_256_bit.hi.hi;
    t -= borrow;
    borrow = (t > a_256_bit.hi.hi);
    r = t - b_256_bit.hi.hi;
    borrow |= (r > t);
    c_256_bit->hi.hi = r;

    return borrow;

    }

//Mixed precision: add a uint256_t into a uint512_t
static inline int ADD_256_INTO_512(uint256_t a_256_bit,uint512_t* c_512_bit) {
    int overflow_flag=0;
    uint256_t overflow_256={.hi=zero_128,.lo=zero_128};
    uint256_t temp={.hi=zero_128,.lo=zero_128};
    temp=c_512_bit->lo;
    overflow_flag=SUM_256_256(a_256_bit,temp,&c_512_bit->lo);
    overflow_256.lo.lo=overflow_flag;
    temp=c_512_bit->hi;
    overflow_flag=SUM_256_256(overflow_256,temp,&c_512_bit->hi);
    return overflow_flag;}


static inline void MULT_64_128(uint64_t a_64_bit, uint64_t b_64_bit, uint128_t* c_128_bit)
{
    uint64_t a_64_bit_hi = (a_64_bit & 0xffffffff);
    uint64_t b_64_bit_hi = (b_64_bit & 0xffffffff);
    uint64_t prod_hi = (a_64_bit_hi * b_64_bit_hi);
    uint64_t w3 = (prod_hi & 0xffffffff);
    uint64_t prod_hi_shift_right = (prod_hi >> 32);

    a_64_bit >>= 32;
    prod_hi = (a_64_bit * b_64_bit_hi) + prod_hi_shift_right;
    prod_hi_shift_right = (prod_hi & 0xffffffff);
    uint64_t w1 = (prod_hi >> 32);

    b_64_bit >>= 32;
    prod_hi = (a_64_bit_hi * b_64_bit) + prod_hi_shift_right;
    prod_hi_shift_right = (prod_hi >> 32);

    c_128_bit->hi = (a_64_bit * b_64_bit) + w1 + prod_hi_shift_right;
    c_128_bit->lo = (prod_hi << 32) + w3;
}



static inline void MULT_128_256(uint128_t a_128_bit,uint128_t b_128_bit,uint256_t* c_256_bit ) {

    //product of .hi terms - stored in .hi field of c_256_bit
    MULT_64_128(a_128_bit.hi,b_128_bit.hi, &c_256_bit->hi);

    //product of .lo terms - stored in .lo field of c_256_bit        
    MULT_64_128(a_128_bit.lo,b_128_bit.lo, &c_256_bit->lo);

    uint128_t cross_product_one{.hi=0, .lo=0};
    uint128_t cross_product_two{.hi=0, .lo=0};
    MULT_64_128(a_128_bit.hi, b_128_bit.lo, &cross_product_one);
    c_256_bit->lo.hi += cross_product_one.lo;
    if(c_256_bit->lo.hi < cross_product_one.lo)  // if overflow
    {
        INCR_128(&c_256_bit->hi);
    }
    c_256_bit->hi.lo += cross_product_one.hi;
    if(c_256_bit->hi.lo < cross_product_one.hi)  // if  overflowed
    {
        c_256_bit->hi.hi+=1;
    }
    
    MULT_64_128(a_128_bit.lo, b_128_bit.hi, &cross_product_two);
    c_256_bit->lo.hi += cross_product_two.lo;
    if(c_256_bit->lo.hi < cross_product_two.lo)  // if overflowed
    {
        INCR_128(&c_256_bit->hi);
    }
    c_256_bit->hi.lo += cross_product_two.hi;
    if(c_256_bit->hi.lo < cross_product_two.hi)  //  overflowed
    {
        c_256_bit->hi.hi+=1;
    }
} 

static inline int MULT_128_128_NEW(uint128_t a_128_bit,uint128_t b_128_bit,uint128_t* accum_128_bit){
    int overflow=0; 
    int equal_flag=0;
    uint256_t full_product_256{.hi=zero_128, .lo=zero_128};
    MULT_128_256(a_128_bit,b_128_bit,&full_product_256);
    *accum_128_bit=full_product_256.lo;
    equal_flag=EQUAL_128(full_product_256.hi,zero_128);
    if (!equal_flag)
    {
        overflow=1;
    }
    return overflow;
}

static inline int MULT_128_128(uint128_t a_128_bit,uint128_t b_128_bit,uint128_t* accum_128_bit) {    
    uint64_t A=(b_128_bit.lo & lo_32)*(a_128_bit.hi & lo_32);
    uint64_t B_32_64=((b_128_bit.lo & lo_32)*(a_128_bit.hi & hi_32))&hi_32;
    uint64_t C_32_64=((b_128_bit.lo & hi_32)*(a_128_bit.hi & lo_32))&hi_32;
    uint64_t E=(a_128_bit.lo & lo_32)*(b_128_bit.hi & lo_32);
    uint64_t F_32_64=((a_128_bit.lo & lo_32)*(b_128_bit.hi & hi_32))&hi_32;
    uint64_t G_32_64=((a_128_bit.lo & hi_32)*(b_128_bit.hi & lo_32))&hi_32;

    //initialization of overflow counter
    int overflow_ctr=0;

     //checking of overflow from ".hi terms"
    int overflow_from_hi_calc=0;
    overflow_from_hi_calc=(a_128_bit.hi*b_128_bit.hi>0);
    overflow_ctr+=overflow_from_hi_calc;
    
    //product of two ".lo" terms
    MULT_64_128(a_128_bit.lo,b_128_bit.lo,accum_128_bit);   

    int overflow=0;
    uint64_t temp=0;

    overflow=SUM_64_64(A,temp,&accum_128_bit->hi); 
    printf("accum_128_bit->hi after add in of A %" PRIu64 "\n",accum_128_bit->hi);
 
    overflow_ctr+=overflow;
    temp=accum_128_bit->hi; 
    overflow=0;

    overflow=SUM_64_64(B_32_64,temp,&accum_128_bit->hi);  
    overflow_ctr+=overflow;
    temp=accum_128_bit->hi; 
    overflow=0;

    overflow=SUM_64_64(C_32_64,temp,&accum_128_bit->hi);  
    overflow_ctr+=overflow;
    temp=accum_128_bit->hi; 
    overflow=0;

    overflow=SUM_64_64(E,temp,&accum_128_bit->hi);  
    overflow_ctr+=overflow;
    temp=accum_128_bit->hi; 
    overflow=0;

    overflow=SUM_64_64(F_32_64,temp,&accum_128_bit->hi);  
    overflow_ctr+=overflow;
    temp=accum_128_bit->hi; 
    overflow=0;
        
    overflow=SUM_64_64(G_32_64,temp,&accum_128_bit->hi);  
    overflow_ctr+=overflow;
    temp=accum_128_bit->hi;  
    overflow=0;

    if(overflow_ctr>0){
        overflow=1;}
    else{overflow=0;}
    
    return overflow;
    }

static inline void MULT_256_512(uint256_t a_256_bit,uint256_t b_256_bit,uint512_t* c_512_bit) {
    int dummy_overflow;
    //product of .hi terms - stored in .hi field of c_512_bit
    MULT_128_256(a_256_bit.hi,b_256_bit.hi, &c_512_bit->hi);
    
    //product of .lo terms - stored in .lo field of c_512_bit        
    MULT_128_256(a_256_bit.lo,b_256_bit.lo, &c_512_bit->lo);

    //cross product of .hi and .lo terms
    uint256_t cross_product_first_term{ .hi = zero_128, .lo = zero_128};
    uint256_t cross_product_second_term{ .hi = zero_128, .lo = zero_128};
    uint256_t cross_product{ .hi = zero_128, .lo = zero_128};
    uint256_t cross_product_shift_128{ .hi = zero_128, .lo = zero_128};
    uint256_t c_512_bit_lo_copy{ .hi = zero_128, .lo = zero_128};
    uint256_t c_512_bit_hi_copy{ .hi = zero_128, .lo = zero_128};
    int overflow=0;

    MULT_128_256(a_256_bit.hi,b_256_bit.lo,&cross_product_first_term);
    MULT_128_256(a_256_bit.lo,b_256_bit.hi,&cross_product_second_term);
    overflow=SUM_256_256(cross_product_first_term,cross_product_second_term,&cross_product);
    
    
    LEFT_SHIFT_256(cross_product,&cross_product_shift_128,128); //the factor in front of cross product is 2**128
    c_512_bit_lo_copy=c_512_bit->lo; 
    dummy_overflow=SUM_256_256(c_512_bit_lo_copy,cross_product_shift_128,&c_512_bit->lo);    
 
    cross_product_shift_128.hi = zero_128; 
    cross_product_shift_128.lo = zero_128;
    RIGHT_SHIFT_256(cross_product,&cross_product_shift_128,128);
    c_512_bit_hi_copy=c_512_bit->hi;    
    dummy_overflow=SUM_256_256(c_512_bit_hi_copy,cross_product_shift_128,&c_512_bit->hi);
    }


static inline int MULT_256_256_NEW(uint256_t a_256_bit,uint256_t b_256_bit,uint256_t* accum_256_bit){

    uint128_t two_0_coeff{.hi=0,.lo=0};
    MULT_64_128(a_256_bit.lo.lo,b_256_bit.lo.lo,&two_0_coeff);
    accum_256_bit->lo.lo=two_0_coeff.lo;
    
    uint128_t two_64_coeff{.hi=0,.lo=0};
    uint128_t two_64_coeff_one{.hi=0,.lo=0};
    MULT_64_128(a_256_bit.lo.hi,b_256_bit.lo.lo,&two_64_coeff_one);
    uint128_t two_64_coeff_two{.hi=0,.lo=0};
    MULT_64_128(a_256_bit.lo.lo,b_256_bit.lo.hi,&two_64_coeff_two);
    uint128_t two_64_coeff_sum{.hi=0,.lo=0};
    int dummy_overflow=0;
    dummy_overflow=SUM_128_128(two_64_coeff_one,two_64_coeff_two,&two_64_coeff_sum);
    if (two_64_coeff_sum.lo+two_0_coeff.hi<two_64_coeff_sum.lo){
        
        two_64_coeff.lo=two_64_coeff_sum.lo+two_0_coeff.hi;
        two_64_coeff.hi=1+two_64_coeff_sum.hi;}
    else{
        two_64_coeff.lo=two_64_coeff_sum.lo+two_0_coeff.hi;
        two_64_coeff.hi=two_64_coeff_sum.hi;
    }
    accum_256_bit->lo.hi=two_64_coeff.lo;
    

    uint128_t two_128_coeff{.hi=0,.lo=0};
    uint128_t  two_128_coeff_one{.hi=0,.lo=0};
    MULT_64_128(a_256_bit.lo.lo,b_256_bit.hi.lo,&two_128_coeff_one);
    uint128_t  two_128_coeff_two{.hi=0,.lo=0};
    MULT_64_128(a_256_bit.hi.lo,b_256_bit.lo.lo,&two_128_coeff_two);
    uint128_t two_128_coeff_three{.hi=0,.lo=0};
    MULT_64_128(a_256_bit.lo.hi,b_256_bit.lo.hi,&two_128_coeff_three);
    uint128_t two_128_coeff_sum_one{.hi=0,.lo=0};
    dummy_overflow=SUM_128_128(two_128_coeff_one,two_128_coeff_two,&two_128_coeff_sum_one);
    uint128_t two_128_coeff_sum_two{.hi=0,.lo=0};
    dummy_overflow=SUM_128_128(two_128_coeff_sum_one,two_128_coeff_three,&two_128_coeff_sum_two);
    
    if (two_128_coeff_sum_two.lo+two_64_coeff.hi<two_128_coeff_sum_two.lo){
        
        two_128_coeff.lo=two_128_coeff_sum_two.lo+two_64_coeff.hi;
        two_128_coeff.hi=1+two_128_coeff_sum_two.hi;}
    else{
        two_128_coeff.lo=two_128_coeff_sum_two.lo+two_64_coeff.hi;
        two_128_coeff.hi=two_128_coeff_sum_two.hi;
    }
    accum_256_bit->hi.lo=two_128_coeff.lo;



//    
//
//    
//    uint64_t two_192_coeff=0;
//    uint64_t two_192_coeff_one=0;
//    int overflow_two_192_coeff_one=0;
//    overflow_two_192_coeff_one=MULT_64_64(a_256_bit.hi.hi,b_256_bit.lo.lo,&two_192_coeff_one);
//    uint64_t two_192_coeff_two=0;
//    int overflow_two_192_coeff_two=0;
//    overflow_two_192_coeff_two=MULT_64_64(a_256_bit.lo.lo,b_256_bit.hi.hi,&two_192_coeff_two);
//    uint64_t two_192_coeff_three=0;
//    int overflow_two_192_coeff_three=0;
//    overflow_two_192_coeff_three=MULT_64_64(a_256_bit.lo.hi,b_256_bit.hi.lo,&two_192_coeff_three);
//    uint64_t two_192_coeff_four=0;
//    int overflow_two_192_coeff_four=0;
//    overflow_two_192_coeff_four=MULT_64_64(a_256_bit.hi.lo,b_256_bit.lo.hi,&two_192_coeff_four);
//    uint64_t two_192_coeff_sum_one=0;
//    int overflow_two_192_coeff_sum_one=0;

//    overflow_two_192_coeff_sum_one=SUM_64_64(two_192_coeff_one,two_192_coeff_two,&two_192_coeff_sum_one);
//    uint64_t two_192_coeff_sum_two=0;
//    int overflow_two_192_coeff_sum_two=0;
//    overflow_two_192_coeff_sum_two=SUM_64_64(two_192_coeff_three,two_192_coeff_four,&two_192_coeff_sum_two);
//    int overflow_two_192_coeff_sum=0;
//    overflow_two_192_coeff_sum=SUM_64_64(two_192_coeff_sum_one,two_192_coeff_sum_two,&two_192_coeff);
    

    return 0;
    
}

static inline int MULT_256_256(uint256_t a_256_bit,uint256_t b_256_bit,uint256_t* accum_256_bit){
    int overflow=0; 
    int equal_flag=0;
    uint512_t full_product_512{.hi=zero_256,.lo=zero_256,};
    MULT_256_512(a_256_bit,b_256_bit,&full_product_512);
    *accum_256_bit=full_product_512.lo;
    equal_flag=EQUAL_256(full_product_512.hi,zero_256);
    if (!equal_flag)
    {
        overflow=1;
    }
    return overflow;
}

int compare128(uint128_t N1, uint128_t N2)
{
    return    (((N1.hi > N2.hi) || ((N1.hi == N2.hi) && (N1.lo > N2.lo))) ? 1 : 0) 
         -    (((N1.hi < N2.hi) || ((N1.hi == N2.hi) && (N1.lo < N2.lo))) ? 1 : 0);
}

size_t nlz64(uint64_t N)
{
    uint64_t I;
    size_t C;

    I = ~N;
    C = ((I ^ (I + 1)) & I) >> 63;

    I = (N >> 32) + 0xffffffff;
    I = ((I & 0x100000000) ^ 0x100000000) >> 27;
    C += I;  N <<= I;

    I = (N >> 48) + 0xffff;
    I = ((I & 0x10000) ^ 0x10000) >> 12;
    C += I;  N <<= I;

    I = (N >> 56) + 0xff;
    I = ((I & 0x100) ^ 0x100) >> 5;
    C += I;  N <<= I;

    I = (N >> 60) + 0xf;
    I = ((I & 0x10) ^ 0x10) >> 2;
    C += I;  N <<= I;

    I = (N >> 62) + 3;
    I = ((I & 4) ^ 4) >> 1;
    C += I;  N <<= I;

    C += (N >> 63) ^ 1;

    return C;
}

size_t nlz128(uint128_t N)
{
    return (N.hi == 0) ? nlz64(N.lo) + 64 : nlz64(N.hi);
}

void shiftleft128(uint128_t N, unsigned S, uint128_t* A)
{
    uint64_t M1, M2;
    S &= 127;

    M1 = ((((S + 127) | S) & 64) >> 6) - 1llu;
    M2 = (S >> 6) - 1llu;
    S &= 63;
    A->hi = (N.lo << S) & (~M2);
    A->lo = (N.lo << S) & M2;
    A->hi |= ((N.hi << S) | ((N.lo >> (64 - S)) & M1)) & M2;
}

void shiftright128(uint128_t N, unsigned S, uint128_t* A)
{
    uint64_t M1, M2;
    S &= 127;

    M1 = ((((S + 127) | S) & 64) >> 6) - 1llu;
    M2 = (S >> 6) - 1llu;
    S &= 63;
    A->lo = (N.hi >> S) & (~M2);
    A->hi = (N.hi >> S) & M2;
    A->lo |= ((N.lo >> S) | ((N.hi << (64 - S)) & M1)) & M2;
} 

void sub128(uint128_t* Ans, uint128_t N, uint128_t M)
{
    Ans->lo = N.lo - M.lo;
    uint64_t C = (((Ans->lo & M.lo) & 1) + (M.lo >> 1) + (Ans->lo >> 1)) >> 63;
    Ans->hi = N.hi - (M.hi + C);
}
void bindivmod128(uint128_t M, uint128_t N, uint128_t* Q, uint128_t* R)
{
    Q->hi = Q->lo = 0;
    size_t Shift = nlz128(N) - nlz128(M);
    shiftleft128(N, Shift, &N);

    do
    {
        shiftleft128(*Q, 1, Q);
        if(compare128(M, N) >= 0)
        {
            sub128(&M, N, M);
            Q->lo |= 1;
        }

        shiftright128(N, 1, &N);
    }while(Shift-- != 0);

    R->hi = M.hi;
    R->lo = M.lo;
}
#else
uint128_t dap_uint128_substract(uint128_t a, uint128_t b);
uint128_t dap_uint128_add(uint128_t a, uint128_t b);
bool dap_uint128_check_equal(uint128_t a, uint128_t b);
#endif
