#include <dap_math_ops.h>
#include <fp256.h>
#include <fp256_ll.h>

int DIV_256_256(uint256_t a_256_bit,uint256_t b_256_bit,uint256_t* q_256_bit,uint256_t* r_256_bit){

    int fpp_output;
    fp256 a_256_bit_fpp;
    fp256 b_256_bit_fpp;
    fp256 q_256_bit_fpp;
    fp256 r_256_bit_fpp;

    q_256_bit_fpp.d[0]=0;
    q_256_bit_fpp.d[1]=0;
    q_256_bit_fpp.d[2]=0;
    q_256_bit_fpp.d[3]=0;

    r_256_bit_fpp.d[0]=0;
    r_256_bit_fpp.d[1]=0;
    r_256_bit_fpp.d[2]=0;
    r_256_bit_fpp.d[3]=0;

    a_256_bit_fpp.d[0]=a_256_bit.lo.lo;
    a_256_bit_fpp.d[1]=a_256_bit.lo.hi;
    a_256_bit_fpp.d[2]=a_256_bit.hi.lo;
    a_256_bit_fpp.d[3]=a_256_bit.hi.hi;

    b_256_bit_fpp.d[0]=b_256_bit.lo.lo;
    b_256_bit_fpp.d[1]=b_256_bit.lo.hi;
    b_256_bit_fpp.d[2]=b_256_bit.hi.lo;
    b_256_bit_fpp.d[3]=b_256_bit.hi.hi;

    fpp_output=fp256_naive_div(&r_256_bit_fpp, &q_256_bit_fpp, &a_256_bit_fpp, &b_256_bit_fpp);

    q_256_bit->lo.lo=q_256_bit_fpp.d[0];
    q_256_bit->lo.hi=q_256_bit_fpp.d[1];
    q_256_bit->hi.lo=q_256_bit_fpp.d[2];
    q_256_bit->hi.hi=q_256_bit_fpp.d[3];

    r_256_bit->lo.lo=r_256_bit_fpp.d[0];
    r_256_bit->lo.hi=r_256_bit_fpp.d[1];
    r_256_bit->hi.lo=r_256_bit_fpp.d[2];
    r_256_bit->hi.hi=r_256_bit_fpp.d[3];

   return fpp_output;

}


