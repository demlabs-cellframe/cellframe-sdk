#include <boost/multiprecision/cpp_int.hpp>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "dap_math_ops.h"
#include <cmath>
#include <iostream>
#include <fstream>

int main()
{
   using namespace boost::multiprecision;

   //density constant value=2147483646
   std::uint64_t i;
   std::uint64_t j;
   std::uint64_t k;
   std::uint64_t l;
   std::uint64_t msb_one=0x7fffffffffffffff;
   std::uint64_t lsb_one=1;
   boost::uint64_t max_64=(std::numeric_limits<boost::uint64_t>::max)();
   int density_constant=40000;
   //2147483646
   int density_index;
   int error_counter_sum_64_128=0;
    
    
   unsign256_t dap_test_256_one;
   unsign256_t dap_test_256_two;
   unsign256_t dap_test_256_sum;   
   int overflow_flag;

   //otherwise the sum structure is filled with garbage
   dap_test_256_sum.lo.lo=0;
   dap_test_256_sum.lo.hi=0;
   dap_test_256_sum.hi.lo=0;
   dap_test_256_sum.hi.hi=0;

   std::ofstream sum_256_256_file;
   sum_256_256_file.open ("SUM_256_256.txt");  

   std::ofstream prod_64_128_file;
   prod_64_128_file.open ("PROD_64_128.txt");  


   uint128_t hi_64{"0xffffffffffffffff0000000000000000"};
   uint128_t lo_64{"0x0000000000000000ffffffffffffffff"};
   uint128_t max_128{"0xffffffffffffffffffffffffffffffff"};

   uint128_t two_64{"0x000000000000000010000000000000000"};



   uint256_t boost_two_64{"0x00000000000000000000000000000000010000000000000000"};
   uint256_t boost_two_128{"0x0000000000000000100000000000000000000000000000000"};
   uint256_t boost_two_192{"0x1000000000000000000000000000000000000000000000000"};


   
   uint256_t boost_test_256_one;
   uint256_t boost_test_256_two;
   uint256_t boost_test_256_sum;
   
   uint256_t boost_dap_256_comparison;


   
   uint128_t boost_dap_64_128_comparison;

   int error_counter_sum=0;
   int error_counter_prod=0;
   int verbose_output=0;


   for (density_index = 0; density_index<density_constant; density_index+=1000){

        i=density_index;
        j=2*density_index;
        k=3*density_index;
        l=4*density_index;

        dap_test_256_one.lo.lo=i;
        dap_test_256_one.lo.hi=j;
        dap_test_256_one.hi.lo=k;
        dap_test_256_one.hi.hi=l;


        uint256_t boost_test_256_one_coeff_2_0=i;               
        uint256_t boost_test_256_one_coeff_2_64=j;
        uint256_t boost_test_256_one_coeff_2_128=k;
        uint256_t boost_test_256_one_coeff_2_192=l;



        boost_test_256_one=boost_test_256_one_coeff_2_0 + boost_test_256_one_coeff_2_64*boost_two_64
        +boost_test_256_one_coeff_2_128*boost_two_128+boost_test_256_one_coeff_2_192*boost_two_192;


        i=max_64-(density_index+1);
        j=max_64-2*(density_index+1);
        k=max_64-3*(density_index+1);
        l=max_64-4*(density_index+1);
        dap_test_256_two.lo.lo=i;
        dap_test_256_two.lo.hi=j;
        dap_test_256_two.hi.lo=k;
        dap_test_256_two.hi.hi=l;

        uint256_t boost_test_256_two_coeff_2_0=i;               
        uint256_t boost_test_256_two_coeff_2_64=j;
        uint256_t boost_test_256_two_coeff_2_128=k;
        uint256_t boost_test_256_two_coeff_2_192=l;


        boost_test_256_two=boost_test_256_two_coeff_2_0 + boost_test_256_two_coeff_2_64*boost_two_64
        +boost_test_256_two_coeff_2_128*boost_two_128+boost_test_256_two_coeff_2_192*boost_two_192;

       

//        add(boost_add_256, i, j);
        overflow_flag=SUM_256_256(dap_test_256_one,dap_test_256_two,&dap_test_256_sum);
        boost_test_256_sum=add(boost_test_256_sum,boost_test_256_one,boost_test_256_two);
        
        boost_dap_256_comparison=dap_test_256_sum.lo.lo+dap_test_256_sum.lo.hi*boost_two_64+
        dap_test_256_sum.hi.lo*boost_two_128+dap_test_256_sum.hi.hi*boost_two_192;

        if(boost_dap_256_comparison!=boost_test_256_sum){
        error_counter_sum+=1;
        sum_256_256_file << "incorrect output for density index=" << std::endl;
        sum_256_256_file << density_index << std::endl;}
        


//        unsign128_t dap_test_64_128_prod;
//        uint128_t boost_test_64_128_prod;
//        uint128_t boost_dap_128_prod_comparison;
//        
//        multiply(boost_test_64_128_prod, i, j);
//        MULT_64_128(i,j,dap_test_64_128_prod);
//        boost_dap_128_prod_comparison=dap_test_64_128_prod.lo+dap_test_64_128_prod.hi*hi_64;
//        
//        if(boost_dap_128_prod_comparison!=boost_test_64_128_prod){
//            error_counter_prod+=1;}
        

        
        if(verbose_output==1){

        if(boost_dap_256_comparison!=boost_test_256_sum){

        sum_256_256_file << "dap_test_256_one"<< std::endl;

        sum_256_256_file << (dap_test_256_one.lo.lo)<< std::endl;
        sum_256_256_file << (dap_test_256_one.lo.hi)<< std::endl;
        sum_256_256_file << (dap_test_256_one.hi.lo)<< std::endl;
        sum_256_256_file << (dap_test_256_one.hi.hi)<< std::endl;


        sum_256_256_file << "dap_test_256_two"<< std::endl;

        sum_256_256_file << (dap_test_256_two.lo.lo)<< std::endl;
        sum_256_256_file << (dap_test_256_two.lo.hi)<< std::endl;
        sum_256_256_file << (dap_test_256_two.hi.lo)<< std::endl;
        sum_256_256_file << (dap_test_256_two.hi.hi)<< std::endl;

        sum_256_256_file << "dap_test_256_sum"<< std::endl;

        sum_256_256_file << (dap_test_256_sum.lo.lo)<< std::endl;
        sum_256_256_file << (dap_test_256_sum.lo.hi)<< std::endl;
        sum_256_256_file << (dap_test_256_sum.hi.lo)<< std::endl;
        sum_256_256_file << (dap_test_256_sum.hi.hi)<< std::endl;

        sum_256_256_file << "boost_test_256_one"<< std::endl;

        sum_256_256_file << (boost_test_256_one)<< std::endl;
    
        sum_256_256_file << "boost_test_256_one factor 0"<< std::endl;

        sum_256_256_file << (boost_test_256_one_coeff_2_0)<< std::endl;
    
        sum_256_256_file << "boost_test_256_one factor 1"<< std::endl;

        sum_256_256_file << (boost_test_256_one_coeff_2_64*boost_two_64)<< std::endl;

        sum_256_256_file << "boost_test_256_one factor 2"<< std::endl;

        sum_256_256_file << (boost_test_256_one_coeff_2_128*boost_two_128)<< std::endl;
    

        sum_256_256_file << "boost_test_256_one factor 3"<< std::endl;

        sum_256_256_file << (boost_test_256_one_coeff_2_192*boost_two_192)<< std::endl;



        sum_256_256_file << "boost_test_256_two"<< std::endl;

        sum_256_256_file << (boost_test_256_two)<< std::endl;


        sum_256_256_file << "boost sum is"<< std::endl;


        sum_256_256_file << (boost_test_256_sum)<< std::endl;

        sum_256_256_file << "boost comparison is"<< std::endl;


        sum_256_256_file << (boost_dap_256_comparison)<< std::endl;}

    
//        if(boost_dap_256_comparison!=boost_test_256_sum){
//
//        prod_64_128_file << "boost_dap_128_prod_comparison"<< std::endl;
//
//        prod_64_128_file << (boost_dap_128_prod_comparison)<< std::endl;
//
//        prod_64_128_file << "boost_test_64_128_prod"<< std::endl;
//
//        prod_64_128_file << (boost_test_64_128_prod)<< std::endl;
//
//}
//






}
  
        
    overflow_flag=0;

    }

    
    sum_256_256_file.close();

   if(error_counter_sum==0){

    std::cout<< "SUM_256_256 returns identical results to boost:: 256 bit addition"<< std::endl;}

//
//   if(error_counter_prod==0){
//
//   std::cout<< "SUM_256_256 returns identical results to boost:: 256 bit addition"<< std::endl;}


   return 0;
}


