#include <boost/multiprecision/cpp_int.hpp>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "dap_math_ops.h"
#include <cmath>
#include <iostream>
#include <fstream>

enum testing_mode{
FULL=0,
BASIC=1,
SQUARE=2,   
};

int main()
{
   //using namespace boost::multiprecision;

   //density constant value=2147483646
   std::uint64_t i;
   std::uint64_t j;
   std::uint64_t k;
   std::uint64_t l;
   std::uint64_t msb_one=0x7fffffffffffffff;
   std::uint64_t lsb_one=1;
   boost::uint64_t max_64=(std::numeric_limits<boost::uint64_t>::max)();
   

   /////testing output parameters
   int verbose_output=1;
   int testing_mode=0;
   int density_constant=200;
   int division_enabled=0;


   //2147483646
   int density_index=0;
   
   int error_counter_sum_64_128=0;
    
   uint128_t dap_test_128_shift={.hi=0, .lo=0}; 
   uint128_t dap_test_128_one={.hi=0, .lo=0};
   uint128_t dap_test_128_two={.hi=0, .lo=0};
   uint128_t dap_test_128_sub={.hi=0, .lo=0};
   uint256_t dap_test_256_one={.hi=zero_128, .lo=zero_128};
   uint256_t dap_test_256_two={.hi=zero_128, .lo=zero_128};
   uint256_t dap_test_256_sum={.hi=zero_128, .lo=zero_128}; 
   uint256_t dap_test_256_sub={.hi=zero_128, .lo=zero_128}; 
   uint256_t dap_test_256_prod={.hi=zero_128, .lo=zero_128};
   uint256_t dap_test_256_shift={.hi=zero_128, .lo=zero_128};
   uint512_t dap_test_512_prod={.hi=zero_256, .lo=zero_256};
   int overflow_flag;
   int overflow_flag_prod;
   int borrow_flag_128;
   int borrow_flag_256;

   //otherwise the sum structure is filled with garbage
   dap_test_256_sum.lo.lo=0;
   dap_test_256_sum.lo.hi=0;
   dap_test_256_sum.hi.lo=0;
   dap_test_256_sum.hi.hi=0;

   std::ofstream sum_256_256_file;
   sum_256_256_file.open ("SUM_256_256.txt");  

   std::ofstream sub_128_128_file;
   sub_128_128_file.open ("SUB_128_128.txt");  
    
   std::ofstream sub_256_256_file;
   sub_256_256_file.open ("SUB_256_256.txt");  

   std::ofstream prod_64_128_file;
   prod_64_128_file.open ("PROD_64_128.txt");  

   std::ofstream prod_128_128_file;
   prod_128_128_file.open ("PROD_128_128.txt");  

   std::ofstream prod_128_256_file;
   prod_128_256_file.open ("PROD_128_256.txt");  

   std::ofstream prod_256_256_file;
   prod_256_256_file.open ("PROD_256_256.txt");  

   std::ofstream prod_256_512_file;
   prod_256_512_file.open ("PROD_256_512.txt"); 

   std::ofstream shift_left_128_file;
   shift_left_128_file.open ("SHIFT_LEFT_128.txt");  

   std::ofstream shift_left_256_file;
   shift_left_256_file.open ("SHIFT_LEFT_256.txt");  

if (division_enabled==1){
   std::ofstream quot_128_file;
   quot_128_file.open ("QUOT_128.txt");  
}


   boost::multiprecision::uint128_t hi_64{"0xffffffffffffffff0000000000000000"};
   boost::multiprecision::uint128_t lo_64{"0x0000000000000000ffffffffffffffff"};
   boost::multiprecision::uint128_t max_128{"0xffffffffffffffffffffffffffffffff"};
   boost::multiprecision::uint128_t two_64{"0x000000000000000010000000000000000"};

   boost::multiprecision::uint256_t boost_two_64{"0x00000000000000000000000000000000010000000000000000"};
   boost::multiprecision::uint256_t boost_two_128{"0x0000000000000000100000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_two_192{"0x1000000000000000000000000000000000000000000000000"};

   boost::multiprecision::uint512_t boost_two_64_for_512_calc{"0x00000000000000000000000000000000010000000000000000"};
   boost::multiprecision::uint512_t boost_two_128_for_512_calc{"0x0000000000000000100000000000000000000000000000000"};
   boost::multiprecision::uint512_t boost_two_192_for_512_calc{"0x1000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint512_t boost_two_256_for_512_calc{"0x000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"};

    boost::multiprecision::uint512_t boost_two_320_for_512_calc{"0x100000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_two_384_for_512_calc{"0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    boost::multiprecision::uint512_t boost_two_448_for_512_calc{"0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};

    boost::multiprecision::uint128_t boost_two_64_for_128_calc{"0x000000000000000010000000000000000"};   

    


   boost::multiprecision::uint256_t boost_test_256_one{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_test_256_two{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_test_256_sum{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_test_256_sub{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_test_256_prod{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_test_512_prod_hi_prod{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_test_512_prod_lo_prod{"0x0000000000000000000000000000000000000000000000000"};
    

   boost::multiprecision::uint512_t boost_test_2_256_quotient{"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint512_t boost_test_2_256_remainder{"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint512_t boost_test_512_prod{"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}; 

   boost::multiprecision::uint128_t boost_test_128_one{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_128_two{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_128_sub{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_256_one_lo{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_256_one_hi{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_256_two_lo{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_256_two_hi{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_dap_64_128_comparison{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_shift_left_128{"0x000000000000000000000000000000000"};   
   boost::multiprecision::uint128_t boost_test_shift_left_128_quotient_limb{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_test_shift_left_128_remainder_limb{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_dap_comparison_shift_left_128{"0x000000000000000000000000000000000"};    
   boost::multiprecision::uint128_t boost_test_64_128_prod{"0x000000000000000000000000000000000"};
   boost::multiprecision::uint128_t boost_dap_128_prod_comparison{"0x000000000000000000000000000000000"};    
   boost::multiprecision::uint128_t boost_dap_128_comparison_sub{"0x000000000000000000000000000000000"};
    
   boost::multiprecision::uint256_t boost_dap_256_comparison{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_dap_256_comparison_sub{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_dap_256_comparison_prod{"0x0000000000000000000000000000000000000000000000000"}; 
   boost::multiprecision::uint256_t boost_test_shift_left_256{"0x0000000000000000000000000000000000000000000000000"};
   boost::multiprecision::uint256_t boost_dap_comparison_shift_left_256{"0x0000000000000000000000000000000000000000000000000"};
    
   boost::multiprecision::uint512_t boost_dap_512_comparison_prod{"0x0"}; 
   


    
   int error_counter_sum=0;
   int error_counter_prod=0;
   int error_counter_sub_128=0;
   int error_counter_sub_256=0;
   int error_counter_prod_128_128=0;
   int error_counter_prod_128_256=0;    
   int error_counter_prod_256_256=0;
   int error_counter_prod_256_512=0;
   int error_counter_shift_left_128=0;
   int error_counter_shift_left_256=0; 
   int error_counter_quot_128=0;   
   


   for (density_index = 0; density_index<density_constant; density_index+=1){


        /////////////////////output of 256+256-->256//////////////////////

        if (testing_mode==FULL){
        i=density_index;
        j=2*density_index;
        k=3*density_index;
        l=4*density_index;
        }
        if (testing_mode==BASIC){
        i=density_index;
        j=density_index;
        k=density_index;
        l=density_index;
        }

        if (testing_mode==SQUARE){
        i=density_index;
        j=density_index;
        k=density_index;
        l=density_index;
        }
        

        dap_test_256_one.lo.lo=i;
        dap_test_256_one.lo.hi=j;
        dap_test_256_one.hi.lo=k;
        dap_test_256_one.hi.hi=l;


        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_0=i;               
        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_64=j;
        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_128=k;
        boost::multiprecision::uint256_t boost_test_256_one_coeff_2_192=l;



        boost_test_256_one=boost_test_256_one_coeff_2_0 + boost_test_256_one_coeff_2_64*boost_two_64
        +boost_test_256_one_coeff_2_128*boost_two_128+boost_test_256_one_coeff_2_192*boost_two_192;
        
//        boost_test_256_one_hi=boost_test_256_one_coeff_2_128+boost_two_64*boost_test_256_one_coeff_2_192;
//        boost_test_256_one_lo=boost_test_256_one_coeff_2_0+boost_test_256_one_coeff_2_64*boost_two_64;
    
        if(testing_mode==FULL){
        i=max_64-(density_index+1);
        j=max_64-2*(density_index+1);
        k=max_64-3*(density_index+1);
        l=max_64-4*(density_index+1);
        }

        if (testing_mode==BASIC){
        i=density_index+1;
        j=density_index+1;
        k=density_index+1;
        l=density_index+1;
        }

        if (testing_mode==SQUARE){
        i=density_index;
        j=density_index;
        k=density_index;
        l=density_index;  
        }
        

        dap_test_256_two.lo.lo=i;
        dap_test_256_two.lo.hi=j;
        dap_test_256_two.hi.lo=k;
        dap_test_256_two.hi.hi=l;
       

        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_0=i;               
        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_64=j;
        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_128=k;
        boost::multiprecision::uint256_t boost_test_256_two_coeff_2_192=l;


        boost_test_256_two=boost_test_256_two_coeff_2_0 + boost_test_256_two_coeff_2_64*boost_two_64
        +boost_test_256_two_coeff_2_128*boost_two_128+boost_test_256_two_coeff_2_192*boost_two_192;

//        boost_test_256_two_hi=boost_test_256_two_coeff_2_128+boost_two_64*boost_test_256_two_coeff_2_192;
//        boost_test_256_two_lo=boost_test_256_one_coeff_2_0+boost_test_256_two_coeff_2_64*boost_two_64;

//        add(boost_add_256, i, j);
        
        overflow_flag=SUM_256_256(dap_test_256_one,dap_test_256_two,&dap_test_256_sum);
        add(boost_test_256_sum,boost_test_256_one,boost_test_256_two);
        
        boost_dap_256_comparison=dap_test_256_sum.lo.lo+dap_test_256_sum.lo.hi*boost_two_64+
        dap_test_256_sum.hi.lo*boost_two_128+dap_test_256_sum.hi.hi*boost_two_192;

        if(boost_dap_256_comparison!=boost_test_256_sum){
        error_counter_sum+=1;
        sum_256_256_file << "incorrect output for density index=" << std::endl;
        sum_256_256_file << density_index << std::endl;}

    
        ///256 bit subtraction

        borrow_flag_256=SUBTRACT_256_256(dap_test_256_two,dap_test_256_one,&dap_test_256_sub);
        subtract(boost_test_256_sub,boost_test_256_two,boost_test_256_one);
        
        boost_dap_256_comparison_sub=dap_test_256_sub.lo.lo+dap_test_256_sub.lo.hi*boost_two_64+
        dap_test_256_sub.hi.lo*boost_two_128+dap_test_256_sub.hi.hi*boost_two_192;

        if(boost_dap_256_comparison_sub!=boost_test_256_sub){
        error_counter_sub_256+=1;
        sub_256_256_file << "incorrect output for density index=" << std::endl;
        sub_256_256_file << density_index << std::endl;}

        



        /////////////////////output of 256*256-->256//////////////////////

        overflow_flag_prod=MULT_256_256(dap_test_256_one,dap_test_256_two,&dap_test_256_prod);
        multiply(boost_test_256_prod,boost_test_256_one,boost_test_256_two);
        multiply(boost_test_512_prod,boost_test_256_one,boost_test_256_two);
//        multiply(boost_test_512_prod_hi_prod,boost_test_256_one_hi,boost_test_256_two_hi);
//        multiply(boost_test_512_prod_lo_prod,boost_test_256_one_lo,boost_test_256_two_lo);
        divide_qr(boost_test_512_prod,boost_two_256_for_512_calc,boost_test_2_256_quotient,boost_test_2_256_remainder);

        boost_dap_256_comparison_prod=dap_test_256_prod.lo.lo+dap_test_256_prod.lo.hi*boost_two_64+
        dap_test_256_prod.hi.lo*boost_two_128+dap_test_256_prod.hi.hi*boost_two_192;

        if(boost_dap_256_comparison_prod!=boost_test_256_prod){
        error_counter_prod_256_256+=1;
        prod_256_256_file << "incorrect product output for density index=" << std::endl;
        prod_256_256_file << density_index << std::endl;}

        /////////////////////output of 256*256-->512//////////////////////
        dap_test_512_prod.lo=zero_256;
        dap_test_512_prod.hi=zero_256;
        uint256_t intermed_lo_prod;
        uint256_t intermed_hi_prod;
        MULT_128_256(dap_test_256_one.lo,dap_test_256_two.lo,&intermed_lo_prod);
        MULT_128_256(dap_test_256_one.hi,dap_test_256_two.hi,&intermed_hi_prod);
        
        MULT_256_512(dap_test_256_one,dap_test_256_two,&dap_test_512_prod);


        boost_dap_512_comparison_prod=dap_test_512_prod.lo.lo.lo+
        dap_test_512_prod.lo.lo.hi*boost_two_64_for_512_calc+
        dap_test_512_prod.lo.hi.lo*boost_two_128_for_512_calc+
        dap_test_512_prod.lo.hi.hi*boost_two_192_for_512_calc+
        dap_test_512_prod.hi.lo.lo*boost_two_256_for_512_calc+
        dap_test_512_prod.hi.lo.hi*boost_two_320_for_512_calc+
        dap_test_512_prod.hi.hi.lo*boost_two_384_for_512_calc+
        dap_test_512_prod.hi.hi.hi*boost_two_448_for_512_calc;

        if(boost_dap_512_comparison_prod!=boost_test_512_prod){
        error_counter_prod_256_512+=1;
        prod_256_512_file << "incorrect product output for density index=" << std::endl;
        prod_256_512_file << density_index << std::endl;}

        /////////////////////output of shift left 128/////////////////////
        
        if (density_index<=127){
        dap_test_128_one=dap_test_256_one.lo;
        LEFT_SHIFT_128(dap_test_128_one,&dap_test_128_shift,density_index);

        boost_test_128_one=dap_test_128_one.lo+dap_test_128_one.hi*boost_two_64_for_128_calc;
        boost_test_shift_left_128=boost_test_128_one<<density_index;
        boost_dap_comparison_shift_left_128=dap_test_128_shift.lo+dap_test_128_shift.hi*boost_two_64_for_128_calc;

                 divide_qr(boost_test_shift_left_128,boost_two_64_for_128_calc,boost_test_shift_left_128_quotient_limb,boost_test_shift_left_128_remainder_limb);
        
        if(boost_dap_comparison_shift_left_128!=boost_test_shift_left_128){
        error_counter_shift_left_128+=1;
        shift_left_128_file << "incorrect shift left 128 output for density index=" << std::endl;
        shift_left_128_file << density_index << std::endl;}
        }
        /////////////////////output of shift left 256/////////////////////
        
        if (density_index<=255){
        LEFT_SHIFT_256(dap_test_256_one,&dap_test_256_shift,density_index);

        boost_test_256_one=boost_test_256_one_coeff_2_0 + boost_test_256_one_coeff_2_64*boost_two_64
        +boost_test_256_one_coeff_2_128*boost_two_128+boost_test_256_one_coeff_2_192*boost_two_192;
        boost_test_shift_left_256=boost_test_256_one<<density_index;
        boost_dap_comparison_shift_left_256=dap_test_256_shift.lo.lo+dap_test_256_shift.lo.hi*boost_two_64+
        dap_test_256_shift.hi.lo*boost_two_128+dap_test_256_shift.hi.hi*boost_two_192;

        
        if(boost_dap_comparison_shift_left_256!=boost_test_shift_left_256){
        error_counter_shift_left_256+=1;
        shift_left_256_file << "incorrect shift left 256 output for density index=" << std::endl;
        shift_left_256_file << density_index << std::endl;}
        }
    
        /////////////////////output of 64*64-->128////////////////////////


        i=density_index;
        j=max_64-(density_index+1);
        uint128_t dap_test_64_128_prod;
        dap_test_64_128_prod.lo=0;
        dap_test_64_128_prod.hi=0;
 


        multiply(boost_test_64_128_prod, i, j);
        MULT_64_128(i,j,&dap_test_64_128_prod);
        boost_dap_128_prod_comparison=dap_test_64_128_prod.lo+dap_test_64_128_prod.hi*two_64;
        
        if(boost_dap_128_prod_comparison!=boost_test_64_128_prod){
            error_counter_prod+=1;}

        /////////////////////output of 128*128-->128////////////////////////

        uint128_t dap_test_128_128_prod_one;
        uint128_t dap_test_128_128_prod_two;
        uint128_t dap_test_128_128_prod_prod;
        dap_test_128_128_prod_one.lo=i;
        dap_test_128_128_prod_one.hi=j;
        dap_test_128_128_prod_two.lo=max_64-(i+1);
        dap_test_128_128_prod_two.hi=max_64-2*(j+1);
        dap_test_128_128_prod_prod.lo=0;
        dap_test_128_128_prod_prod.hi=0;
        
        boost::multiprecision::uint128_t boost_test_128_128_prod;
        boost::multiprecision::uint128_t boost_test_128_128_one;
        boost::multiprecision::uint128_t boost_test_128_128_two;   
        boost::multiprecision::uint128_t boost_dap_128_128_prod_comparison;

        ////compute boost "factors"
        boost_test_128_128_one=i+j*boost_two_64_for_128_calc;
        boost_test_128_128_two=max_64-(i+1)+(max_64-2*(j+1))*boost_two_64_for_128_calc;
        
        
        multiply(boost_test_128_128_prod, boost_test_128_128_one, boost_test_128_128_two);
        MULT_128_128(dap_test_128_128_prod_one,dap_test_128_128_prod_two,&dap_test_128_128_prod_prod);
        boost_dap_128_128_prod_comparison=dap_test_128_128_prod_prod.lo+dap_test_128_128_prod_prod.hi*boost_two_64_for_128_calc;
        
        if(boost_dap_128_128_prod_comparison!=boost_test_128_128_prod){
            error_counter_prod_128_128+=1;}


        ///128 bit subtraction

        borrow_flag_128=SUBTRACT_128_128(dap_test_128_one,dap_test_128_two,&dap_test_128_sub);
        subtract(boost_test_128_sub,boost_test_128_one,boost_test_128_two);
        
        boost_dap_128_comparison_sub=dap_test_128_sub.lo+dap_test_128_sub.hi*boost_two_64_for_128_calc;
        

        if(boost_dap_128_comparison_sub!=boost_test_128_sub){
        error_counter_sub_128+=1;
        sub_128_128_file << "incorrect output for density index=" << std::endl;
        sub_128_128_file << density_index << std::endl;}

        



        /////////////////////output of 128*128-->256////////////////////////

        
        uint128_t dap_test_128_256_prod_one;
        uint128_t dap_test_128_256_prod_two;
        uint256_t dap_test_128_256_prod_prod;
        dap_test_128_256_prod_one.lo=i;
        dap_test_128_256_prod_one.hi=j;
        dap_test_128_256_prod_two.lo=max_64-(i+1);
        dap_test_128_256_prod_two.hi=max_64-2*(j+1);
        dap_test_128_256_prod_prod.lo=zero_128;
        dap_test_128_256_prod_prod.hi=zero_128;
        
        boost::multiprecision::uint256_t boost_test_128_256_prod;
        boost::multiprecision::uint128_t boost_test_128_256_one;
        boost::multiprecision::uint128_t boost_test_128_256_two;   
        boost::multiprecision::uint256_t boost_dap_128_256_prod_comparison;

        ////compute boost "factors"
        boost_test_128_256_one=i+j*boost_two_64_for_128_calc;
        boost_test_128_256_two=(max_64-(i+1))+(max_64-2*(j+1))*boost_two_64_for_128_calc;
        
        multiply(boost_test_128_256_prod, boost_test_128_256_one, boost_test_128_256_two);
        MULT_128_256(dap_test_128_256_prod_one,dap_test_128_256_prod_two,&dap_test_128_256_prod_prod);
        boost_dap_128_256_prod_comparison=dap_test_128_256_prod_prod.lo.lo+
        dap_test_128_256_prod_prod.lo.hi*boost_two_64+
        dap_test_128_256_prod_prod.hi.lo*boost_two_128+
        dap_test_128_256_prod_prod.hi.hi*boost_two_192;
    

        
        if(boost_dap_128_256_prod_comparison!=boost_test_128_256_prod){
            
            error_counter_prod_128_256+=1;

            std::cout << ("boost_dap_128_256_prod_comparison")<< std::endl;
            std::cout << (boost_dap_128_256_prod_comparison)<< std::endl;
            std::cout << ("boost_test_128_256_prod")<< std::endl;
            std::cout << (boost_test_128_256_prod)<< std::endl;}


        /////////////////////output of 128/128-->128////////////////////////
if(division_enabled==1){

        i=density_index+1;
        j=density_index+2;
        uint128_t dap_test_128_quot_one;
        uint128_t dap_test_128_quot_two;
        uint128_t dap_test_128_quot_quot;
        uint128_t dap_test_128_quot_rem;
        dap_test_128_quot_one.lo=i;
        dap_test_128_quot_one.hi=j;
        dap_test_128_quot_two.lo=max_64-(i+1);
        dap_test_128_quot_two.hi=max_64-2*(j+1);
        dap_test_128_quot_quot.lo=0;
        dap_test_128_quot_quot.hi=0;
        dap_test_128_quot_rem.lo=0;
        dap_test_128_quot_rem.hi=0;
        
        boost::multiprecision::uint128_t boost_test_128_quot_one;
        boost::multiprecision::uint128_t boost_test_128_quot_two;   
        boost::multiprecision::uint128_t boost_test_128_quot_quot;
        boost::multiprecision::uint128_t boost_test_128_quot_rem;
        boost::multiprecision::uint128_t boost_dap_128_quot_comparison_quot;
        boost::multiprecision::uint128_t boost_dap_128_quot_comparison_rem;

        ////compute boost "factors"
        boost_test_128_quot_one=i+j*boost_two_64_for_128_calc;
        boost_test_128_quot_two=(max_64-(i+1))+(max_64-2*(j+1))*boost_two_64_for_128_calc;
        
        divide_qr( boost_test_128_quot_two, boost_test_128_quot_one,boost_test_128_quot_quot,boost_test_128_quot_rem);
        bindivmod128(dap_test_128_quot_one,dap_test_128_quot_two,&dap_test_128_quot_quot,&dap_test_128_quot_rem);


        boost_dap_128_quot_comparison_quot=dap_test_128_quot_quot.lo+
        dap_test_128_quot_quot.hi*boost_two_64_for_128_calc;

        boost_dap_128_quot_comparison_rem=dap_test_128_quot_rem.lo+
        dap_test_128_quot_rem.hi*boost_two_64_for_128_calc;

        
        if((boost_dap_128_quot_comparison_quot!=boost_test_128_quot_quot)||(boost_dap_128_quot_comparison_rem!=boost_test_128_quot_rem)){
            
            error_counter_quot_128+=1;

            std::cout << ("boost_dap_128_quot_comparison_quot")<< std::endl;
            std::cout << (boost_dap_128_quot_comparison_quot)<< std::endl;
            std::cout << ("boost_dap_128_quot_comparison_rem")<< std::endl;
            std::cout << (boost_dap_128_quot_comparison_rem)<< std::endl;}

}


        /////////////////////print to file section////////////////////////

        
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

    
        if(boost_dap_256_comparison_prod!=boost_test_256_prod){

        prod_256_256_file << "dap_test_256_one"<< std::endl;

        prod_256_256_file << (dap_test_256_one.lo.lo)<< std::endl;
        prod_256_256_file << (dap_test_256_one.lo.hi)<< std::endl;
        prod_256_256_file << (dap_test_256_one.hi.lo)<< std::endl;
        prod_256_256_file << (dap_test_256_one.hi.hi)<< std::endl;


        prod_256_256_file << "dap_test_256_two"<< std::endl;

        prod_256_256_file << (dap_test_256_two.lo.lo)<< std::endl;
        prod_256_256_file << (dap_test_256_two.lo.hi)<< std::endl;
        prod_256_256_file << (dap_test_256_two.hi.lo)<< std::endl;
        prod_256_256_file << (dap_test_256_two.hi.hi)<< std::endl;

        prod_256_256_file << "dap_test_256_prod"<< std::endl;

        prod_256_256_file << (dap_test_256_prod.lo.lo)<< std::endl;
        prod_256_256_file << (dap_test_256_prod.lo.hi)<< std::endl;
        prod_256_256_file << (dap_test_256_prod.hi.lo)<< std::endl;
        prod_256_256_file << (dap_test_256_prod.hi.hi)<< std::endl;

        prod_256_256_file << "boost_test_256_one"<< std::endl;

        prod_256_256_file << (boost_test_256_one)<< std::endl;
    
        prod_256_256_file << "boost_test_256_one factor 0"<< std::endl;

        prod_256_256_file << (boost_test_256_one_coeff_2_0)<< std::endl;
    
        prod_256_256_file << "boost_test_256_one factor 1"<< std::endl;

        prod_256_256_file << (boost_test_256_one_coeff_2_64*boost_two_64)<< std::endl;

        prod_256_256_file << "boost_test_256_one factor 2"<< std::endl;

        prod_256_256_file << (boost_test_256_one_coeff_2_128*boost_two_128)<< std::endl;
    

        prod_256_256_file << "boost_test_256_one factor 3"<< std::endl;

        prod_256_256_file << (boost_test_256_one_coeff_2_192*boost_two_192)<< std::endl;



        prod_256_256_file << "boost_test_256_two"<< std::endl;

        prod_256_256_file << (boost_test_256_two)<< std::endl;



        prod_256_256_file << "boost_test_256_two factor 0"<< std::endl;

        prod_256_256_file << (boost_test_256_two_coeff_2_0)<< std::endl;
    
        prod_256_256_file << "boost_test_256_two factor 1"<< std::endl;

        prod_256_256_file << (boost_test_256_two_coeff_2_64*boost_two_64)<< std::endl;

        prod_256_256_file << "boost_test_256_two factor 2"<< std::endl;

        prod_256_256_file << (boost_test_256_two_coeff_2_128*boost_two_128)<< std::endl;
    
        prod_256_256_file << "boost_test_256_two factor 3"<< std::endl;

        prod_256_256_file << (boost_test_256_two_coeff_2_192*boost_two_192)<< std::endl;


        prod_256_256_file << "boost 256 prod is"<< std::endl;


        prod_256_256_file << (boost_test_256_prod)<< std::endl;


        prod_256_256_file << "boost 512 prod is"<< std::endl;


        prod_256_256_file << (boost_test_512_prod)<< std::endl;


        prod_256_256_file << "boost 2**256 quotient is"<< std::endl;


        prod_256_256_file << (boost_test_2_256_quotient)<< std::endl;

        prod_256_256_file << "boost 2**256 remainder is"<< std::endl;


        prod_256_256_file << (boost_test_2_256_remainder)<< std::endl;

        prod_256_256_file << "boost comparison is"<< std::endl;

        prod_256_256_file << (boost_dap_256_comparison_prod)<< std::endl;}

        if(boost_dap_512_comparison_prod!=boost_test_512_prod){


        prod_256_512_file << "dap_test_512_prod"<< std::endl;

        prod_256_512_file << (dap_test_512_prod.lo.lo.lo)<< std::endl;
        prod_256_512_file << (dap_test_512_prod.lo.lo.hi)<< std::endl;
        prod_256_512_file << (dap_test_512_prod.lo.hi.lo)<< std::endl;
        prod_256_512_file << (dap_test_512_prod.lo.hi.hi)<< std::endl;
        prod_256_512_file << (dap_test_512_prod.hi.lo.lo)<< std::endl;
        prod_256_512_file << (dap_test_512_prod.hi.lo.hi)<< std::endl;
        prod_256_512_file << (dap_test_512_prod.hi.hi.lo)<< std::endl;
        prod_256_512_file << (dap_test_512_prod.hi.hi.hi)<< std::endl;


        prod_256_512_file << "boost 512 prod is"<< std::endl;

        prod_256_512_file << (boost_test_512_prod)<< std::endl;

        prod_256_512_file << "boost comparison is"<< std::endl;

        prod_256_512_file << (boost_dap_512_comparison_prod)<< std::endl;}


        if(boost_test_64_128_prod!=boost_dap_128_prod_comparison){
        
        prod_64_128_file <<  " i is "<< std::endl;

        prod_64_128_file << (i)<< std::endl;
        
        prod_64_128_file <<  " j is "<< std::endl;

        prod_64_128_file << (j)<< std::endl;

        prod_64_128_file << "boost_dap_128_prod_comparison"<< std::endl;

        prod_64_128_file << (boost_dap_128_prod_comparison)<< std::endl;

        prod_64_128_file << "boost_test_64_128_prod"<< std::endl;

        prod_64_128_file << (boost_test_64_128_prod)<< std::endl;

        prod_64_128_file << "difference"<< std::endl;

        prod_64_128_file << (boost_dap_128_prod_comparison-boost_test_64_128_prod)<< std::endl;

}


        if(boost_test_128_128_prod!=boost_dap_128_128_prod_comparison){
        
        prod_128_128_file <<  " i is "<< std::endl;

        prod_128_128_file << (i)<< std::endl;
        
        prod_128_128_file <<  " j is "<< std::endl;

        prod_128_128_file << (j)<< std::endl;

        prod_128_128_file <<  " boost_test_128_128_one is "<< std::endl;

        prod_128_128_file << (boost_test_128_128_one)<< std::endl;

        prod_128_128_file <<  " boost_test_128_128_two is "<< std::endl;

        prod_128_128_file << (boost_test_128_128_two)<< std::endl;

        prod_128_128_file << "boost_dap_128_128_prod_comparison"<< std::endl;

        prod_128_128_file << (boost_dap_128_128_prod_comparison)<< std::endl;

        prod_128_128_file << "dap_test_128_128_prod_prod.lo"<< std::endl;

        prod_128_128_file << (dap_test_128_128_prod_prod.lo)<< std::endl;

        prod_128_128_file << "dap_test_128_128_prod_prod.hi"<< std::endl;

        prod_128_128_file << (dap_test_128_128_prod_prod.hi)<< std::endl;


        prod_128_128_file << "boost_test_128_128_prod"<< std::endl;

        prod_128_128_file << (boost_test_128_128_prod)<< std::endl;}


  
if (density_index<=127){
  if(boost_dap_comparison_shift_left_128!=boost_test_shift_left_128){
        shift_left_128_file <<  " density_index is "<< std::endl;

        shift_left_128_file << (density_index)<< std::endl;

        shift_left_128_file <<  " dap_test_128_one is "<< std::endl;

        shift_left_128_file << (dap_test_128_one.lo)<< std::endl;
        shift_left_128_file << (dap_test_128_one.hi)<< std::endl;
        
        shift_left_128_file <<  " dap_test_128_shift is "<< std::endl;

        shift_left_128_file << (dap_test_128_shift.lo)<< std::endl;
        shift_left_128_file << (dap_test_128_shift.hi)<< std::endl;

        shift_left_128_file <<  " boost_test_shift_left_128 .lo is  "<< std::endl;
        shift_left_128_file << boost_test_shift_left_128_remainder_limb<< std::endl;

        shift_left_128_file <<  " boost_test_shift_left_128 .hi is  "<< std::endl;
        shift_left_128_file << boost_test_shift_left_128_quotient_limb<< std::endl;


        }
        }


 if (density_index<=255){
 if(boost_dap_comparison_shift_left_256!=boost_test_shift_left_256){


        shift_left_256_file <<  " density_index is "<< std::endl;

        shift_left_256_file << (density_index)<< std::endl;

        shift_left_256_file <<  " dap_test_256_one is "<< std::endl;

        shift_left_256_file << (dap_test_256_one.lo.lo)<< std::endl;
        shift_left_256_file << (dap_test_256_one.lo.hi)<< std::endl;
        shift_left_256_file << (dap_test_256_one.hi.lo)<< std::endl;
        shift_left_256_file << (dap_test_256_one.hi.hi)<< std::endl;
   
        
        shift_left_256_file <<  " dap_test_256_shift is "<< std::endl;

        shift_left_256_file << (dap_test_256_shift.lo.lo)<< std::endl;
        shift_left_256_file << (dap_test_256_shift.lo.hi)<< std::endl;
        shift_left_256_file << (dap_test_256_shift.hi.lo)<< std::endl;
        shift_left_256_file << (dap_test_256_shift.hi.hi)<< std::endl;}
    }
    } 
        
    overflow_flag=0;

    }
    
    sum_256_256_file.close();

   if(error_counter_sum==0){

    std::cout<< "SUM_256_256 returns identical results to boost:: 256 bit addition"<< std::endl;}

    prod_64_128_file.close();

   if(error_counter_sub_128==0){

    std::cout<< "SUB_128_128 returns identical results to boost:: 128 bit subtraction"<< std::endl;}

    sub_128_128_file.close();

   if(error_counter_sub_256==0){

    std::cout<< "SUB_256_256 returns identical results to boost:: 256 bit subtraction"<< std::endl;}

    sub_256_256_file.close();


   if(error_counter_prod==0){

   std::cout<< "PROD_64_128 returns identical results to boost:: multiplication"<< std::endl;}

   prod_128_128_file.close();

   if(error_counter_prod_128_128==0){

   std::cout<< "PROD_128_128 returns identical results to boost:: 128 bit multiplication"<< std::endl;}

   if(error_counter_prod_128_256==0){

   std::cout<< "PROD_128_256 returns identical results to boost:: 128 bit multiplication"<< std::endl;}

   if(error_counter_prod_256_256==0){

   std::cout<< "PROD_256_256 returns identical results to boost:: 256 bit multiplication"<< std::endl;}

    if(error_counter_prod_256_512==0){

   std::cout<< "PROD_256_512 returns identical results to boost:: 256 bit multiplication"<< std::endl;}


   
   if(error_counter_shift_left_128==0){

    std::cout<< "SHIFT_LEFT_128 returns identical results to boost:: 128 bit <<"<< std::endl;}
   
   
   if(error_counter_shift_left_256==0){

    std::cout<< "SHIFT_LEFT_256 returns identical results to boost:: 256 bit <<"<< std::endl;}

if (division_enabled==1){

   if(error_counter_quot_128==0){

    std::cout<< "QUOT_128 returns identical results to boost:: 128 bit division"<< std::endl;}
   
}
   return 0;
}


