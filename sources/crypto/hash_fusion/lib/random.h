#ifndef __RANDOM_H__
#define __RANDOM_H__


#include "utils.h"

/*******************************************************************************
   random.h

   Simple random number generators
   - Uses the Park-Miller MINSTD Lehmer generator:

		  a = 7^5 = 16807
		  m = 2^31 - 1 = 2147483647

		  x_n+1 = (a * x_n) mod m

     See:  Park and Miller, "Random Number Generators: Good ones are hard to find",
     Communications of the ACM, October 1988, Volume 31, No 10, pages 1192-1201.
     
   Author: brian.monahan@hpe.com
      
   (c) Copyright 2017 Hewlett Packard Enterprise Development LP 

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met: 

   1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer. 

   2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution. 

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
   PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
*******************************************************************************/

// params
//int getModulus();
//int getMultiplier();

// Gets the current seed
unsigned int getSeed();

// Sets seed
// - selects randomised value, by giving a 0 seed value ...
void setSeed(unsigned int seed);

// choose next random integer value
unsigned int nextRandom();

// choose next random Boolean value (fair)
Boolean_t nextRandom_Boolean();

// choose next Boolean event according to probability
// - Value is TRUE on probability: pro / (pro + con)
// - Value is FALSE on probability: con / (pro + con)
Boolean_t nextRandom_Event(double pro, double con);

// choose random value v in **closed interval range**, where a <= v <= b.
int nextRandom_Range(int a, int b);

// choose next random Byte_t value
Byte_t nextRandom_BYTE();

// choose a random value in the range (0, 1)
double nextRandom_Real();

#endif
