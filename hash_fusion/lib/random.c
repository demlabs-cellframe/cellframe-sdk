/* random.c

   Basic randomisation ...

   Uses simple Park-Miller MINSTD Lehmer RNG ...

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
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "utils.h"
#include "random.h"


unsigned long curState = -1;

unsigned long m = 2147483647;  // 2^31 - 1
unsigned long a = 16807;       // 7^5

// params
int getModulus() { return (int)m; }
int getMultiplier() { return (int)a; }


// Gets the current seed
unsigned int getSeed() {
  return curState;
}


// sets seed
// - selects randomised value, by giving a 0 seed value ...
void setSeed(unsigned int seed) {
   if (seed == 0) {
      seed = (unsigned int)time(NULL);
   }

   curState = seed % m;
}

// choose next random value
unsigned int nextRandom() {
   curState = (a*curState % m);  // Needs long (64-bit) to avoid overflow ...
   return (unsigned int)curState;
}


// choose next random Boolean value
Boolean_t nextRandom_Boolean() {
   return (nextRandom() % 2 == 0 ? TRUE : FALSE);
}


// choose next Boolean event according to probability
// - Value is TRUE on probability: pro / (pro + con)
// - Value is FALSE on probability: con / (pro + con)
Boolean_t nextRandom_Event(double pro, double con) {
   double prob = pro / (pro + con);
   return (nextRandom_Real() < prob ? TRUE : FALSE);
}


// choose random value v in **closed interval range**, where a <= v <= b.
int nextRandom_Range(int a, int b) {
   if (a == b) return a;

   if (a > b) {
      int c = a;
      a = b;
      b = c;
   }

   int mod = (b - a) + 1;
   unsigned int val = nextRandom() % mod;
   return val + a;
}


// choose next random Byte_t value
Byte_t nextRandom_BYTE() {
  return (Byte_t)nextRandom();
}


// choose a random value in the range (0, 1)
double nextRandom_Real() {
   //double val = (double)nextRandom();
   return (double)nextRandom()/m;
}


/*
void test() {
   unsigned int val = 0;
   int count = 0;

   printf("a = %i\n", a);
   printf("m = %i\n", m);

   //if x0 = 1, then x10000 = 1043618065
   setSeed(1);

   for (int i = 0; i <= 10003; i++) {
      val = nextRandom();
      count = i % 1000;
      if (count < 3 || 1000-3 < count) {
         printf("%i. val = %u = %.9g\n", i, val, (double)val/m);
      }
   }
}
*/
