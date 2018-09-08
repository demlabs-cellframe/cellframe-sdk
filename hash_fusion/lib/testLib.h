#ifndef __TEST_LIB_H__
#define __TEST_LIB_H__

/*******************************************************************************
  testLib.h

  Test Lib code for Hash Fusion and Merkle Tree testing code

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

#include "utils.h"
#include "hashlib.h"
#include "fragment.h"
#include "fragmentMap.h"
#include "hashFusion.h"


typedef enum {
     CONSOLE_OUTPUT_KIND = 650,  // Console output
     CSV_OUTPUT_KIND,            // CSV output
     JSON_OUTPUT_KIND            // JSON output
   }
   OutputKind_t;


/*******************************************************************************
  Parameters
  - These parameters allow user code to set/get entities.
*******************************************************************************/

// Generated permutation of dataBlocks simulating the order in which
// dataBlocks arrive at their destination ...
int *destBlocksPerm;

// Total number of data blocks to be consumed.
int totalBlocks;

// Blocksize
int blockSize;

// Specifies type of hash
HashSpec_t hSpec;

// autoClean option - for Merkle Tree
Boolean_t autoClean;

// Hash Fusion accumulation type
HFuseAccum_t accumKind;


/*******************************************************************************
  Key comparison predicate
*******************************************************************************/
Comparison_t keyCompFn(Key_t keyA, Key_t keyB);


/*******************************************************************************
  Adjacency comparison predicate
*******************************************************************************/
AdjData_t adjCompFn(Key_t keyA, Key_t keyB);


/*******************************************************************************
  Methods
*******************************************************************************/
void initialiseTestData();

void populateBlocks();

void randomiseDestOrder();

// These execute hash accumulation computation
// - input is a destination permutation (as 0-based int array)
// - output is pointer to the generated digest ...
Digest_t  *calcDigest_FusionStruct(int *destPerm);
Digest_t  *calcDigest_MerkleTree(int *destPerm);

#endif
