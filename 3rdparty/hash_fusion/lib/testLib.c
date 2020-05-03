/*
   Test Lib code:

   Hash Fusion and Merkle Tree testing code

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
#include <math.h>

#include "utils.h"
#include "bytevector.h"
#include "stringbuffer.h"
#include "matrix.h"
#include "random.h"
#include "alloc.h"
#include "hashlib.h"
#include "merkleTree.h"
#include "fragment.h"
#include "fragmentMap.h"
#include "hashFusion.h"
#include "testLib.h"

/*******************************************************************************
  Variables and Arrays
*******************************************************************************/

// permutation of dataBlocks indicating the order in which
// dataBlocks arrive at their destination ...
// - Setting this to NULL ensures that the identity perm is used.
int *destBlocksPerm = 0;

// Total number of data blocks to be consumed.
int totalBlocks = 5; //20 * 1024;    // number of dataBlocks

// Blocksize
int blockSize = 1024;

// specifies type of hash
HashSpec_t hSpec = HSP_SHA256;

// autoClean option - for Merkle Tree
Boolean_t autoClean = FALSE;

// Hash Fusion accumulation type
HFuseAccum_t accumKind = LINEAR_LIST_ACCUM_HF;

static Byte_t **dataBlocks = NULL;

static ByteVec_t *tempBV = NULL;


/*******************************************************************************
  Key comparison predicate
*******************************************************************************/
Comparison_t keyCompFn(Key_t keyA, Key_t keyB) {
   return cmp_key(keyA, keyB);
}


/*******************************************************************************
  Adjacency comparison predicate
*******************************************************************************/
AdjData_t adjCompFn(Key_t keyA, Key_t keyB) {
   if (keyA == NULL_KEY) return ADJACENCY_UNDEF;
   if (keyB == NULL_KEY) return ADJACENCY_UNDEF;

   long vA = (long)keyA;
   long vB = (long)keyB;

   if (vA + 1 == vB) return LESS_THAN_ADJACENT;
   if (vA == vB + 1) return GREATER_THAN_ADJACENT;

   return (vA < vB ? LESS_THAN_NOT_ADJACENT : vA == vB ? ADJACENCY_EQUAL : GREATER_THAN_NOT_ADJACENT);
}


/*******************************************************************************
  Methods
*******************************************************************************/
void initialiseTestData() {
	// checking allocation ...
	checkAllocation_MM    = TRUE;
	checkDeallocation_MM  = TRUE;
   tempBV = allocate_BV(blockSize+1);
   dataBlocks = ALLOC_ARR(totalBlocks, Byte_t *);

   // allocate the destBlocksPerm array
   destBlocksPerm = ALLOC_ARR(totalBlocks, int);
}

void populateBlocks() {

   Byte_t *curBlock = NULL;
   for (int i = 0; i < totalBlocks; i++) {

      // allocate fresh block ...
      curBlock  = ALLOC_BLK(blockSize);
      dataBlocks[i] = curBlock;
      // fill curBlock with random data
      for (int j = 0; j < blockSize; j++) {
         curBlock[j] = nextRandom_BYTE();
      }
      // Load data block into bytevector
      importForeignContent_BV(tempBV, blockSize, curBlock);

      // reset temp bytevector
      reset_BV(tempBV);
   }
}

void randomiseDestOrder() {

   int swop = 0;
   int temp = 0;
   // insert default identity permutation ...
   for (int i = 0; i < totalBlocks; i++) {
   	destBlocksPerm[i] = i;
   }

   // randomly permute elements by swopping ...
   for (int i = 0; i < totalBlocks; i++) {
      swop = nextRandom_Range(0, totalBlocks-1);

      // swop element destBlocksPerm[i] with destBlocksPerm[swop]
   	temp = destBlocksPerm[i];
   	destBlocksPerm[i] = destBlocksPerm[swop];
   	destBlocksPerm[swop] = temp;
   }
}

/*******************************************************************************
  Calc Digests Methods
*******************************************************************************/

Digest_t  *calcDigest_FusionStruct(int *destPerm) {

   // New HFuse structure
   HFuse_t *hFuse = new_HF(keyCompFn, adjCompFn, accumKind, hSpec);

   Byte_t *curBlock = NULL;

   int posn = 0;

   for (int count = 0; count < totalBlocks; count++) {

      posn = (destPerm == NULL ? count : destPerm[count]);

      // Set the current block
      curBlock = dataBlocks[posn];

      // Load data block into bytevector
      reset_BV(tempBV);
      importForeignContent_BV(tempBV, blockSize, curBlock);

      // Add data to fusion struct
      if (!addDataBlock_HF(hFuse, posn+1, tempBV)) {
         diagnostic("calcDigest_FusionStruct : addDataBlock_HF FAILED! posn: %i", posn+1);
         error_exit();
      }
   }

   // Freshly allocated digest
   Digest_t *digest = new_DG(hSpec);

   // Check complete ...
   if (getState_HF(hFuse) == Complete_HFuseState) {

   	if (!getDigest_HF(digest, hFuse)) {
   	   diagnostic("calcDigest_FusionStruct : complete digest undefined for hFuse");
   	   codeError_exit();
   	}
   }
   else {
      diagnostic("calcDigest_FusionStruct: HashFusion structure state: %s\n  ... FAILED", showState_HF(hFuse));
      codeError_exit();
   }

   // Deallocate hFuse
   deallocate_HF(hFuse);

   return digest;
}


Digest_t *calcDigest_MerkleTree(int *destPerm) {

   // New Merkle Tree
   MTree_t *mTree = allocate_MT(hSpec, autoClean);

   Byte_t *curBlock = NULL;

   int posn = 0;

   for (int count = 0; count < totalBlocks; count++) {

      posn = (destPerm == NULL ? count : destPerm[count]);

      // Set the current block
      curBlock = dataBlocks[posn];

      // Load data block into bytevector
      reset_BV(tempBV);
      importForeignContent_BV(tempBV, blockSize, curBlock);

      // add data to tree
      addDataBlock_MT(mTree, posn+1, tempBV);
   }

   Digest_t *topHash = new_DG(hSpec);

   // Finalise ...
   if (finalise_MT(mTree)) {

   	if (!getTopHash_MT(topHash, mTree)) {
   	   diagnostic("calcDigest_MerkleTree : top hash digest undefined for mTree_src");
   	   codeError_exit();
   	}

   }
   else {
      diagnostic("calcDigest_MerkleTree: Merkle Tree structure state: %s\n  ... FAILED", showState_MT(mTree));
      codeError_exit();
   }

   // deallocate memory
   deallocate_MT(mTree);

   return topHash;
}
