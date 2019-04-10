/* hashFusion.c

   HashFusion Library

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

#include "utils.h"
#include "alloc.h"
#include "position.h"
#include "linkedList.h"
#include "stringbuffer.h"
#include "bytevector.h"
#include "matrix.h"
#include "fragment.h"
#include "fragmentMap.h"
#include "hashFusion.h"


////////////////////////////////////////////////////////////////////////////////
//  Hash Fusion types and structures
////////////////////////////////////////////////////////////////////////////////
struct hashFusion {
   CompareFn_t        posnCompFn;     // Position comparison function
   AdjCompareFn_t     adjCompFn;     // Adjacency comparison function
   HFuseAccum_t       accumType;     // Accumulation type

   HashSpec_t         hashSpec;      // Hash specifier
   int                dim;           // Dimension of matrices (dependant upon hashSpec)
   int                digestLen;     // Length of digest (dependant upon hashSpec)

   Digest_t          *digest;        // Final digest value -- weak reference (NO allocation)
   int                blockCount;    // Current total of blocks
   Key_t              maxPosition;   // Max position
   HFuseState_t       state;         // Current state
   FragMap_t         *fragments;     // Fragment map structure
};


////////////////////////////////////////////////////////////////////////////////
//  Memory management
////////////////////////////////////////////////////////////////////////////////
MemMgr_t *hashFusion_MemMgr = NULL;


////////////////////////////////////////////////////////////////////////////////
//  Static method prototypes
////////////////////////////////////////////////////////////////////////////////
static void ensureMemMgmt();

// Mapping from to FragMapKind_t
static FragMapKind_t toFragMapKind(HFuseAccum_t accumKind);

// Matrix combination utility
static Object_t matrixCombiner(Object_t a, Object_t b);

// Extract result
static Boolean_t tryExtractResult(HFuse_t *hFuse);

// Show utilities
static void initShowList(StringBuf_t *sBuf, ShowFn_t showFn);
static void showList(HFuse_t *hFuse);


////////////////////////////////////////////////////////////////////////////////
//  Methods
////////////////////////////////////////////////////////////////////////////////
// Allocate a new HashFusion object.
//
// Parameters:
//   CompareFn_t     posnCompFn     // Key comparison function
//   AdjCompareFn_t  adjCompFn     // Adjacency comparison function
//   HFuseAccum_t    hfAccumType   // HashFusion accumulation type (specifies method to accumulate)
//   HashSpec_t      hSpec         // Hash function specifier
HFuse_t *new_HF(CompareFn_t posnCompFn, AdjCompareFn_t adjCompFn, HFuseAccum_t hfAccumType, HashSpec_t hSpec) {
	// Ensure that the allocation structures exist
	ensureMemMgmt();

   HFuse_t *newHF = allocateObject_MM(hashFusion_MemMgr);

   FragCls_t *fragCls = new_FC(posnCompFn, adjCompFn, matrixCombiner, deallocateMatrix);


   FragMapKind_t fragKind = toFragMapKind(hfAccumType);

   int digestLen = getDigestLength_DG(hSpec);

   newHF->posnCompFn   =  posnCompFn;
   newHF->adjCompFn   =  adjCompFn;
	newHF->accumType   =  hfAccumType;
	newHF->hashSpec    =  hSpec;
	newHF->dim         =  calcDimension(digestLen); // calculate dimension
	newHF->digestLen   =  digestLen;
	newHF->digest      =  NULL;  // weak reference (NO allocation)
	newHF->blockCount  =  0;
	newHF->maxPosition =  0;
	newHF->state       =  Initial_HFuseState;
	newHF->fragments   =  new_FM(fragCls, fragKind);

	return newHF;
}


// Deallocate/recycle Hash Fusion object
void deallocate_HF(HFuse_t *hFuse) {

   if (hFuse == NULL) return;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // deallocate fragments
   deallocate_FM(hFuse->fragments);

   // nullify elements
   NULLIFY_OBJ(hFuse, HFuse_t);

   deallocateObject_MM(hashFusion_MemMgr, sizeof(HFuse_t), hFuse);
}


// Resets the given hash fusion object
// - Giving NULL parameters implies reuse of existing parameters.
void reset_HF(HFuse_t *hFuse, CompareFn_t posnCompFn, AdjCompareFn_t adjCompFn, HFuseAccum_t accumType, HashSpec_t hSpec) {
   req_NonNull(hFuse);

	// Ensure that the allocation structures exist
	ensureMemMgmt();

   // Set parameters
   posnCompFn = (posnCompFn == NULL    ? hFuse->posnCompFn : posnCompFn);
   adjCompFn  = (adjCompFn == NULL     ? hFuse->adjCompFn  : adjCompFn);
   accumType  = (accumType == ZERO_VAL ? hFuse->accumType  : accumType);
   hSpec      = (hSpec == ZERO_VAL     ? hFuse->hashSpec   : hSpec);

   // deallocate fragment map
   deallocate_FM(hFuse->fragments);

   FragCls_t *fragCls = new_FC(posnCompFn, adjCompFn, matrixCombiner, deallocateMatrix);

   FragMapKind_t fragKind = toFragMapKind(accumType);

   int digestLen = getDigestLength_DG(hSpec);

   hFuse->posnCompFn  =  posnCompFn;
   hFuse->adjCompFn   =  adjCompFn;
	hFuse->accumType   =  accumType;
	hFuse->hashSpec    =  hSpec;
	hFuse->dim         =  calcDimension(digestLen); // calculate dimension
	hFuse->digestLen   =  digestLen;
	hFuse->digest      =  NULL;  // weak ref.
	hFuse->blockCount  =  0;
	hFuse->maxPosition =  0;
	hFuse->state       =  Initial_HFuseState;
}

// Inspect current state ...
HFuseState_t getState_HF(HFuse_t *hFuse) {
   req_NonNull(hFuse);

   return hFuse->state;
}

// Show current state ...
char *showState_HF(HFuse_t *hFuse) {
   req_NonNull(hFuse);

   // process current state
   switch (hFuse->state) {
      case NULL_HFuseState:     return "NULL state";

      case Initial_HFuseState:  return "Initialised";
      case Partial_HFuseState:  return "Partial";
      case Complete_HFuseState: return "Complete";

      default:
         diagnostic("hashFusion.showState_HF : Unknown state: %i", hFuse->state);
         codeError_exit();
   }
}

// Gets current accumulation type
HFuseAccum_t getAccumType_HF(HFuse_t *hFuse) {
   req_NonNull(hFuse);

   return hFuse->accumType;
}


// Gets current Hash Spec
HashSpec_t getHashSpec_HF(HFuse_t *hFuse) {
   req_NonNull(hFuse);

   return hFuse->hashSpec;
}

// Gets Digest - if defined
// - This clones the mTree's digest object into given digest, dgst.
// - Returns TRUE only if digest was cloned.
Boolean_t getDigest_HF(Digest_t *dgst, HFuse_t *hFuse) {
   req_NonNull(dgst);
   req_NonNull(hFuse);

   if (hFuse->digest == NULL || hFuse->state != Complete_HFuseState) {
      return FALSE;
   }
   else {
      clone_DG(dgst, hFuse->digest);

      return TRUE;
   }
}

// Gets the total number of blocks so far.
int getNumBlocks_HF(HFuse_t *hFuse) {
   req_NonNull(hFuse);

   return hFuse->blockCount;
}

// Gets the number of fragments ...
int getNumFragments_HF(HFuse_t *hFuse) {
   req_NonNull(hFuse);

   return getSize_FM(hFuse->fragments);
}

// Show hash fragments info by appending to stringbuffer
// - uses specified show function showFn
// - set indent string
// - set compact display
// - set max length (if positive)
void show_HF(HFuse_t *hFuse, StringBuf_t *sBuf, ShowFn_t showFn) {
   req_NonNull(hFuse);
   req_NonNull(sBuf);

   showFn = (showFn == NULL ? show_Frag : showFn);

   initShowList(sBuf, showFn);
   showList(hFuse);
}

// show attributes
static char *show_indent = "   ";                // indent string
static Boolean_t show_compact_display = FALSE;
static int show_max_length = -1;

void setShowIndent_HF(char * indent) {
   show_indent = indent;
}

void setShowCompact_HF(Boolean_t isCompact) {
	show_compact_display = asBoolean(isCompact);
}

void setShowMaxLength_HF(int maxLength) {
	show_max_length = maxLength;
}


////////////////////////////////////////////////////////////////////////////////
//  Adding blocks, hashes and fragments
////////////////////////////////////////////////////////////////////////////////


// Calculate hash from data block
Boolean_t calcDataHash_HF(Digest_t *digest, Key_t position, ByteVec_t *dataVec) {
   req_NonNull(digest);
   req_NonNull(dataVec);
   req_Pos(position);    // Strictly positive keys ...

   // Hash the data and place it in digest
   return hashBV_DG(digest, dataVec);
}


// Adds data block into sequence
// - Position is 1-based and runs from 1 to max value K (with no gaps)
// - Returns TRUE if successful
Boolean_t addDataBlock_HF(HFuse_t *hFuse, Key_t position, ByteVec_t *dataVec) {

   req_NonNull(hFuse);
   req_NonNull(dataVec);
   req_Pos(position);    // Strictly positive keys ...

   // Allocate a temporary digest
   HashSpec_t hSpec = hFuse->hashSpec;
   int dim          = hFuse->dim;
   int digestLen    = hFuse->digestLen;

   Digest_t *tempDigest = new_DG(hSpec);

   // Hash the data and place it in digest
   if (!hashBV_DG(tempDigest, dataVec)) {
      deallocate_DG(tempDigest);
      return FALSE;
   }

   Boolean_t status = addDataHash_HF(hFuse, position, tempDigest);

   // deallocate temp. digest object
   deallocate_DG(tempDigest);
   return status;
}

// Adds data hash into sequence
// - Position is 1-based and runs from 1 to max value K (with no gaps)
// - Returns TRUE if successful
Boolean_t addDataHash_HF(HFuse_t *hFuse, Key_t position, Digest_t *digest) {
   return addDataRange_HF(hFuse, position, position, digest);
}

// Adds data hash for range into sequence
// - Position is 1-based and runs from 1 to max value K (with no gaps)
// - Returns TRUE if successful
Boolean_t addDataRange_HF(HFuse_t *hFuse, Key_t lower, Key_t upper, Digest_t *digest) {
   req_NonNull(hFuse);
   req_NonNull(digest);
   req_Pos(lower);    // Strictly positive keys ...
   req_Pos(upper);    // Strictly positive keys ...


   int dim          = hFuse->dim;         // dimension
   int digestLen    = hFuse->digestLen;   // digest length

   ByteVec_t *tempBV = allocate_BV(digestLen+1);

   // extract hash value into byte vector from the digest ...
   if (!getHashValue_DG(digest, tempBV)) {
      diagnostic("addDataRange_HF: Digest could not be extracted to bytevector");
      codeError_exit();
   }

   // Allocate fresh matrix of appropriate dimension
   Matrix_t *matrix = allocateTriMatrix(dim);

   // creating matrix version of hash digest value ...
   // - This automatically deals with any padding
   insertContent(matrix, tempBV);

   // deallocate the temporaries
   deallocate_BV(tempBV);

   if (lower == upper) {
      // Adding a single point ...
		if (!addPoint_FM(hFuse->fragments, lower, (Object_t)matrix)) {
		   return FALSE;
		}
   }
   else {
      // Adding range ...
		if (!addFragment_FM(hFuse->fragments, lower, upper, (Object_t)matrix)) {
		   return FALSE;
		}
   }
   // updating blockCount and maxPosition ...
   hFuse->blockCount  += 1;
   hFuse->maxPosition  = keyMax(hFuse->posnCompFn, upper, hFuse->maxPosition);

   hFuse->state  =  Partial_HFuseState;

   // try to extract result ...
   tryExtractResult(hFuse);

   return TRUE;
}


////////////////////////////////////////////////////////////////////////////////
// Show functions for enumerated functions:
////////////////////////////////////////////////////////////////////////////////
char *show_HFuseAccum(HFuseAccum_t val) {
   switch (val) {
      case DIRECT_ACCUM_HF:       return "DIRECT_ACCUM_HF";
      case LINEAR_LIST_ACCUM_HF:  return "LINEAR_LIST_ACCUM_HF";
      case TREE_SET_ACCUM_HF:     return "TREE_SET_ACCUM_HF";
      default:
         diagnostic("Unrecognised value (of type HFuseAccum_t): %i", val);
         error_exit();
   }
}

char *show_HFuseState(HFuseState_t val) {
   switch (val) {
      case NULL_HFuseState:      return "NULL_HFuseState";
      case Initial_HFuseState:   return "Initial_HFuseState";
      case Partial_HFuseState:   return "Partial_HFuseStateF";
      case Complete_HFuseState:  return "Complete_HFuseState";

      default:
         diagnostic("Unrecognised value (of type HFuseState_t): %i", val);
         error_exit();
   }
}


////////////////////////////////////////////////////////////////////////////////
// Static methods
////////////////////////////////////////////////////////////////////////////////
static void ensureMemMgmt() {
   if (hashFusion_MemMgr == NULL) {
      hashFusion_MemMgr  = new_MM(sizeof(HFuse_t));
   }
}


// Mapping from HFuseAccum_t to FragMapKind_t
static FragMapKind_t toFragMapKind(HFuseAccum_t accumKind) {
   switch (accumKind) {
      case DIRECT_ACCUM_HF:    return LINEAR_LIST_FRAG_MAP;
      case LINEAR_LIST_ACCUM_HF:  return LINEAR_LIST_FRAG_MAP;
      case TREE_SET_ACCUM_HF:     return BINARY_TREE_FRAG_MAP;

      default: return LINEAR_LIST_FRAG_MAP;
   }
}


// Matrix combination utility
static Object_t matrixCombiner(Object_t a, Object_t b) {
   Matrix_t *matA = (Matrix_t *)a;
   Matrix_t *matB = (Matrix_t *)b;

   int dim = getDimension(matA);
   Matrix_t *matC = allocateTriMatrix(dim);

   multiply(matC, matA, matB);
   return (Object_t)matC;
}


// Extract result
static Boolean_t tryExtractResult(HFuse_t *hFuse) {
   req_NonNull(hFuse);
   if (hFuse->maxPosition == hFuse->blockCount) {

      HashSpec_t hSpec = hFuse->hashSpec;
      FragMap_t *fragMap = hFuse->fragments;

      // Should now have only one element in the fragments list ...
      int curLength = getSize_FM(fragMap);
      if (curLength != 1) {
         diagnostic("hashFusion.addDataBlock_HF: Currently have %i fragments, should instead have only 1 when Complete", curLength);
         codeError_exit();
      }

      // Fetch the top fragment ...
      Frag_t *firstFrag  = getFirstFragment_FM(fragMap);

      Matrix_t *fragMatrix = (Matrix_t *)firstFrag->value;

      int digestSize = getDigestLength_DG(hSpec);

      ByteVec_t *tempBV = allocate_BV(1+digestSize);

      // extracting content into bytevector from matrix
      extractContent(tempBV, fragMatrix);
      setLength_BV(tempBV, digestSize);

      // allocate or reset the digest object.
      if (hFuse->digest == NULL) {
         hFuse->digest = new_DG(hSpec);
      }
      else {
         reset_DG(hFuse->digest, 0);
      }

      // transfer hash value to digest ...
      if (!setHashValue_DG(hFuse->digest, tempBV)) {
         diagnostic("hashFusion.addDataBlock_HF: The operation setHashValue_DG failed for digest");
         codeError_exit();
      }

      // set state to Complete
      hFuse->state  =  Complete_HFuseState;

      // finally deallocate temporary bytevector
      deallocate_BV(tempBV);

      return TRUE;
   }
   else {
      // hard reset of digest ...
      deallocate_DG(hFuse->digest);
      hFuse->digest = NULL;

      return FALSE;
   }
}


/*******************************************************************************
   Showing Hash Fusion fragments
*******************************************************************************/
static StringBuf_t *curSBuf = NULL;
static ShowFn_t curShowFn = NULL;

static void initShowList(StringBuf_t *sBuf, ShowFn_t showFn) {
   req_NonNull(sBuf);

   curSBuf   = sBuf;
   curShowFn = showFn;
}


static void showList(HFuse_t *hFuse) {
   req_NonNull(hFuse);

   int numFragments = getNumFragments_HF(hFuse);

   addItems_SB(curSBuf, "%sHFuse <state:%s, fragments:%i, blockCount:%i, maxPosition:%i, digest:%s>\n"
                      , show_indent
                      , showState_HF(hFuse)
                      , numFragments
                      , hFuse->blockCount
                      , hFuse->maxPosition
                      , showFingerprint_DG(hFuse->digest, 8)
                      );

   if (show_compact_display || numFragments == 0) return;

   // Show fragments

   addItems_SB(curSBuf, "\n%sFragments (%i):\n", show_indent, numFragments);

   int count = 0;

   FragMap_t *fragMap = hFuse->fragments;
   Frag_t *curFrag = start_EnumMap_FM(fragMap);
   while (curFrag != NULL) {
      addItems_SB(curSBuf, "%s  %i: %s\n",  show_indent, count+1, curShowFn(curFrag));

      curFrag = next_EnumMap_FM(fragMap);
      count += 1;

      if (count > 100) {
         diagnostic("showList: count exceeded limit %i, Seems to be a loop ...", count);
         error_exit();
      }
   }
   addItems_SB(curSBuf, "%sEnd.\n", show_indent);

   // check that the actual number of fragments (count) and the calculated number of fragments (numFragments) agree ...
   if (count != numFragments) {
      print_SB(curSBuf);
      diagnostic("showList : NumFragments = %i, actual num. fragments = %i", numFragments, count);
      error_exit();
   }
   //stop_EnumMap_FM(fragMap);
}
