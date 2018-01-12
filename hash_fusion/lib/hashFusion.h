#ifndef __HASHFUSION_H__
#define __HASHFUSION_H__

/*******************************************************************************
   hashFusion.h

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
*******************************************************************************/

#include "utils.h"
#include "bytevector.h"
#include "stringbuffer.h"
#include "fragment.h"
#include "hashlib.h"


/*******************************************************************************
   Hash Fusion object type
   - This corresponds to a Merkle Hash Tree
*******************************************************************************/
typedef struct hashFusion HFuse_t;


/*******************************************************************************
   Hash Fusion Accumulation Type

   + Provides implmentation to accumulate hash objects in sequence.

   + Types of accumulation structure:

     - Free Form: Accumulate hashes directly in sequence.  Effectively combines hashes
       as given with no gaps.

     - Linear List: Builds a linear list of fragments.  Useful for small numbers of
       blocks.

     - Balanced Binary Tree:  Builds a self-balancing tree structure (with O(lg N)
       access and insert behaviour).  This is a scalable solution suitable for
       large files.

*******************************************************************************/
typedef enum {
     DIRECT_ACCUM_HF = 100,  // Direct accumulation structure (i.e. only accumulate directly at either end).
     LINEAR_LIST_ACCUM_HF,      // Linear list accumulation structure
     TREE_SET_ACCUM_HF          // Balanced binary tree accumulation structure
   }
   HFuseAccum_t;


/*******************************************************************************
   Hash Fusion state
*******************************************************************************/
// Hash Fusion state values
// - a complete sequence means there are no missing blocks (i.e. no gaps between 0 and current max position).
// - even if we have a complete sequence, there could still be more input.
//
// Operations cycle: init->partial <-> complete
typedef enum {
		NULL_HFuseState = 10,   // Not a valid state (i.e. uninitialised)
		Initial_HFuseState,     // Initial state (empty sequence)
		Partial_HFuseState,     // Partial state (partial sequence) - in progress/under construction
		Complete_HFuseState     // Complete state (completed initial sequence, but there could be more input ...)
   }
   HFuseState_t;


/*******************************************************************************
   Methods
*******************************************************************************/
// Allocate a new HashFusion object.
// Parameters:
//   CompareFn_t     keyCompFn     // Key comparison function
//   AdjCompareFn_t  adjCompFn     // Adjacency comparison function
//   HFuseAccum_t    hfAccumType   // HashFusion accumulation type (specifies method to accumulate)
//   HashSpec_t      hSpec         // Hash function specifier
HFuse_t *new_HF(CompareFn_t keyCompFn, AdjCompareFn_t adjCompFn, HFuseAccum_t hfAccumType, HashSpec_t hSpec);

// Deallocate/recycle HashFusion object
void deallocate_HF(HFuse_t *hFuse);

// Resets the given HashFusion object
// - Giving NULL parameters implies reuse of existing parameters.
void reset_HF(HFuse_t *hFuse, CompareFn_t keyCompFn, AdjCompareFn_t adjCompFn, HFuseAccum_t hfAccumType, HashSpec_t hSpec);

// Inspect current state ...
HFuseState_t getState_HF(HFuse_t *hFuse);

// Show current state ...
char *showState_HF(HFuse_t *hFuse);

// Gets current accumulation type
HFuseAccum_t getAccumType_HF(HFuse_t *hFuse);

// Gets current Hash Spec
HashSpec_t getHashSpec_HF(HFuse_t *hFuse);

// Gets Digest - if defined
// - This clones the digest object into given digest, dgst.
// - Returns TRUE only if digest was cloned.
Boolean_t getDigest_HF(Digest_t *dgst, HFuse_t *hFuse);

// Gets the total number of blocks so far.
int getNumBlocks_HF(HFuse_t *hFuse);

// Gets the number of fragments ...
int getNumFragments_HF(HFuse_t *hFuse);

////////////////////////////////////////////////////////////////////////////////
// Hash joining ...
////////////////////////////////////////////////////////////////////////////////

// Calculate hash from data block
Boolean_t calcDataHash_HF(Digest_t *digest, Key_t position, ByteVec_t *dataVec);

// Adds data block into sequence
// - Position is 1-based and runs from 1 to max value K (with no gaps)
// - Returns TRUE if successful
Boolean_t addDataBlock_HF(HFuse_t *hFuse, Key_t position, ByteVec_t *dataVec);

// Adds data hash into sequence
// - Position is 1-based and runs from 1 to max value K (with no gaps)
// - Returns TRUE if successful
Boolean_t addDataHash_HF(HFuse_t *hFuse, Key_t position, Digest_t *digest);

// Adds data hash for range into sequence
// - Position is 1-based and runs from 1 to max value K (with no gaps)
// - Returns TRUE if successful
Boolean_t addDataRange_HF(HFuse_t *hFuse, Key_t lower, Key_t upper, Digest_t *digest);


////////////////////////////////////////////////////////////////////////////////
// Show functions
////////////////////////////////////////////////////////////////////////////////
// Show hash fragments info by appending to stringbuffer
// - uses specified show function showFn
// - set indent string
// - set compact display
// - set max length (if positive)
void show_HF(HFuse_t *hFuse, StringBuf_t *sbuf, ShowFn_t showFn);
void setShowIndent_HF(char * indent);
void setShowCompact_HF(Boolean_t isCompact);
void setShowMaxLength_HF(int maxLength);

// Show functions for enumerated functions:
char *show_HFuseAccum(HFuseAccum_t val);
char *show_HFuseState(HFuseState_t val);

#endif
