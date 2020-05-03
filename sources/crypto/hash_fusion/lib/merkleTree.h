#ifndef __MERKLE_TREE_H__
#define __MERKLE_TREE_H__

/*******************************************************************************
   merkleTree.h

   Merkle Tree
   - Standard Peer-2-Peer hashing of a sequence of blocks
   - Handles building of data sequence in random order ...
   - Merkle, R. C. (1988). "A Digital Signature Based on a Conventional Encryption Function".
     Advances in Cryptology — CRYPTO '87. Lecture Notes in Computer Science 293. p. 369

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
#include "hashlib.h"

// Sequential blocks
typedef struct merkleTree MTree_t;

// Merkle Tree state
// - Merkle tree operations cycle: init->partial->complete->final
typedef int MTreeState_t;

// Merkle Tree state
// - a complete sequence means there are no missing blocks (i.e. no gaps between 0 and current max position).
// - even if we have a complete sequence, there could still be more input.
#define MTree_NULL       0   // Not a valid state (i.e. uninitialised)
#define MTree_Initial    1   // Initial state (empty sequence)
#define MTree_Partial    2   // Partial state (partial sequence) - in progress/under construction
#define MTree_Complete   3   // Complete state (completed initial sequence, but there could be more input ...)
#define MTree_Final      4   // Final state (completed sequence, and no more blocks to be added)

// The default auto clean option
// - If set autoClean TRUE, deallocate tree nodes as soon as possible.
Boolean_t autoCleanDefault;

// New Merkle Tree
// - initialises the tree object
// - Auto clean is set to the default as defined by autoCleanDefault.
MTree_t *new_MT(HashSpec_t hSpec);

// Allocates Merkle Tree
// - initialises the tree object
// - The autoClean setting can be defined.
MTree_t *allocate_MT(HashSpec_t hSpec, Boolean_t autoClean);

// Deallocate/recycle Merkle Tree object
void deallocate_MT(MTree_t *mTree);

// Resets the given hash tree
// - The existing autoClean state from mTree is reused.
void reset_MT(MTree_t *mTree, HashSpec_t hSpec);

// Inspect current state ...
MTreeState_t getState_MT(MTree_t *mTree);

// Show current state ...
char *showState_MT(MTree_t *mTree);

// Gets current Hash Spec
HashSpec_t getHashSpec_MT(MTree_t *mTree);

// Gets Top Hash - if defined
// - This clones the mTree's digest object into given digest, dgst.
// - Returns TRUE only if digest was cloned.
Boolean_t getTopHash_MT(Digest_t *dgst, MTree_t *mTree);

// Gets the total number of blocks so far.
int getNumBlocks_MT(MTree_t *mTree);

// Gets the total number of tree nodes (i.e. internal nodes and leaves).
int getTotalNodes_MT(MTree_t *mTree);

// Gets the auto clean flag.
// - if TRUE, deallocate tree nodes as soon as possible.
Boolean_t getAutoClean_MT(MTree_t *mTree);

// Gets the height of the hash tree ...
int getHeight_MT(MTree_t *mTree);

// Show hash tree by appending to stringbuffer
// - set indent string
// - set incrment indent string
// - set compact display
// - set max depth (if positive)
void show_MT(MTree_t *mTree, StringBuf_t *sbuf);
void setShowIndent_MT(char * indent);
void setShowIncrIndent_MT(char * indent);
void setShowCompact_MT(Boolean_t isCompact);
void setShowMaxDepth_MT(int maxDepth);

// Adds data block into sequence
// - position is 1-based i.e. from 1 to N
void addDataBlock_MT(MTree_t *mTree, int position, ByteVec_t *dataVec);

// Finalise the tree (if possible)
// - Returns true if successfully finalised, otherwise false.
Boolean_t finalise_MT(MTree_t *mTree);

// Maximum indent length
#define  MAX_INDENT_LENGTH    20

// Maximum Tree Height ...
#define MAX_TREE_HEIGHT   32

#endif
