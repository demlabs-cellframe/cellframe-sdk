#ifndef __ARENA_H__
#define __ARENA_H__

#include "utils.h"


/*******************************************************************************
  arena.h

  Arena-based memory management

  An arena is a block of memory divided into a series of fixed-size blocks.

  Each block can have a reference count.   Allocation is cheap.

  Memory is never physically deallocated - it means that it is unreserved.
  This means that the memory is available for reallocation to an owner
  for some use/purpose.  The use of deallocated/unallocated memory is considered
  erroneous until that memory is reallocated.

  The implementation can be switched to provide a straightforward malloc/free
  version (see USE_MALLOC_AND_FREE_ARENA)
  
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

// Uncomment the following line to use straightforward malloc/free allocation:
//#define USE_MALLOC_AND_FREE_ARENA

// Arena Memory Manager
typedef struct arenaObj ArenaMemMgr_t;

// Arena Allocation Policy
typedef enum {
    REFERENCE_BLOCKS_POLICY_AMM,   // blocks are objects - use reference counting.
    TEMPORARY_BLOCKS_POLICY_AMM,   // blocks represented temporary memory - ignore reference counting.
    PERMANENT_BLOCKS_POLICY_AMM    // blocks are permanent and are never recycled/deallocated - ignores reference counting.
} ArenaPolicy_t;

// Allocates a new arena with blockSize, numBlocks and policy:
// - blockSize : size of block (i.e. allocation unit)
// - numBlocks : total number of blocks to be allocated.
// - policy    : allocation policy to be used by arena.
ArenaMemMgr_t *new_AMM(int blockSize, int numBlocks, ArenaPolicy_t policy);

// Deallocate the specified arena
// - This returns TRUE if deallocation was successful
// - If there are blocks still allocated, then deallocation of the arena
//   will not succeed.
Boolean_t deallocateArena_AMM(ArenaMemMgr_t *arena);

// Allocates the next block of memory ...
void *allocateBlock_AMM(ArenaMemMgr_t *arena);

// Deallocates the given block of memory
// - Decrements the reference count (if this is meaningful)
void deallocateBlock_AMM(ArenaMemMgr_t *arena, void *block);

// Get the arena allocation policy for arena
ArenaPolicy_t getPolicy_AMM(ArenaMemMgr_t *arena);

// Get the size of blocks allocated by arena
int getBlockSize_AMM(ArenaMemMgr_t *arena);

// Total number of blocks for arena: total = free + allocated
int getTotalBlocks_AMM(ArenaMemMgr_t *arena);

// Number of blocks free for allocation by arena
int getFreeBlocks_AMM(ArenaMemMgr_t *arena);

// Number of allocated blocks by arena
int getAllocatedBlocks_AMM(ArenaMemMgr_t *arena);

// Increment reference to block (if possible)
// - This fails if the block was not allocated within the arena.
//
void incrRefCount_AMM(ArenaMemMgr_t *arena, void *block);

#endif
