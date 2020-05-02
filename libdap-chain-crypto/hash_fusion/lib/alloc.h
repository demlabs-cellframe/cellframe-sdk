#ifndef __ALLOC_H__
#define __ALLOC_H__

#include "utils.h"


/*******************************************************************************
  alloc.h

  Very basic memory management (using free-lists)

  The implementation can be switched to provide a straightforward malloc/free
  version (see USE_MALLOC_AND_FREE)

  
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
//#define USE_MALLOC_AND_FREE

// Allocation structure structure
typedef struct memMgr MemMgr_t;


/*******************************************************************************
  Methods
*******************************************************************************/

// creates a fresh allocation structure ...
MemMgr_t *new_MM(size_t blockSize);


// sets the object initialiser
void setInitialiser_MM(MemMgr_t *fLst, VoidFn_t initFn);


// sets the object finaliser
void setFinaliser_MM(MemMgr_t *fLst, VoidFn_t finalFn);


// get size of allocation structure
int getLength_MM(MemMgr_t *fLst);


// get number of allocated objects
int getAllocated_MM(MemMgr_t *fLst);


// get blockSize i.e. the size of memory to allocate
size_t getBlockSize_MM(MemMgr_t *fLst);


// allocates an object (from allocation structure if possible)
void *allocateObject_MM(MemMgr_t *fLst);

// deallocates object
// - the objSize parameter is used to check that the object is being returned
//   to the right memory pool.
void deallocateObject_MM(MemMgr_t *fLst, size_t objSize, void *obj);

// Resets an allocation manager
// - disposes of allocation structure objects if the newBlockSize is different from current blocksize.
// - finaliser is run on all allocation structures elements.
void reset_MM(MemMgr_t *fLst, size_t newBlockSize);


// recycles a allocation structure ...
void recycle_MM(MemMgr_t *fLst);


/*******************************************************************************
  Checking integrity
*******************************************************************************/

// Apply check on allocation
// - This check applies to all free-lists
Boolean_t checkAllocation_MM;

// Apply check on deallocation
// - This check applies to all free-lists
Boolean_t checkDeallocation_MM;

// Check allocation/deallocation integrity
// - checks if the given object is currently recycled ...
// - this is a hard error if so ...
Boolean_t checkIfRecycled_MM(MemMgr_t *fLst, void *obj);

#endif
