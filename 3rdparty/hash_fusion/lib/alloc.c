/*******************************************************************************
   alloc.c

   Very simple free-list based storage management

   The implementation can be switched to a straightforward malloc/free
   version (see USE_MALLOC_AND_FREE).

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "alloc.h"

typedef struct pair Pair_t;

struct memMgr {
   size_t blockSize;       // allocation size

   VoidFn_t initFn;        // object initialiser function
   VoidFn_t finalFn;       // object finaliser function

   int allocated;          // objects allocated
   int length;             // current length of allocation structure

   Pair_t *freeList;       // allocation structure
};

struct pair {
   void *object;           // object pointer
   Pair_t *nextItem;       // next item
};


// Global old cells list
// - Allows old pairs to be reused ...
static Pair_t *oldPairsList;

// Global allocation structure for free-lists (!)
// - allows free-lists themselves to be allocated and deallocated.
static MemMgr_t *freeList_List = NULL;


// Static Method prototypes
static void ensureMemMgmt(void *obj);
static void dispose_MemMgr_Entries(MemMgr_t *fLst);


////////////////////////////////////////////////////////////////////////////////
// Methods
////////////////////////////////////////////////////////////////////////////////

// creates a newly allocated allocation structure ...
MemMgr_t *new_MM(size_t blockSize) {
   req_Pos(blockSize);

   // bootstrap allocation of allocation structures
   if (freeList_List == NULL) {
      // create freeList_List
      freeList_List = ALLOC_OBJ(MemMgr_t);              // Allocate MemMgr_t object

      ensureMemMgmt(freeList_List);                     // Initialise freeList_List
      freeList_List->blockSize = sizeof(MemMgr_t);      // set blockSize for MemMgr_t objects

      setInitialiser_MM(freeList_List, ensureMemMgmt);  // set initialier for MemMgr_t objects
   }

   // Allocate allocation structure ...
   MemMgr_t *newList  = allocateObject_MM(freeList_List);
   newList->blockSize = blockSize;

   return newList;
}


// sets the object initialiser
// - this is run on all allocated objects ...
//   either freshly created or reallocated.
void setInitialiser_MM(MemMgr_t *fLst, VoidFn_t initFn) {
   req_NonNull(fLst);

   fLst->initFn = initFn;
}


// sets the object finaliser
// - this is run when allocation structures are disposed of.
void setFinaliser_MM(MemMgr_t *fLst, VoidFn_t finalFn) {
   req_NonNull(fLst);

   fLst->finalFn = finalFn;
}

// get length of allocation structure
int getLength_MM(MemMgr_t *fLst) {
   req_NonNull(fLst);

   return fLst->length;
}


// get blockSize
size_t getBlockSize_MM(MemMgr_t *fLst) {
   req_NonNull(fLst);

   return fLst->blockSize;
}


// get number of allocated objects
int getAllocated_MM(MemMgr_t *fLst) {
   req_NonNull(fLst);
   return fLst->allocated;
}


// Resets a allocation structure
// - disposes of allocation structure objects if the newBlockSize is different from current blocksize.
// - finaliser is run on all allocation structures elements.
void reset_MM(MemMgr_t *fLst, size_t newBlockSize) {
   req_NonNull(fLst);
   req_Pos(newBlockSize);

   // check if block size has changed ...
   if (newBlockSize == fLst->blockSize) {
      // no change needed to fLst object
      return;
   }

   // clears the current objects on allocation structure
   dispose_MemMgr_Entries(fLst);

   // initialise allocation structure - as though it were freshly allocated
   ensureMemMgmt(fLst);

   // sets the blocksize
   fLst->blockSize = newBlockSize;
}


// recycles a allocation structure ...
void recycle_MM(MemMgr_t *obj) {
   MemMgr_t *fLst = (MemMgr_t *)obj;

   // dispose of the allocation structure entries
   // - this will activate the object finalisers ...
   dispose_MemMgr_Entries(fLst);

   // recycle the MemMgr_t object on the freeList_List
   deallocateObject_MM(freeList_List, sizeof(MemMgr_t), fLst);
}


/*******************************************************************************
  Checking integrity
*******************************************************************************/

// Apply check on allocation
// - This check applies to all free-lists
Boolean_t checkAllocation_MM = FALSE;

// Apply check on deallocation
// - This check applies to all free-lists
Boolean_t checkDeallocation_MM = FALSE;

// Check allocation/deallocation integrity
// - checks if the given object is currently recycled ...
// - this is a hard error if so ...
Boolean_t checkIfRecycled_MM(MemMgr_t *fLst, void *obj) {
   req_NonNull(fLst);

   Pair_t *nextPair = fLst->freeList;

   while (nextPair != NULL) {
      if (nextPair->object == obj) {
         return TRUE;
      }
      nextPair = nextPair->nextItem;
   }

   return FALSE;
}


/*******************************************************************************
  Static Methods
*******************************************************************************/
static void ensureMemMgmt(void *obj) {
   MemMgr_t *fLst = (MemMgr_t *)obj;

   //fLst->blockSize
   fLst->initFn    = NULL;
   fLst->finalFn   = NULL;
   fLst->allocated = 0;
   fLst->length    = 0;
   fLst->freeList  = NULL;
}


static void dispose_MemMgr_Entries(MemMgr_t *fLst) {
   req_NonNull(fLst);

   Pair_t* cells = fLst->freeList;  // ensures that we only act upon an allocation structure ...

   if (cells == NULL) {
      // Nothing to do ...
      return;
   }

   VoidFn_t finalFn =
      (fLst->finalFn == NULL ? free : fLst->finalFn);

   Pair_t *curPair = cells;
   Pair_t *prevPair = NULL;

   // move all cells to oldPairsList and reset any objects
   while (curPair != NULL) {
      // Make prevPair equal to the curPair.
      prevPair = curPair;

      // Set curPair to the next cell pointed at by prevPair
      curPair = prevPair->nextItem;

      // Finalise the object (if any) pointed at by prevPair;
      finalFn(prevPair->object);
      prevPair->object = NULL;

      // Add prevPair to oldPairsList
      prevPair->nextItem = oldPairsList;
      oldPairsList = prevPair;
   }
}


////////////////////////////////////////////////////////////////////////////////
// Allocation and Deallocation Methods
////////////////////////////////////////////////////////////////////////////////

#ifdef USE_MALLOC_AND_FREE


   /////////////////////////////////////////////////////////////////////////////
   // Straightforward allocation using malloc/free
   /////////////////////////////////////////////////////////////////////////////

	// Allocates an object
	// - runs the object initialiser function (if non-null).
	void *allocateObject_MM(MemMgr_t *fLst) {
		req_NonNull(fLst);

		// allocates fresh object memory
		// - guaranteed to be zeroed (IMPORTANT!!)
		void *resultObj = ALLOC_BLK(fLst->blockSize);

		fLst->allocated += 1;

		// run the object initialiser ... if initialiser function is non-null
		if (fLst->initFn != NULL) {
		   fLst->initFn(resultObj);
		}

		return resultObj;
	}

	// Deallocates object by adding it to the allocation structure
	// - the object is NOT finalised here ... only when allocation structures are disposed of/recycled.
	// - the objSize parameter provides a simple check that the object is being returned
	//   to the correct memory pool.
	void deallocateObject_MM(MemMgr_t *fLst, size_t objSize, void *obj) {
		if (obj == NULL) return;

		req_NonNull(fLst);
		req_EQ(objSize, fLst->blockSize);  // heuristic integrity check that sizes are correct (not perfect)

		free(obj);
	}


#else


   /////////////////////////////////////////////////////////////////////////////
   // Allocation using allocation structures
   /////////////////////////////////////////////////////////////////////////////

	// Allocates an object (from allocation structure when possible)
	// - runs the object initialiser function (if non-null).
	void *allocateObject_MM(MemMgr_t *fLst) {
		req_NonNull(fLst);

		void *resultObj = NULL;

		Pair_t *freePairs = fLst->freeList;

		if (freePairs == NULL) {
		   // allocates fresh object memory
		   // - guaranteed to be zeroed (IMPORTANT!!)
		   resultObj = ALLOC_BLK(fLst->blockSize);

		   fLst->allocated += 1;
		}
		else {

		   needs_Pos("length of allocation structure is not > 0", fLst->length);

		   // take the top free cell from free cells
		   Pair_t *topPair = freePairs;

		   // extract object from top cell..
		   resultObj = topPair->object;

		   // Ensure that the top cell releases object
		   topPair->object = NULL;

		   // update allocation structure entry (i.e. remove topPair from allocation structure)
		   fLst->freeList = topPair->nextItem;

		   // reduce length of allocation structure
		   fLst->length -= 1;

		   // make topPair point at the current old cells list
		   topPair->nextItem = oldPairsList;

		   // move top cell to the top of old cells list
		   oldPairsList = topPair;
		}

		// run the object initialiser ... if initialiser function is non-null
		if (fLst->initFn != NULL) {
		   fLst->initFn(resultObj);
		}

		// check that allocated object is *not* curently deallocated ...
		if (checkAllocation_MM) {
		   if (checkIfRecycled_MM(fLst, resultObj)) {
		      diagnostic("allocateObject_MM: Allocated object is currently deallocated: MemMgmt: 0x%lu, Object: 0x%lu"
		                , (Ptr_t)fLst
		                , (Ptr_t)resultObj
		                );
		      error_exit();
		   }
		}

		return resultObj;
	}


	// Deallocates object by adding it to the allocation structure
	// - the object is NOT finalised here ... only when allocation structures are
	//   disposed of/recycled.
	// - the object may contain info such as associated memory pointers/sizes to
	//   be retained for reuse e.g. bytevectors.
	// - the objSize parameter provides a heuristic check that the right kind of
	//   object is being returned into the correct memory pool.
	void deallocateObject_MM(MemMgr_t *fLst, size_t objSize, void *obj) {
		if (obj == NULL) return;

		req_NonNull(fLst);
		req_EQ(objSize, fLst->blockSize);  // heuristic integrity check that sizes are correct (not perfect)


		// check that object is *not* already deallocated ...
		if (checkDeallocation_MM) {
		   if (checkIfRecycled_MM(fLst, obj)) {
		      diagnostic("deallocateObject_MM: Attempted double deallocation of object: MemMgmt: 0x%lu, Object: 0x%lu"
		                , (Ptr_t)fLst
		                , (Ptr_t)obj
		                );
		      error_exit();
		   }
		}

		Pair_t *freePairs = fLst->freeList;

		Pair_t *topPair = NULL;

		// ensure topPair exists ...
		if (oldPairsList != NULL) {
		   // found existing pair
		   // take top pair from oldPairsList
		   topPair = oldPairsList;

		   // make old pairs the next cell of top cell
		   oldPairsList = topPair->nextItem;
		}
		else {
		   // allocate fresh cell to top cell
		   topPair = ALLOC_OBJ(Pair_t);
		}

		// Bind obj to topPair
		topPair->object = obj;

		// make top cell link to free cells
		topPair->nextItem = freePairs;

		// make allocation structure point at top cell
		fLst->freeList = topPair;

		// increment length of allocation structure
		fLst->length += 1;
	}

#endif
