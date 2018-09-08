/*******************************************************************************
  fragment.c

  Implements fragment classes and objects.

  These structures are transparently implemented - with open access/update.

  Uses opaque objects to encode generics ...
  
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
#include "fragment.h"

/*******************************************************************************
   Memory Management
*******************************************************************************/
static MemMgr_t *fragCls_MemMgr = NULL;
static MemMgr_t *fragObj_MemMgr = NULL;


/*******************************************************************************
   Static Method prototypes
*******************************************************************************/
// Memory management helper
static void ensureMemMgmt();

static FragCompare_t
   fragmentCompare(CompareFn_t posnCompFn,
                   Posn_t thisLower,
                   Posn_t thisUpper,
                   Posn_t otherLower,
                   Posn_t otherUpper);


/*******************************************************************************
   Fragment Class Methods
*******************************************************************************/
//
// Create a new fragment system class (FragCls_t)
// - This provides a coordinated set of related methods:
//
// - Parametric methods:
//     posnCompFn :  positionPos comparison function
//     adjCompFn  :  adjacency comparison function
//     objCombFn  :  object combination function
//     finalObjFn :  finalise object function
FragCls_t *new_FC(CompareFn_t posnCompFn, AdjCompareFn_t adjCompFn, CombineFn_t objCombFn, VoidFn_t finalObjFn) {

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // check integrity
   if (posnCompFn == NULL) {
      diagnostic("new_FC : Null position comparison function given");
      error_exit();
   }

   if (adjCompFn == NULL) {
      diagnostic("new_FC : Null adjacency comparison function given");
      error_exit();
   }

   if (objCombFn == NULL) {
      diagnostic("new_FC : Null object combination function given");
      error_exit();
   }

   // defaults
   finalObjFn = (finalObjFn == NULL ? nullVoidFn : finalObjFn);

   // allocate new class
   FragCls_t *newCls = allocateObject_MM(fragCls_MemMgr);

   // set attributes
   newCls->posnCompFn  =  posnCompFn;
   newCls->adjCompFn   =  adjCompFn;
   newCls->objCombFn   =  objCombFn;
   newCls->finalObjFn  =  finalObjFn;

   return newCls;
}


// Deallocate fragment class
void deallocate_FC(void *item) {
   if (item == NULL) return;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   FragCls_t *fragCls = (FragCls_t *)item;

   // Nullify object
   NULLIFY_OBJ(fragCls, FragCls_t)

   // recycle the current fragment object
   deallocateObject_MM(fragCls_MemMgr, sizeof(FragCls_t), fragCls);
}


// Clones object
FragCls_t *clone_FC(FragCls_t *fragCls) {
   return new_FC(fragCls->posnCompFn, fragCls->adjCompFn, fragCls->objCombFn, fragCls->finalObjFn);
}


/*******************************************************************************
   Fragment Object Methods
*******************************************************************************/
// Create a new fragment + value objects
// - note that fragCls should be non-null.
Frag_t *new_Frag(FragCls_t *fragCls, Posn_t lower, Posn_t upper, Object_t value) {
   req_NonNull(fragCls);

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // allocate new Tree
   Frag_t *newObj = allocateObject_MM(fragObj_MemMgr);

   // set attributes
   newObj->class  =  fragCls;
   newObj->lower  =  lower;
   newObj->upper  =  upper;
   newObj->value  =  value;

   return newObj;
}


// Deallocate fragment object
// - deallocate the frag object
void deallocate_Frag(void *item) {
   if (item == NULL) return;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // Cast to appropriate object
   Frag_t *fragObj = (Frag_t *)item;

   // nullify object
   NULLIFY_OBJ(fragObj, Frag_t);

   // recycle the current fragment object
   deallocateObject_MM(fragObj_MemMgr, sizeof(Frag_t), fragObj);
}


// Deallocate fragment object
// - deallocate the frag object (incl. the value)
void deallocateAll_Frag(void *item) {
   if (item == NULL) return;

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // Cast to appropriate object
   Frag_t *fragObj = (Frag_t *)item;

   VoidFn_t finalFn = fragObj->class->finalObjFn;

   // Call the finalisation/deallocation function for the object value.
   finalFn((void *)fragObj->value);

   // nullify object
   NULLIFY_OBJ(fragObj, Frag_t);

   // recycle the current fragment object
   deallocateObject_MM(fragObj_MemMgr, sizeof(Frag_t), fragObj);
}


// Fragment comparisons
FragCompare_t compare_Frag(Frag_t *thisFrag, Frag_t *otherFrag) {
   // check for nulls
   if (thisFrag == NULL) return FRAGMENT_UNDEF;
   if (otherFrag == NULL) return FRAGMENT_UNDEF;

   // check consistency of fragment class
   if (thisFrag->class != otherFrag->class) return FRAGMENT_UNDEF;

   CompareFn_t posnCompFn = thisFrag->class->posnCompFn;

   // Assume that: thisLower <= thisUpper
   Posn_t thisLower = thisFrag->lower;
   Posn_t thisUpper = thisFrag->upper;

   // Assume that: otherLower <= otherUpper
   Posn_t otherLower = otherFrag->lower;
   Posn_t otherUpper = otherFrag->upper;

   return fragmentCompare(posnCompFn, thisLower, thisUpper, otherLower, otherUpper);
}


FragCompare_t compareEnds_Frag(FragCls_t *fragCls, Posn_t thisLower, Posn_t thisUpper, Posn_t otherLower, Posn_t otherUpper) {
   req_NonNull(fragCls);

   req_NonZero(thisLower);
   req_NonZero(thisUpper);
   req_NonZero(otherLower);
   req_NonZero(otherUpper);

   CompareFn_t posnCompFn = fragCls->posnCompFn;

   return fragmentCompare(posnCompFn, thisLower, thisUpper, otherLower, otherUpper);
}


/*******************************************************************************
   Show fragment
*******************************************************************************/
static char showFragmentBuf[LINE_BUFSIZE+1];

// Showing fragments
char *show_Frag(void *item) {
   if (item == NULL) return NULL_STR;

   Frag_t *curFrag = (Frag_t *)item;

   sprintf(showFragmentBuf, "0x%lu = (lower: %i, upper: %i, value: 0x%lu)"
                          , (Ptr_t)curFrag
                          , (int)curFrag->lower
                          , (int)curFrag->upper
                          , (Object_t)curFrag->value
                          );

   return showFragmentBuf;
}


/*******************************************************************************
   Static Method prototypes
*******************************************************************************/
// ensure the allocation of memory management resources
static void ensureMemMgmt() {
   if (fragCls_MemMgr == NULL) {
      fragCls_MemMgr   =  new_MM(sizeof(FragCls_t));
      fragObj_MemMgr   =  new_MM(sizeof(Frag_t));
   }
}

// fragment comparison code ...
static FragCompare_t fragmentCompare(CompareFn_t posnCompFn,
                                   Posn_t thisLower,
                                   Posn_t thisUpper,
                                   Posn_t otherLower,
                                   Posn_t otherUpper) {
   if (posnCompFn(thisLower, otherLower) <= 0) {
      // thisLower <= otherLower

      if (posnCompFn(otherUpper, thisUpper) <= 0) {
         // thisLower <= otherLower <= otherUpper <= thisUpper
         return FRAGMENT_CONTAINS;
      }
      else {
         // thisUpper < otherUpper

         if (posnCompFn(thisUpper, otherLower) < 0) {
            // thisLower <= thisUpper < otherLower <= otherUpper
            return FRAGMENT_DISJOINT;
         }
         else {
            // thisLower <= otherLower <= thisUpper < otherUpper
            return FRAGMENT_OVERLAPS;
         }
      }
   }
   else {

      // otherLower < thisLower
      if (posnCompFn(thisUpper, otherUpper) <= 0) {
         // otherLower < thisLower <= thisUpper <= otherUpper
         return FRAGMENT_CONTAINED;
      }
      else {
         // otherUpper < thisUpper

         if (posnCompFn(otherUpper, thisLower) < 0) {
            // otherLower <= otherUpper < thisLower <= thisUpper
            return FRAGMENT_DISJOINT;
         }
         else {
            // otherLower < thisLower <= otherUpper < thisUpper
            return FRAGMENT_OVERLAPS;
         }
      }
   }
}
