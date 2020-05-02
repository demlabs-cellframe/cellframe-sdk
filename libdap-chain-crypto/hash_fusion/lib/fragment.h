#ifndef __FRAGMENT_H__
#define __FRAGMENT_H__

/*******************************************************************************
   fragment.h

   Fragment classes and objects

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


/*******************************************************************************
   Classes and Types
*******************************************************************************/

// Fragment Objects
typedef struct fragmentObj Frag_t;

// Fragment System Class
// - specifies comparisons
typedef struct fragmentClass FragCls_t;

// Type of value combiners
typedef Object_t (*CombineFn_t) (Object_t objA, Object_t objB);

// Type of adjacency comparison outcomes (AdjData_t)
// - let acf(pa, pb) = ov, where acf is an adjacency comparison function.
//   Then: ov is one of these outcome values, as specified below:
typedef enum {
      ADJACENCY_UNDEF,            // outcome not defined
		LESS_THAN_NOT_ADJACENT,     // pa < pb  and  pa is not adjacent to pb
		LESS_THAN_ADJACENT,         // pa < pb  and  pa is adjacent to pb
		ADJACENCY_EQUAL,            // pa == pb
		GREATER_THAN_ADJACENT,      // pa > pb  and  pa is adjacent to pb
		GREATER_THAN_NOT_ADJACENT   // pa > pb  and  pa is not adjacent to pb
   }
   AdjData_t;

// Type of adjacency comparison functions
typedef AdjData_t (*AdjCompareFn_t) (Posn_t pa, Posn_t pb);

// Fragment comparisons ...  (subsumption of fragments)
typedef enum {
		FRAGMENT_UNDEF,      // Undefined/unspecified outcome
		FRAGMENT_CONTAINED,  // specified fragment is contained in other fragment
		FRAGMENT_CONTAINS,   // specified fragment contains other fragment
		FRAGMENT_OVERLAPS,   // specified fragment overlaps with other fragment
		FRAGMENT_DISJOINT    // specified fragment is disjoint from other fragment
   }
   FragCompare_t;


/*******************************************************************************
   Structural definitions for fragmentClass and fragmentObj
   - transparent definitions
   - allows open access and update for these shared objects
*******************************************************************************/
struct fragmentClass {
   CompareFn_t     posnCompFn;  // position comparison function
   AdjCompareFn_t  adjCompFn;   // adjacency comparison functio
   CombineFn_t     objCombFn;   // object combination function
   VoidFn_t        finalObjFn;  // finalise object function
};

struct fragmentObj {
   FragCls_t *class;
   Posn_t     lower;
   Posn_t     upper;
   Object_t   value;
};


/*******************************************************************************
   Fragment Class Methods
*******************************************************************************/
//
// Create a new fragment class (FragCls_t)
// - This provides a coordinated set of related methods:
//
// - Parametric methods:
//     posnCompFn :  position comparison function
//     adjCompFn  :  adjacency comparison function
//     objCombFn  :  object combination function
//     finalObjFn :  finalise object function
FragCls_t *new_FC(CompareFn_t posnCompFn, AdjCompareFn_t adjCompFn, CombineFn_t objCombFn, VoidFn_t finalObjFn);


// Deallocate fragment class
void deallocate_FC(void *item);


// Clones object
FragCls_t *clone_FC(FragCls_t *fragCls);


/*******************************************************************************
   Fragment Object Methods
*******************************************************************************/
// Create new fragment object (Frag_t)
// - Note: explicit fragment class pointer links to data specific operations.
Frag_t *new_Frag(FragCls_t *fragCls, Posn_t lower, Posn_t upper, Object_t value);

// Deallocate fragment object
void deallocate_Frag(void *item);       // deallocate the frag object itself
void deallocateAll_Frag(void *item);    // deallocate the frag object (incl. the value)

// Fragment comparisons ...
FragCompare_t compare_Frag(Frag_t *thisFrag, Frag_t *otherFrag);
FragCompare_t compareEnds_Frag(FragCls_t *fragCls, Posn_t thisLower, Posn_t thisUpper, Posn_t otherLower, Posn_t otherUpper);

// Showing fragments
char *show_Frag(void *item);

#endif
