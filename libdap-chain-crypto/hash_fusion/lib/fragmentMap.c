/*******************************************************************************
  fragmentMap.c

  Provides fragment maps e.g. a map from a set of closed fragments to a space of
  values. In essence, we have each map M with functional typing: SetOf(Fragments)->Value
  so that:

         M = { intv |-> v  |  intv in S }

  The domain of the map is a set of closed fragments, based upon some finite
  discrete linearly ordered set of points (e.g. subset of the integers, finite
  subset of strings).

  A closed fragment of points is characterised by a pair [lower, upper] which
  characterises the range defined by:  { x | lower <= x <= upper }

  Note that when upper = lower, then [lower, upper] is the singleton set {x}
  where x = lower = upper.

  We want to also merge adjacent fragments and therefore combine map values
  for _adjacent_ fragments.  If VCF is the value combiner operation, then:

     { ... [a, b] |-> v1,  [b', c] |=> v2 ... }   (where b and b' are adjacent)

     Becomes:

     { ... [a,c] |-> (v1 VCF v2) ... }

  (PS: This is an example of "multiset rewriting reduction")

  Two fragments are _adjacent_ iff:

      A.upper + 1 = B.lower  OR  B.upper + 1 = A.lower

  We can always merge two adjacent fragments to make a larger fragment.

       [3, 7] \/ [8, 10]  =
       [3, 5] \/ [6, 10]  =  [3, 10]

  An fragment map M is said to be _reduced_ when the domain of M is a set of
  disjoint, non-adjacent closed fragments.

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
#include "rbTree.h"
#include "linkedList.h"
#include "fragment.h"
#include "fragmentMap.h"

/*******************************************************************************
   Classes and Types
*******************************************************************************/

// Fragment Maps - FragMap_t
struct fragmentMap {
   FragCls_t      *class;     // Class info. determining comparison structures etc.

   FragMapKind_t   fragKind;  // This value determines the structural type of the data
   Object_t        data;      // Opaque data structure pointer ...

   Posn_t          current;
   Boolean_t       locked;
};


/*******************************************************************************
   Memory Management
   - Opaque data objects have specific memory allocation defined elsewhere.
*******************************************************************************/
static MemMgr_t *fragMap_MemMgr = NULL;


/*******************************************************************************
   Static Method prototypes
*******************************************************************************/
// Memory management helper
static void ensureMemMgmt();

// Allocate data object
static Object_t allocateDataObject(FragCls_t *fragCls, FragMapKind_t fragKind);

// Deallocate data object
static void deallocateDataObject(FragMapKind_t fragKind, Object_t data);

// Code to compare existing fragments in the fragment map with the proposed fragment
// - several outcomes possible
static FragCompare_t checkDisjointFragment(FragMap_t *fragMap, Posn_t lower, Posn_t upper);

// Remove all fragments from the data contained in the proposed fragments
static void clearCoveredFragments(FragMap_t *fragMap, Posn_t lower, Posn_t upper);

// Generic data object methods
static int getSize_MapObj(FragMap_t *fragMap);

static Frag_t *getFirstFragment_MapObj(FragMap_t *fragMap);

static Posn_t minPosn_MapObj(FragMap_t *fragMap);
static Posn_t maxPosn_MapObj(FragMap_t *fragMap);

static Posn_t nextPosn_MapObj(FragMap_t *fragMap, Posn_t point, Boolean_t allowEQ);
static Posn_t priorPosn_MapObj(FragMap_t *fragMap, Posn_t point, Boolean_t allowEQ);

static Frag_t *lookup_MapObj(FragMap_t *fragMap, Posn_t point);
static Frag_t *delete_MapObj(FragMap_t *fragMap, Posn_t point);
static Frag_t *insert_MapObj(FragMap_t *fragMap, Posn_t point, Frag_t *newFrag);

// Single Fragment methods
static Boolean_t addPoint_SingleFrag(FragMap_t *fragMap, Posn_t point, Object_t value);
static Boolean_t addFragment_SingleFrag(FragMap_t *fragMap, Posn_t lower, Posn_t upper, Object_t value);

static Posn_t minPosn_SingleFrag(Frag_t *frag);
static Posn_t maxPosn_SingleFrag(Frag_t *frag);

static Posn_t nextPosn_SingleFrag(CompareFn_t posnCompFn, Frag_t *frag, Posn_t point, Boolean_t allowEQ);
static Posn_t priorPosn_SingleFrag(CompareFn_t posnCompFn, Frag_t *frag, Posn_t point, Boolean_t allowEQ);

static Frag_t *lookup_SingleFrag(CompareFn_t posnCompFn, Frag_t *frag, Posn_t point);


// Ordered List object methods
static Posn_t minPosn_OrdList(LinkList_t *fragSeq);
static Posn_t maxPosn_OrdList(LinkList_t *fragSeq);

static Posn_t nextPosn_OrdList(CompareFn_t posnCompFn, LinkList_t *fragSeq, Posn_t point, Boolean_t allowEQ);
static Posn_t priorPosn_OrdList(CompareFn_t posnCompFn, LinkList_t *fragSeq, Posn_t point, Boolean_t allowEQ);

static Frag_t *lookup_OrdList(CompareFn_t posnCompFn, LinkList_t *fragSeq, Posn_t point);

static Frag_t *delete_OrdList(FragCls_t *fragCls, LinkList_t *fragSeq, Posn_t point);

static Frag_t *insert_OrdList(FragCls_t *fragCls, LinkList_t *fragSeq, Posn_t point, Frag_t *newFrag);


/*******************************************************************************
   Fragment Map Methods
*******************************************************************************/
// Create a new fragment map (FragMap_t)
// - Assume that the FragCls_t object is never shared (i.e. always fresh and can be dealocated).
FragMap_t *new_FM(FragCls_t *fragCls, FragMapKind_t fragKind) {
   req_NonNull(fragCls);

   // ensure that the allocation structures exist ...
   ensureMemMgmt();

   // allocate new Tree
   FragMap_t *newMap = allocateObject_MM(fragMap_MemMgr);

   // set attributes
   newMap->class     =  fragCls;
   newMap->fragKind  =  fragKind;
   newMap->data      =  allocateDataObject(fragCls, fragKind);

   newMap->current   =  NULL_POSN;
   newMap->locked    =  FALSE;

   return newMap;
}


// Deallocate fragment map
void deallocate_FM(void *item) {
   if (item == NULL) return;

   FragMap_t *fragMap = (FragMap_t *)item;

   // Deallocate the frag class
   // - This assumes that the object is never shared ...
   deallocate_FC(fragMap->class);

   // Deallocate the data object ...
   deallocateDataObject(fragMap->fragKind, fragMap->data);

   // Nullify map object
   NULLIFY_OBJ(fragMap, FragMap_t);

   // recycle the current map object
   deallocateObject_MM(fragMap_MemMgr, sizeof(FragMap_t), fragMap);
}


// Add a point mapping to given fragment map
// - Adds the point to the mapping and then reduces the domain set
//   by combining with adjacent fragments in the mapping.
// - Returns TRUE if addition was successful, FALSE otherwise.
Boolean_t addPoint_FM(FragMap_t *fragMap, Posn_t point, Object_t value) {
   req_NonNull(fragMap);

   // Check if map is locked
   if (fragMap->locked) return FALSE;

   // Check if point is already within the data
   if (lookupFragment_FM(fragMap, point) != NULL) return FALSE;

   // Handle fragment kind == NULL_FRAG_MAP
   if (fragMap->fragKind == NULL_FRAG_MAP) {
      return addPoint_SingleFrag(fragMap, point, value);
   }

   FragCls_t *sysClass = fragMap->class;
   AdjCompareFn_t adjCompFn = sysClass->adjCompFn;
   CombineFn_t    objCombFn = sysClass->objCombFn;

   // Records current fragment containing the new point ...
   // - This will be inserted at the end.
   Frag_t *curFragment = NULL;

   // Current point at which curFragment is inserted into mapping
   // - This is always equal to: curFragment->lower
   Posn_t bindPoint = NULL_POSN;

   // Get next point
   // - this works even though point is _NOT_ already in the data ...
   Posn_t nextLowerPoint  =  nextPosn_MapObj(fragMap, point, FALSE);

   if (adjCompFn(point, nextLowerPoint) == LESS_THAN_ADJACENT) {
      // Combine the next item ...
      Frag_t *nextFrag    = lookup_MapObj(fragMap, nextLowerPoint);
      Object_t nextValue  = nextFrag->value;

      // Unbind the entry for nextFrag in fragMap
      delete_MapObj(fragMap, nextLowerPoint);

      // Calculate new value
      Object_t newValue   = objCombFn(value, nextValue);

      // Update the nextFrag object
      nextFrag->lower = point;
      nextFrag->value = newValue;

      // Assign the current fragment to be nextFrag (!= NULL)
      curFragment = nextFrag;
      bindPoint = point;
   }

   Posn_t priorLowerPoint  = priorPosn_MapObj(fragMap, point, FALSE);

   Frag_t *priorFrag      = lookup_MapObj(fragMap, priorLowerPoint);

   Posn_t priorUpperPoint  = (priorFrag == NULL ? NULL_POSN : priorFrag->upper);

   if (adjCompFn(priorUpperPoint, point) == LESS_THAN_ADJACENT) {
      Object_t priorValue  = priorFrag->value;
      Object_t nextValue   = value;
      Posn_t newUpperPoint  = point;

      // combine with curFragment if not specified
      if (curFragment != NULL) {
         newUpperPoint = curFragment->upper;
         nextValue     = curFragment->value;

         // Preserve value ...
         curFragment->value = ZERO_VAL;

         // Deallocate current fragment
         deallocate_Frag(curFragment);
      }

      // Unbind the entry for priorFrag in fragMap
      delete_MapObj(fragMap, priorLowerPoint);

      // Get new value for extended fragment
      Object_t newValue = objCombFn(priorValue, nextValue);

      // Update the prior fragment object
      priorFrag->upper = newUpperPoint;
      priorFrag->value = newValue;

      // Set the current fragment containing the point ...
      curFragment = priorFrag;
      bindPoint = priorLowerPoint;
   }

   if (curFragment == NULL) {
      // insert point as a singleton ...
      curFragment = new_Frag(sysClass, point, point, value);
      bindPoint = point;
   }
   insert_MapObj(fragMap, bindPoint, curFragment);

   return TRUE;
}


// Add a consistent fragment to given fragment map
// - Adds the fragment to the mapping and then reduces the domain set
//   by combining with adjacent fragments in the mapping.
// - Returns TRUE if addition was successful, FALSE otherwise.
Boolean_t addFragment_FM(FragMap_t *fragMap, Posn_t lower, Posn_t upper, Object_t value) {
   req_NonNull(fragMap);

   // Check if map is locked
   if (fragMap->locked) return FALSE;

   FragCls_t *fragCls = fragMap->class;

   // Check if endpoints are already within the data
   switch (checkDisjointFragment(fragMap, lower, upper)) {
      // Add the new fragment
      case FRAGMENT_DISJOINT:
         break;

      // Nothing to do.  The proposed fragment already exists or is contained
      // by some other fragment.
      case FRAGMENT_CONTAINED:
         return TRUE;

      // Clear out fragments covered by proposed fragment
      // and then add the new fragment
      case FRAGMENT_CONTAINS:
         clearCoveredFragments(fragMap, lower, upper);
         break;

      // Failure detected.
      default:
         return FALSE;
   }

   // Handle fragment kind == NULL_FRAG_MAP
   if (fragMap->fragKind == NULL_FRAG_MAP) {
      return addFragment_SingleFrag(fragMap, lower, upper, value);
   }

   FragCls_t *sysClass = fragMap->class;
   AdjCompareFn_t adjCompFn   = sysClass->adjCompFn;
   CombineFn_t    objCombFn = sysClass->objCombFn;

   // Records current fragment containing the proposed fragment ...
   Frag_t *curFragment = NULL;

   // Current point at which curFragment is inserted into mapping
   // - This is always equal to: curFragment->lower
   Posn_t bindPoint = NULL_POSN;

   // Get next point
   // - this works even though upper is _NOT_ already in the data ...
   Posn_t nextLowerPoint  =  nextPosn_MapObj(fragMap, upper, FALSE);

   if (adjCompFn(upper, nextLowerPoint) == LESS_THAN_ADJACENT) {
      // Combine the next item ...
      Frag_t *nextFrag    = lookup_MapObj(fragMap, nextLowerPoint);
      Object_t nextValue  = nextFrag->value;

      // Unbind the entry for nextFrag in fragMap
      delete_MapObj(fragMap, nextLowerPoint);

      Object_t newValue   = objCombFn(value, nextValue);

      // Update the nextFrag object
      nextFrag->lower = lower;
      nextFrag->value = newValue;

      // Assign the current fragment to be nextFrag (!= NULL)
      curFragment = nextFrag;
      bindPoint = lower;
   }

   // Get prior upper point
   Posn_t priorLowerPoint  = priorPosn_MapObj(fragMap, lower, FALSE);
   Frag_t *priorFrag      = lookup_MapObj(fragMap, priorLowerPoint);
   Posn_t priorUpperPoint  = (priorFrag == NULL ? NULL_POSN : priorFrag->upper);

   if (adjCompFn(priorUpperPoint, lower) == LESS_THAN_ADJACENT) {
      Object_t priorValue  = priorFrag->value;
      Object_t nextValue   = value;
      Posn_t newUpperPoint  = upper;

      // combine with curFragment if not specified
      if (curFragment != NULL) {
         newUpperPoint = curFragment->upper;
         nextValue     = curFragment->value;

         // Preserve value ...
         curFragment->value = ZERO_VAL;

         // Deallocate the fragment
         deallocate_Frag(curFragment);
      }

      // Unbind the entry for priorFrag in fragMap
      delete_MapObj(fragMap, priorLowerPoint);

      // Get new value for extended fragment
      Object_t newValue = objCombFn(priorValue, nextValue);

      // Update the prior fragment object
      priorFrag->upper = newUpperPoint;
      priorFrag->value = newValue;

      // Set the current fragment containing the point ...
      curFragment = priorFrag;
      bindPoint = priorLowerPoint;
   }

   if (curFragment == NULL) {
      // insert point as a singleton ...
      curFragment = new_Frag(sysClass, lower, upper, value);
      bindPoint = lower;
   }
   insert_MapObj(fragMap, bindPoint, curFragment);

   return TRUE;
}


// Lookup covering fragment for a given point.
// - This determines the fragment that covers the given point, and returns it.
// - Returns NULL if not found
Frag_t *lookupFragment_FM(FragMap_t *fragMap, Posn_t point) {
   req_NonNull(fragMap);

   if (point == NULL_POSN) return NULL;

   CompareFn_t posnCompFn = fragMap->class->posnCompFn;

   // look for any prior point (including equality).
   Posn_t priorLowerPoint = priorPosn_MapObj(fragMap, point, TRUE);

   // check priorLowerPoint for NULL_POSN
   if (priorLowerPoint == NULL_POSN) return NULL;


   Frag_t *priorFrag = lookup_MapObj(fragMap, priorLowerPoint);
   req_NonNull(priorFrag);  // priorFrag should be non-NULL

   Posn_t priorUpperPoint = priorFrag->upper;
   req_NonZero(priorUpperPoint);  // priorUpperPoint should be non-zero

   // check if priorFrag **doesn't** cover the point ...
   if (posnCompFn(point, priorUpperPoint) > 0) return NULL;
   return priorFrag;
}


// Size of fragment map - i.e. number of disjoint fragments
int getSize_FM(FragMap_t *fragMap) {
  req_NonNull(fragMap);

  return getSize_MapObj(fragMap);
}


// Get the first fragment
// - Returns NULL if empty
Frag_t *getFirstFragment_FM(FragMap_t *fragMap){
  req_NonNull(fragMap);

  return getFirstFragment_MapObj(fragMap);
}


// Enumerate fragment point mappings
// - Checks if map is locked (i.e. being enumerated).
// - Enumerates fragment objects in order.
// - Returns NULL, when completed.
// - Changes are locked out during enumeration.
Boolean_t isLocked_FM(FragMap_t *fragMap) {
   req_NonNull(fragMap);

   if (fragMap->current == NULL_POSN) {
      fragMap->locked = FALSE;
   }

   return fragMap->locked;
}

Frag_t *start_EnumMap_FM(FragMap_t *fragMap) {
   req_NonNull(fragMap);
   if (fragMap->locked) return NULL;

   Posn_t initPosn = minPosn_MapObj(fragMap);

   // checks position is valid ...
   if (initPosn == NULL_POSN) {
      fragMap->locked = FALSE;
      return NULL;
   }

   fragMap->current = initPosn;
   fragMap->locked = TRUE;

   // return value
   return (Frag_t *)lookup_MapObj(fragMap, initPosn);
}

Frag_t *next_EnumMap_FM(FragMap_t *fragMap) {
   req_NonNull(fragMap);

   if (!fragMap->locked) return NULL;

   if (fragMap->current == NULL_POSN) {
      fragMap->locked = FALSE;
      return NULL;
   }

   // set current position
   Posn_t curPosn = nextPosn_MapObj(fragMap, fragMap->current, FALSE);
   Frag_t *curVal = (Frag_t *)lookup_MapObj(fragMap, curPosn);
   fragMap->current = curPosn;

   if (curPosn == NULL_POSN || curVal == NULL) {
      fragMap->locked = FALSE;
      return NULL;
   }

   // return value
   return curVal;
}

void stop_EnumMap_FM(FragMap_t *fragMap) {
   req_NonNull(fragMap);

   fragMap->current = NULL_POSN;
   fragMap->locked  = FALSE;
}


/*******************************************************************************
   Static methods
*******************************************************************************/
// ensure the allocation of memory management resources
static void ensureMemMgmt() {
   if (fragMap_MemMgr == NULL) {
      fragMap_MemMgr  =  new_MM(sizeof(FragMap_t));
   }
}


// Allocate data object
// - no object deallocation functions are set ...
static Object_t allocateDataObject(FragCls_t *fragCls, FragMapKind_t fragKind) {
   RBTree_t *newTree = NULL;

   switch (fragKind) {
      case NULL_FRAG_MAP:
         return (Object_t)NULL;  // Actual object allocated when fragment added.

      case LINEAR_LIST_FRAG_MAP:
         return (Object_t)new_LL();

      case BINARY_TREE_FRAG_MAP:
         newTree = new_RBT(fragCls->posnCompFn);
         setAllowUpdates_RBT(newTree, TRUE);
         setAllowNullKey_RBT(newTree, FALSE);
         return (Object_t)newTree;

      default:
         diagnostic("allocateDataObject: Bad value for fragment kind %i", fragKind);
         error_exit();
   }
}

// Deallocate data object
// - the associated fragments should here be deallocated.
static void deallocateDataObject(FragMapKind_t fragKind, Object_t data) {
   switch(fragKind) {
      case NULL_FRAG_MAP:
         deallocate_Frag((Frag_t *)data);
         return;

      case LINEAR_LIST_FRAG_MAP:
         deallocateWithFinaliser_LL((LinkList_t *)data, deallocate_Frag);
         return;

      case BINARY_TREE_FRAG_MAP:
         deallocateWithFinaliser_RBT((RBTree_t *)data, deallocate_Frag);
         return;

      default:
         diagnostic("deallocateDataObject: Bad value for fragment kind %i", fragKind);
         error_exit();
   }
}


// Code to compare existing fragments in the fragment map with the proposed fragment
// - several outcomes possible
static FragCompare_t checkDisjointFragment(FragMap_t *fragMap, Posn_t lower, Posn_t upper) {
   req_NonNull(fragMap);
   req_NonNull(fragMap->class);

   if (lower == NULL_POSN) return FRAGMENT_UNDEF;
   if (upper == NULL_POSN) return FRAGMENT_UNDEF;

   CompareFn_t posnCompFn = fragMap->class->posnCompFn;

   // check for the proposed fragment, lower <= upper
   if (posnCompFn(upper, lower) < 0) return FRAGMENT_UNDEF;

   // Find fragments in data covering each endpoint
   Frag_t *startFrag  = lookupFragment_FM(fragMap, lower);
   Frag_t *endFrag    = lookupFragment_FM(fragMap, upper);

   // Check if endpoints miss the fragments
   if (startFrag == NULL && endFrag == NULL) {
      // Neither startFrag or endFrag fragment is defined
      // However, the proposed fragment could contain fragments from the data.

      Posn_t nextPoint = nextPosn_MapObj(fragMap, lower, FALSE);

      if (nextPoint == NULL_POSN || posnCompFn(upper, nextPoint) < 0) {
         // Either nextPoint does not exist OR upper < nextPoint
         // This means the proposed fragment is disjoint with fragments in the map.
         return FRAGMENT_DISJOINT;
      }

      // lower < nextPoint < upper
      return FRAGMENT_CONTAINS;
   }

   // At least one of startFrag or endFrag is non-NULL ...
   if (startFrag != endFrag) {
      // This means that the two fragments are distinct and cannot both be NULL.
      // Therefore, at least one fragment contains one of lower or upper.
      // This means either startFrag or endFrag overlaps with the proposed fragment.
      return FRAGMENT_OVERLAPS;
   }

   // Now have that startFrag == endFrag
   Posn_t upperStartFrag = startFrag->upper;

   if (posnCompFn(upper, upperStartFrag) <= 0) {
      return FRAGMENT_CONTAINED;
   }

   return FRAGMENT_UNDEF;
}


// Remove all fragments from the data contained in the proposed fragments
static void clearCoveredFragments(FragMap_t *fragMap, Posn_t lower, Posn_t upper) {
   req_NonNull(fragMap);
   req_NonNull(fragMap->class);

   if (lower == NULL_POSN || upper == NULL_POSN) return;

   CompareFn_t posnCompFn = fragMap->class->posnCompFn;

   Posn_t curPosn  = nextPosn_MapObj(fragMap, lower, FALSE);

   while (curPosn != NULL_POSN && posnCompFn(curPosn, upper) <= 0) {
      delete_MapObj(fragMap, curPosn);
      curPosn  = nextPosn_MapObj(fragMap, curPosn, FALSE);
   }
}


/*******************************************************************************
   Generic data object methods
*******************************************************************************/
static Frag_t *insert_MapObj(FragMap_t *fragMap, Posn_t point, Frag_t *newFrag) {
   req_NonNull(fragMap);
   req_NonNull(fragMap->class);

   switch(fragMap->fragKind) {
      case LINEAR_LIST_FRAG_MAP:
         return insert_OrdList(fragMap->class, (LinkList_t *)fragMap->data, point, newFrag);

      case BINARY_TREE_FRAG_MAP:
         return insert_RBT((RBTree_t *)fragMap->data, (Key_t)point, newFrag);

      default:
         diagnostic("insert_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}

static Frag_t *delete_MapObj(FragMap_t *fragMap, Posn_t point) {
   req_NonNull(fragMap);

   switch(fragMap->fragKind) {
      case LINEAR_LIST_FRAG_MAP:
         return delete_OrdList(fragMap->class, (LinkList_t *)fragMap->data, point);

      case BINARY_TREE_FRAG_MAP:
         return delete_RBT((RBTree_t *)fragMap->data, (Key_t)point);

      default:
         diagnostic("delete_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}

static int getSize_MapObj(FragMap_t *fragMap) {
   req_NonNull(fragMap);

   switch(fragMap->fragKind) {
      case NULL_FRAG_MAP:
         return ((Frag_t *)fragMap->data == NULL ? 0 : 1);

      case LINEAR_LIST_FRAG_MAP:
         return getLength_LL((LinkList_t *)fragMap->data);

      case BINARY_TREE_FRAG_MAP:
         return getSize_RBT((RBTree_t *)fragMap->data);

      default:
         diagnostic("getSize_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}

static Frag_t *getFirstFragment_MapObj(FragMap_t *fragMap) {
   req_NonNull(fragMap);

   switch(fragMap->fragKind) {
      case NULL_FRAG_MAP:
         return (Frag_t *)fragMap->data;

      case LINEAR_LIST_FRAG_MAP:
         return getTopObject_LL((LinkList_t *)fragMap->data);

      case BINARY_TREE_FRAG_MAP:
         return getFirstElement_RBT((RBTree_t *)fragMap->data);

      default:
         diagnostic("getSize_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}

static Posn_t minPosn_MapObj(FragMap_t *fragMap)  {
   req_NonNull(fragMap);

   switch(fragMap->fragKind) {
      case NULL_FRAG_MAP:
         return minPosn_SingleFrag((Frag_t *)fragMap->data);

      case LINEAR_LIST_FRAG_MAP:
         return minPosn_OrdList((LinkList_t *)fragMap->data);

      case BINARY_TREE_FRAG_MAP:
         return (Posn_t)minKey_RBT((RBTree_t *)fragMap->data);

      default:
         diagnostic("minPosn_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}

static Posn_t maxPosn_MapObj(FragMap_t *fragMap)  {
   req_NonNull(fragMap);

   switch(fragMap->fragKind) {
      case NULL_FRAG_MAP:
         return maxPosn_SingleFrag((Frag_t *)fragMap->data);

      case LINEAR_LIST_FRAG_MAP:
         return maxPosn_OrdList((LinkList_t *)fragMap->data);

      case BINARY_TREE_FRAG_MAP:
         return (Posn_t)maxKey_RBT((RBTree_t *)fragMap->data);

      default:
         diagnostic("maxPosn_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}


static Posn_t nextPosn_MapObj(FragMap_t *fragMap, Posn_t point, Boolean_t allowEQ)  {
   req_NonNull(fragMap);
   req_NonNull(fragMap->class);

   switch(fragMap->fragKind) {
      case NULL_FRAG_MAP:
         return nextPosn_SingleFrag(fragMap->class->posnCompFn, (Frag_t *)fragMap->data, point, allowEQ);

      case LINEAR_LIST_FRAG_MAP:
         return nextPosn_OrdList(fragMap->class->posnCompFn, (LinkList_t *)fragMap->data, point, allowEQ);

      case BINARY_TREE_FRAG_MAP:
         return (Posn_t)nextKey_RBT((RBTree_t *)fragMap->data, (Key_t)point, allowEQ);

      default:
         diagnostic("nextPosn_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}

static Posn_t priorPosn_MapObj(FragMap_t *fragMap, Posn_t point, Boolean_t allowEQ)  {
   req_NonNull(fragMap);

   switch(fragMap->fragKind) {
      case NULL_FRAG_MAP:
         return priorPosn_SingleFrag(fragMap->class->posnCompFn, (Frag_t *)fragMap->data, point, allowEQ);

      case LINEAR_LIST_FRAG_MAP:
         return priorPosn_OrdList(fragMap->class->posnCompFn, (LinkList_t *)fragMap->data, point, allowEQ);

      case BINARY_TREE_FRAG_MAP:
         return (Posn_t)priorKey_RBT((RBTree_t *)fragMap->data, (Key_t)point, allowEQ);

      default:
         diagnostic("priorPosn_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}

static Frag_t *lookup_MapObj(FragMap_t *fragMap, Posn_t point) {
   req_NonNull(fragMap);

   if (point == NULL_POSN) return NULL;

   switch(fragMap->fragKind) {
      case NULL_FRAG_MAP:
         return lookup_SingleFrag(fragMap->class->posnCompFn, (Frag_t *)fragMap->data, point);

      case LINEAR_LIST_FRAG_MAP:
         return lookup_OrdList(fragMap->class->posnCompFn, (LinkList_t *)fragMap->data, point);

      case BINARY_TREE_FRAG_MAP:
         return lookup_RBT((RBTree_t *)fragMap->data, (Key_t)point);

      default:
         diagnostic("getAllowUpdates_MapObj: Bad value for fragment kind %i", fragMap->fragKind);
         error_exit();
   }
}


/*******************************************************************************
   Single Fragment Methods
   - Fragment map consists of a single fragment ...
*******************************************************************************/
static Boolean_t addPoint_SingleFrag(FragMap_t *fragMap, Posn_t point, Object_t value) {
   req_NonNull(fragMap);

   FragCls_t *sysClass = fragMap->class;
   AdjCompareFn_t adjCompFn   = sysClass->adjCompFn;
   CombineFn_t    objCombFn = sysClass->objCombFn;

   // get current fragment
   Frag_t *curFrag = (Frag_t *)fragMap->data;

   if (curFrag == NULL) {
      // Create new fragment ...
      curFrag = new_Frag(fragMap->class, point, point, value);

      // update data component ...
      fragMap->data = (Object_t)curFrag;

      return TRUE;
   }
   else {
       if (adjCompFn(curFrag->upper, point) == LESS_THAN_ADJACENT) {
          // Updating curFrag with new combined value ...
          curFrag->value = objCombFn(curFrag->value, value);

          // Updating upper range of curFrag
          curFrag->upper = point;

          return TRUE;
       }
       else if (adjCompFn(point, curFrag->lower) == LESS_THAN_ADJACENT) {
          // Updating curFrag with new combined value ...
          curFrag->value = objCombFn(value, curFrag->value);

          // Updating lower range of curFrag
          curFrag->lower = point;

          return TRUE;
       }
       else {
          return FALSE;
       }
    }
}


static Boolean_t addFragment_SingleFrag(FragMap_t *fragMap, Posn_t lower, Posn_t upper, Object_t value) {
   req_NonNull(fragMap);

   FragCls_t *sysClass = fragMap->class;
   AdjCompareFn_t adjCompFn   = sysClass->adjCompFn;
   CombineFn_t    objCombFn = sysClass->objCombFn;

   // get current fragment
   Frag_t *curFrag = (Frag_t *)fragMap->data;

   if (curFrag == NULL) {
      // Create new fragment ...
      curFrag = new_Frag(fragMap->class, lower, upper, value);

      // update data component ...
      fragMap->data = (Object_t)curFrag;

      return TRUE;
   }
   else {
       if (adjCompFn(curFrag->upper, lower) == LESS_THAN_ADJACENT) {
          // Updating curFrag with new combined value ...
          curFrag->value = objCombFn(curFrag->value, value);

          // Updating upper range of curFrag
          curFrag->upper = upper;

          return TRUE;
       }
       else if (adjCompFn(upper, curFrag->lower) == LESS_THAN_ADJACENT) {
          // Updating curFrag with new combined value ...
          curFrag->value = objCombFn(value, curFrag->value);

          // Updating lower range of curFrag
          curFrag->lower = lower;

          return TRUE;
       }
       else {
          return FALSE;
       }
    }
}

static Posn_t minPosn_SingleFrag(Frag_t *frag) {
   if (frag == NULL) return NULL_POSN;

   return frag->lower;
}

static Posn_t maxPosn_SingleFrag(Frag_t *frag) {
   if (frag == NULL) return NULL_POSN;

   return frag->upper;
}

static Posn_t nextPosn_SingleFrag(CompareFn_t posnCompFn, Frag_t *frag, Posn_t point, Boolean_t allowEQ) {
   req_NonNull(frag);

   Posn_t lower = frag->lower;

   int indication = posnCompFn(point, lower);

   if (indication < 0) return lower;
   if (indication == 0 && allowEQ) return lower;

   return NULL_POSN;
}

static Posn_t priorPosn_SingleFrag(CompareFn_t posnCompFn, Frag_t *frag, Posn_t point, Boolean_t allowEQ) {
   req_NonNull(frag);

   Posn_t lower = frag->lower;

   int indication = posnCompFn(lower, point);

   if (indication < 0) return lower;
   if (indication == 0 && allowEQ) return lower;

   return NULL_POSN;
}

static Frag_t *lookup_SingleFrag(CompareFn_t posnCompFn, Frag_t *frag, Posn_t point) {
   if (point == NULL_POSN) return NULL;

   return (posnCompFn(point, frag->lower) == 0 ? frag : NULL);
}


/*******************************************************************************
   Ordered List Methods
   - Fragment map is list-based
*******************************************************************************/
static Frag_t *insert_OrdList(FragCls_t *fragCls, LinkList_t *fragSeq, Posn_t point, Frag_t *newFrag) {
   req_NonNull(fragSeq);


   CompareFn_t posnCompFn  =  fragCls->posnCompFn;
   VoidFn_t    finalObjFn  =  fragCls->finalObjFn;

   // No NULL_POSNs are allowed.
   if (point == NULL_POSN) return NULL;

   ListNode_t *prevNode = NULL;
   ListNode_t *curNode  = getTopNode_LL(fragSeq);

   ListNode_t *newNode  = NULL;   // node to be added ...
   ListNode_t *nextNode = NULL;   // successor to new node

   Frag_t *curFrag = NULL;
   Posn_t curPosn  = NULL_POSN;

   int indication = 0;
   while (curNode != NULL) {
      curFrag  =  (Frag_t *)getNodeObject_LL(curNode);
      curPosn   =  curFrag->lower;

      indication = posnCompFn(curPosn, point);
      if (indication == 0) {
         // Update the found node with new frag ...
         setNodeObject_LL(curNode, newFrag);

         finalObjFn(curFrag);
         return curFrag;
      }
      else if (indication > 0) {
         // Make new node with new frag ...
         newNode = newNodeObject_LL(newFrag, NULL);

         if (prevNode == NULL) {
            // Insert as head of list
            nextNode = getTopNode_LL(fragSeq);
            setTopNode_LL(fragSeq, newNode);
         }
         else {
            nextNode = curNode;
            setNextNode_LL(prevNode, newNode);
         }

         // Splice new node into list betwen prevNode and curNode
         setNextNode_LL(newNode, nextNode);

         // update the list
         incrLength_LL(fragSeq, 1);
         if (nextNode == NULL) {
            setEndNode_LL(fragSeq, newNode);
         }

         return NULL;
      }

      prevNode = curNode;
      curNode = getNextNode_LL(curNode);
   }

   // At end of list ...
   newNode = newNodeObject_LL(newFrag, NULL);

   if (prevNode == NULL) {
      // List is currently empty ...
      setTopNode_LL(fragSeq, newNode);
   }
   else {
      setNextNode_LL(prevNode, newNode);
   }

	// update the list
	incrLength_LL(fragSeq, 1);        // length has increased by 1
	setEndNode_LL(fragSeq, newNode);  // newNode is now the end node

   return NULL;
}


static Frag_t *delete_OrdList(FragCls_t *fragCls, LinkList_t *fragSeq, Posn_t point) {
   req_NonNull(fragSeq);

   ListNode_t *newNode = NULL;

   CompareFn_t posnCompFn = fragCls->posnCompFn;

   // No NULL_POSNs are allowed.
   if (point == NULL_POSN) return NULL;

   ListNode_t *prevNode = NULL;
   ListNode_t *curNode = getTopNode_LL(fragSeq);
   ListNode_t *nextNode = NULL;

   Frag_t *curFrag = NULL;
   Posn_t curPosn  = NULL_POSN;

   int indication = 0;
   while (curNode != NULL) {
      curFrag =  (Frag_t *)getNodeObject_LL(curNode);
      curPosn  =  curFrag->lower;

      nextNode = getNextNode_LL(curNode);

      indication = posnCompFn(curPosn, point);
      if (indication == 0) {
         // found node to delete

         if (prevNode == NULL) {
            setTopNode_LL(fragSeq, nextNode);
         }
         else {
            setNextNode_LL(prevNode, nextNode);
         }

         // update the list ...
         incrLength_LL(fragSeq, -1);
         if (nextNode == NULL) {
            setEndNode_LL(fragSeq, prevNode);
         }

         // deallocate list node
         deallocateNode_LL(curNode, nullVoidFn);

         // return current fragment
         return curFrag;

      }
      else if (indication > 0) {
         // nothing to delete
         return NULL;
      }

      prevNode = curNode;
      curNode = nextNode;
   }
   return NULL;
}


static Posn_t minPosn_OrdList(LinkList_t *fragSeq) {
   if (getLength_LL(fragSeq) == 0) return NULL_POSN;

   Frag_t *frag = (Frag_t *)getTopObject_LL(fragSeq);
   return frag->lower;
}

static Posn_t maxPosn_OrdList(LinkList_t *fragSeq) {
   if (getLength_LL(fragSeq) == 0) return NULL_POSN;

   Frag_t *frag = (Frag_t *)getEndObject_LL(fragSeq);
   return frag->upper;
}

static Posn_t nextPosn_OrdList(CompareFn_t posnCompFn, LinkList_t *fragSeq, Posn_t point, Boolean_t allowEQ) {
   if (point == NULL_POSN) return NULL_POSN;

   ListNode_t *curNode = getTopNode_LL(fragSeq);
   Frag_t *curFrag = NULL;
   Posn_t curPosn = NULL_POSN;

   int indicator = 0;

   // walking the list
   while (curNode != NULL) {
      curFrag = (Frag_t *)getNodeObject_LL(curNode);
      curPosn  = curFrag->lower;

      indicator = posnCompFn(curPosn, point);
      if (allowEQ && indicator == 0) return curPosn;
      if (indicator > 0) return curPosn;

      curNode = getNextNode_LL(curNode);
   }
   return NULL_POSN;
}

static Posn_t priorPosn_OrdList(CompareFn_t posnCompFn, LinkList_t *fragSeq, Posn_t point, Boolean_t allowEQ) {

   if (point == NULL_POSN) return NULL_POSN;

   ListNode_t *curNode = getTopNode_LL(fragSeq);
   Frag_t *curFrag = NULL;
   Posn_t curPosn = NULL_POSN;
   Posn_t prevPosn = NULL_POSN;

   int indicator = 0;

   // walking the list
   while (curNode != NULL) {
      curFrag = (Frag_t *)getNodeObject_LL(curNode);
      prevPosn = curPosn;
      curPosn  = curFrag->lower;

      indicator = posnCompFn(curPosn, point);
      if (allowEQ && indicator == 0) return curPosn;
      if (indicator >= 0) return prevPosn;

      curNode = getNextNode_LL(curNode);
   }
   return curPosn;
}

static Frag_t *lookup_OrdList(CompareFn_t posnCompFn, LinkList_t *fragSeq, Posn_t point) {
   if (point == NULL_POSN) return NULL;

   ListNode_t *curNode = getTopNode_LL(fragSeq);
   Frag_t *curFrag;
   Posn_t curPosn;

   // walking the list
   while (curNode != NULL) {
      curFrag = (Frag_t *)getNodeObject_LL(curNode);
      curPosn = curFrag->lower;

      if (posnCompFn(curPosn, point) == 0) return curFrag;

      curNode = getNextNode_LL(curNode);
   }

   return NULL;

}
