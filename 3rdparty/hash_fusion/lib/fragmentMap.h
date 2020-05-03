#ifndef __FRAGMENT_MAP_H__
#define __FRAGMENT_MAP_H__

/*******************************************************************************
  fragmentMap.h

  Provides fragment maps e.g. a map from fragments to a space of values.
  A fragment is a pair consisting of a fragment and its valuation.

  In essence, we have each map M with functional typing: Fragments -> Value
  so that:

         M = { intv |-> v  |  intv in S }

  The domain of the map is a set of closed fragments, based upon some finite
  discrete linearly ordered set of points (e.g. subset of the integers, finite
  subset of strings).

  A closed fragment of points is characterised by a pair [lower, upper] which
  is defined by:  { x | lower <= x <= upper }

  Note that when upper = lower, then [lower, upper] is the singleton set {x}
  where x = lower = upper.

  We want to also merge adjacent fragments and therefore combine map values
  for _adjacent_ fragments.  If VCF is the value combiner operation, then:

     { ... [a, b] |-> v1,  [b', c] |=> v2 ... }   (where b and b' are adjacent)

     Becomes:

     { ... [a,c] |-> (v1 VCF v2) ... }

  (An example of "multiset rewriting reduction")

  Two fragments are _adjacent_ iff:

      A.upper + 1 = B.lower  OR  B.upper + 1 = A.lower

  We can always merge two adjacent fragments to make a larger fragment.

       [3, 7] \/ [8, 10]  =
       [3, 5] \/ [6, 10]  =  [3, 10]

  An fragment map M is said to be _reduced_ when the domain of M is a set of
  disjoint, non-adjacent closed fragments.

  NOTE: The NULL_KEY is not a valid key here.

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
#include "fragment.h"

/*******************************************************************************
   Classes and Types
*******************************************************************************/

typedef enum {
      NULL_FRAG_MAP = 180,   // Trivial fragment map i.e. single fragment mode.
      LINEAR_LIST_FRAG_MAP,  // Use Linear List implementation for fragment map
      BINARY_TREE_FRAG_MAP   // Use Binary Tree implementation for fragment map
   }
   FragMapKind_t;


// Fragment Maps
typedef struct fragmentMap FragMap_t;


/*******************************************************************************
   Fragment Map Methods
*******************************************************************************/
// Create a new fragment map (FragMap_t)
FragMap_t *new_FM(FragCls_t *fragCls, FragMapKind_t fragKind);


// Deallocate fragment map
void deallocate_FM(void *item);


// Add a point mapping to given fragment map
// - Adds the point to the mapping and then reduces the domain set
//   by combining with adjacent fragments in the mapping.
// - Returns TRUE if addition was successful, FALSE otherwise.
Boolean_t addPoint_FM(FragMap_t *fragMap, Posn_t point, Object_t value);


// Add a consistent fragment to given fragment map
// - Adds the fragment to the mapping and then reduces the domain set
//   by combining with adjacent fragments in the mapping.
// - Returns TRUE if addition was successful, FALSE otherwise.
Boolean_t addFragment_FM(FragMap_t *fragMap, Posn_t lower, Posn_t upper, Object_t value);


// Lookup covering fragment for a given point.
// - This determines the fragment that covers the given point, and returns it.
// - Returns NULL if not found
Frag_t *lookupFragment_FM(FragMap_t *fragMap, Posn_t point);


// Size of fragment map - i.e. number of disjoint fragments
int getSize_FM(FragMap_t *fragMap);


// Get the first fragment
// - Returns NULL if empty
Frag_t *getFirstFragment_FM(FragMap_t *fragMap);


// Enumerate fragment point mappings
// - Checks if map is locked (i.e. being enumerated).
// - Enumerates fragment objects in order.
// - Returns NULL, when completed.
// - Changes are locked out during enumeration.
Boolean_t isLocked_FM(FragMap_t *fragMap);     // Checks if map is locked.
Frag_t *start_EnumMap_FM(FragMap_t *fragMap);  // Initialises enumeration + locks mapping.
Frag_t *next_EnumMap_FM(FragMap_t *fragMap);   // Gets the next fragment element (othwrwise NULL)
void stop_EnumMap_FM(FragMap_t *fragMap);      // Stops the enumeration + unlocks mapping.


#endif
