#ifndef __RB_TREE_H__
#define __RB_TREE_H__

/*******************************************************************************
  rbTree.h

  Red-Black Trees

  - Implements ordered keys mapping to value (i.e. ordered treemap).
    + Provides set and/or map abstractions.

  - Significant input from:
    +  Chapter 12, Binary Search Trees
    +  Chapter 13, Red-Black Trees

    from Cormen et al, Introduction to Algorithms, 3rd Ed. MIT Press

  Keys are encoded as an "opaque" type (see utils.h)

  Red-Black properties:
  =====================
  - Each internal node has colour either RED or BLACK.

  - The root of the tree is BLACK.

  - If a node is RED, then both of its decendants must be BLACK.

  - All terminal nodes (i.e. NULLs) are BLACK.

  - All new nodes start out being coloured RED.

  - For every node, the total number of BLACK nodes is the same for each
    decendant path from the node to the leaves.

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
#include "stringbuffer.h"

// Red-Black Tree structure
// - This encodes the root of the tree itself.
typedef struct rbTree RBTree_t;


/*******************************************************************************
  Parameters
  - These parameters are typically varied for testing purposes.
  - As they affect all instances, they should not be relied upon in production.
*******************************************************************************/
// Enable/disable internal checking of RB tree
Boolean_t doInternalChecks;

// Enable/disable output of reports from checking (see: checkTree_RBT)
Boolean_t outputCheckReports;

// Enable balancing
Boolean_t doBalancing;

// Abort when checking the tree fails
// - When true, enables the output of reports when running checkTree_RBT ...
Boolean_t abortOnCheckFailure;


/*******************************************************************************
  Methods
*******************************************************************************/
// Allocate an RBTree_t object ...
//
// - keyCompFn     - Used to compare keys - as a linear (less-than) ordering.
//                 - Take care with NULL_KEYs - these may be either significant or not,
//                   depending upon application
//                 - If function is NULL, then the standard < ordering on unsigned long values is used.
//
RBTree_t *new_RBT(CompareFn_t keyCompFn);

// Deallocate an RBTree object ...
void deallocate_RBT(void *item);

// Deallocate an RBTree object ... with specific object finaliser
void deallocateWithFinaliser_RBT(void *item, VoidFn_t finalObjFn);

// Set object finaliser function ...
// - No finalisation happens for data items unless this is set.
void setFinaliser_RBT(RBTree_t *tree, VoidFn_t finalObjFn);

// Inserts data under given key into given tree ...
// - If key already exists in tree and updates allowed:
//   + replaces previous data with dataItem.
//   + return previous data.
// - Otherwise, insert new dataItem and return NULL.
// - If updates not allowed only new values are inserted,
//   - In this case, NULL is always returned.
// - In general, use the size of tree to determine when new elements were added.
void *insert_RBT(RBTree_t *tree, Key_t key, void *dataItem);

// Deletes data under given key from given tree.
// - If found, returns the data pointer found.
// - Otherwise return NULL
void *delete_RBT(RBTree_t *tree, Key_t key);

// Checks that given key belongs to given tree.
// - Successful lookups are cached.
Boolean_t member_RBT(RBTree_t *tree, Key_t key);

// Get first data element
// - Returns NULL if empty
void *getFirstElement_RBT(RBTree_t *tree);

// Get last data element
// - Returns NULL if empty
void *getLastElement_RBT(RBTree_t *tree);

// Lookup data in tree for the given key
// - If found, returns the corresponding data pointer for the given key.
// - Otherwise return NULL
// - The last successful lookup is cached.
void *lookup_RBT(RBTree_t *tree, Key_t key);

// find key of first element matching the predicate ...
// - finds the key of the first/least element in the tree satisfying the predicate
Key_t findFirstMatch_RBT(RBTree_t *tree, PredFn_t predFn);

// find key of last element matching the predicate ...
// - finds the key of the last/greatest element in the tree satisfying the predicate
Key_t findLastMatch_RBT(RBTree_t *tree, PredFn_t predFn);

// Returns minimum key in given tree, if it exists
// - Updates the lookup cache - this means that the corresponding min-value
//   can be efficiently accessed.
// - Otherwise, return NULL_KEY.
Key_t minKey_RBT(RBTree_t *tree);

// Returns maximum key in given tree
// - Updates the lookup cache - this means that the corresponding max-value
//   can be efficiently accessed.
// - Otherwise, return NULL_KEY.
Key_t maxKey_RBT(RBTree_t *tree);

// Returns next successor key in given tree, if it exists
// - Otherwise, return NULL_KEY.
// - If allowEQ is TRUE, then can return the given key if present.
// - Given key may not itself exist in the tree.
Key_t nextKey_RBT(RBTree_t *tree, Key_t key, Boolean_t allowEQ);

// Returns predecessor key in given tree, if it exists
// - Otherwise, return NULL_KEY.
// - If allowEQ is TRUE, then can return the given key if present.
// - Given key may not itself exist in the tree.
Key_t priorKey_RBT(RBTree_t *tree, Key_t key, Boolean_t allowEQ);

// Utility to check tree for integrity (useful for testing)
Boolean_t checkTree_RBT(RBTree_t *tree);

// Height of tree
int getHeight_RBT(RBTree_t *tree);

// Total number of nodes in tree
int getSize_RBT(RBTree_t *tree);

// Set/Get allow updates
void setAllowUpdates_RBT(RBTree_t *tree, Boolean_t status);
Boolean_t getAllowUpdates_RBT(RBTree_t *tree);

// Set/Get allow NULL_KEY as a valid key
void setAllowNullKey_RBT(RBTree_t *tree, Boolean_t status);
Boolean_t getAllowNullKey_RBT(RBTree_t *tree);


// Show tree by appending to stringbuffer
// - set indent string
// - set incrment indent string
// - set compact display
// - set max depth (if positive)
// - set show details of nodes (default: TRUE)
// - set show tree tightly
// - set show tree in in-order (default)
// - set show tree in pre-order
// - set show ids (default: TRUE)
// - set show addresses (default: FALSE)
// - set show simplified addresses (e.g. addr mod 0x10000) (default: FALSE)

void show_RBT(RBTree_t *tree, StringBuf_t *sbuf);
void setShow_Indent_RBT(char * indent);
void setShow_IncrIndent_RBT(char * indent);
void setShow_Compact_RBT(Boolean_t isCompact);
void setShow_MaxDepth_RBT(int maxDepth);
void setShow_Details_RBT(Boolean_t details);
void setShow_Tightly_RBT(Boolean_t tightly);
void setShow_Inorder_RBT();
void setShow_Preorder_RBT();
void setShow_IDs_RBT(Boolean_t ids);
void setShow_Addrs_RBT(Boolean_t addrs);
void setShow_SimplifiedAddrs_RBT(Boolean_t simplified);


// Maximum indent length
#define  MAX_INDENT_LENGTH    20

// Maximum Tree Height ...
#define MAX_TREE_HEIGHT   32

#endif
