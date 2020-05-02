#ifndef __LINKED_LIST_H__
#define __LINKED_LIST_H__

/*******************************************************************************
  linkedList.h

  Linked lists ...
  - can add elements at either end (i.e. stack/queue semantics supported)
  - efficient append and reverse (linear)

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

// Linked List structure
typedef struct linkedList LinkList_t;

// List Node structure
typedef struct listNode ListNode_t;


/*******************************************************************************
  Methods on Lists
*******************************************************************************/

// Creates a newly allocated link list ...
LinkList_t *new_LL();

// Set finaliser function ...
void setFinaliserFn(LinkList_t *lst, VoidFn_t finalFn);

// Allow/disallow updates
// - This only inhibits updates using updateNthObject
// - Updates etc. using the ListNode based operations still permitted.
Boolean_t getAllowUpdates_LL(LinkList_t *lst);
void setAllowUpdates_LL(LinkList_t *lst, Boolean_t status);

// Deallocates a link list
void deallocate_LL(LinkList_t *lst);

// Deallocates a link list - with finaliser
void deallocateWithFinaliser_LL(LinkList_t *lst, VoidFn_t finalFn);

// Resets a link list
// -the finaliser function (if set) is retained.
void reset_LL(LinkList_t *lst);

// get length of link list
int getLength_LL(LinkList_t *lst);

// calc. length of link list
int calcLength_LL(LinkList_t *lst);

// add object to top of the list (stack-wise - LIFO)
void addObject_LL(LinkList_t *lst, void *obj);
void pushObject_LL(LinkList_t *lst, void *obj);

// add object to end of the list (stack-wise - FIFO)
void addEndObject_LL(LinkList_t *lst, void *obj);

// gets the top element (i.e. the front element) - or NULL (if empty).
// - does not modify the list
void *getTopObject_LL(LinkList_t *lst);
void *getHead_LL(LinkList_t *lst);

// return top element, but also removes it from list.
void *popObject_LL(LinkList_t *lst);

// Gets the end data element in list
void *getEndObject_LL(LinkList_t *lst);

// Sets the end data element in list
// - returns the old pointer
void *setEndObject_LL(LinkList_t *lst, void *obj);

// Gets the Nth element (0 based)
// - Negative index counts back from the end
// - If index is out of range, return NULL
void *getNthObject_LL(LinkList_t *lst, int index);

// Update Nth object in the list
// - Returns the old pointer ...
// - Negative index counts back from the end
// - If index is out of range, return NULL
void *updateNthObject_LL(LinkList_t *lst, int index, void *obj);

// Insert object at Nth position in the list
// - Negative index counts back from the end
// - If index is out of range, return FALSE
// - returns TRUE, if insert completed.
Boolean_t insertNthObject_LL(LinkList_t *lst, int index, void *obj);

// Clone source list into dest list.
void cloneList_LL(LinkList_t *dest, LinkList_t *source);

// Append source list to end of dest list.
// - destructively modifies the dest list by adding cloned
//   source list.
void nAppendList_LL(LinkList_t *dest, LinkList_t *source);

// reverse-append source list to end of dest list.
void nRevAppendList_LL(LinkList_t *dest, LinkList_t *source);

// Destructively reverse given list
// - reuses existing cells - no allocation needed ...
void nReverseList_LL(LinkList_t *lst);


/*******************************************************************************
  List Node Methods
  - Methods for walking/manipulating list nodes directly
*******************************************************************************/
// Gets the top node (i.e. element 0)
ListNode_t *getTopNode_LL(LinkList_t *lst);

// Sets the top node
// - returns the old top node (in case it needs to be deallocated)
// - updates internals to use the new list defined by topNode.
ListNode_t *setTopNode_LL(LinkList_t *lst, ListNode_t *topNode);

// Deallocate a list node
// - returns the next node
// - the value object can be deallocated via the custom deallocObjFn.
// - if deallocObjFn is NULL, then no deallocation is performed ...
ListNode_t *deallocateNode_LL(ListNode_t *node,  VoidFn_t deallocObjFn);

// Gets the Nth node (0-based)
// - Negative index counts back from the end
// - If index is out of range, return NULL
ListNode_t *getNthNode_LL(LinkList_t *lst, int index);

// Allocates a fresh list node
ListNode_t *newNodeObject_LL(void *obj, ListNode_t *nextNode);

// Gets the object from the given node  - or NULL (if empty).
void *getNodeObject_LL(ListNode_t *node);

// Sets the object from the given node  - or NULL (if empty).
// - returns the old pointer
void *setNodeObject_LL(ListNode_t *node, void *newObj);

// Gets the next node (could be NULL) following the given node ...
ListNode_t *getNextNode_LL(ListNode_t *node);

// Sets the next node (could be NULL) following the given node ...
// - returns the old node (which may need to be disposed of).
// - fails if curNode is NULL.
ListNode_t *setNextNode_LL(ListNode_t *curNode, ListNode_t *newNextNode);


/*******************************************************************************
  List representation maintenance ...

  - USE WITH CARE ...
  - in general, these are either UNSAFE (not guaranteed) OR EXPENSIVE.

*******************************************************************************/
// Set length of link list (UNSAFE)
// - Can break the representation
void setLength_LL(LinkList_t *lst, int length);

// Increment length of link list (UNSAFE)
// - Can break the representation
void incrLength_LL(LinkList_t *lst, int increment);

// Set end of list (UNSAFE)
// - Checks that next node pointer of newEndNode is NULL (fails if not).
// - Can break the representation
void setEndNode_LL(LinkList_t *lst, ListNode_t *newEndNode);

// Update link list (EXPENSIVE - this traverses list from fromNode)
// - starts from top object
// - ensures the current length is valid
// - ensures that the last pointer is valid
// - returns the current length
int updateList_LL(LinkList_t *lst);


#endif
