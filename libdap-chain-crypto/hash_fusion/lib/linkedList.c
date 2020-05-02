
/*******************************************************************************
  linkedList.c

  Linked lists ...
  - can add elements at either end (i.e. stack/queue semantics)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"
#include "linkedList.h"
#include "fragment.h"

// Default status to allow updates to list
#define DEFAULT_ALLOW_UPDATES  TRUE

// Top Level of List object
struct linkedList {
   Boolean_t     allowUpd;   // Flag to allow updates or not
   int           length;     // List length
   VoidFn_t      finalFn;
   ListNode_t    *first;
   ListNode_t    *last;
};


// List nodes
struct listNode {
   void       *data;
   ListNode_t *next;
};


// Memory Management
MemMgr_t *linkedList_MemMgr = NULL;
MemMgr_t *listNode_MemMgr = NULL;

// local methods/prototypes
static void ensureMemMgmt();
static void deallocateNodes(ListNode_t *nodes, VoidFn_t finalFn);

static void ensureMemMgmt() {
   if (linkedList_MemMgr == NULL) {
      linkedList_MemMgr  = new_MM(sizeof(LinkList_t));
   }

   if (listNode_MemMgr == NULL) {
      listNode_MemMgr  = new_MM(sizeof(ListNode_t));
   }
}

static void deallocateNodes(ListNode_t *nodes, VoidFn_t finalFn) {
   if (nodes == NULL) return;

   // Ensure memory management ...
   ensureMemMgmt();

   VoidFn_t deallocFn = (finalFn == NULL ? nullVoidFn : finalFn);
   nullVoidFn(nodes);

   ListNode_t *curNode = nodes;
   ListNode_t *nextNode = NULL;

   // walk the list to deallocate nodes
   while (curNode != NULL) {
      nextNode = curNode->next;

      // deallocate object
      deallocFn(curNode->data);

      // Nullify node content
      NULLIFY_OBJ(curNode, ListNode_t);

      // recycle the node
      deallocateObject_MM(listNode_MemMgr, sizeof(ListNode_t), curNode);

      // advance the curNode to the next ...
      curNode = nextNode;
   }
}


/*******************************************************************************
  Methods
*******************************************************************************/

// creates a newly allocated link list ...
LinkList_t *new_LL() {

   // ensure that the allocation structures exists
   ensureMemMgmt();

   LinkList_t *newList = allocateObject_MM(linkedList_MemMgr);

   newList->allowUpd = DEFAULT_ALLOW_UPDATES;
   newList->length   = 0;
   newList->finalFn  = nullVoidFn;
   newList->first    = NULL;
   newList->last     = NULL;

   return newList;
}


// Allow/disallow updates
Boolean_t getAllowUpdates_LL(LinkList_t *lst) {
   req_NonNull(lst);

   return (lst->allowUpd);
}

void setAllowUpdates_LL(LinkList_t *lst, Boolean_t status) {
   req_NonNull(lst);

   lst->allowUpd = status;
}


// Deallocates a link list
void deallocate_LL(LinkList_t *lst) {
   deallocateWithFinaliser_LL(lst, lst->finalFn);
}


// Deallocates a link list - with specific finaliser
void deallocateWithFinaliser_LL(LinkList_t *lst, VoidFn_t finalFn) {
   if (lst == NULL) return;

   // ensure that the allocation structures exists
   ensureMemMgmt();

   deallocateNodes(lst->first, finalFn);

   // nullify/scrub attributes
   NULLIFY_OBJ(lst, LinkList_t);

   deallocateObject_MM(linkedList_MemMgr, sizeof(LinkList_t), lst);}


// Resets a link list
// -the finaliser function (if set) is retained.
void reset_LL(LinkList_t *lst) {
   if (lst == NULL) return;

   // deallocate the elements
   deallocateNodes(lst->first, lst->finalFn);

   lst->length   = 0;
   lst->first    = NULL;
   lst->last     = NULL;
}


// set finaliser function ...
void setFinaliserFn(LinkList_t *lst, VoidFn_t finalFn) {
   req_NonNull(lst);

   lst->finalFn = finalFn;
}


// get length of link list
int getLength_LL(LinkList_t *lst) {
   req_NonNull(lst);

   return lst->length;
}


// calc. length of link list
int calcLength_LL(LinkList_t *lst) {
   req_NonNull(lst);

   int count = 0;
   ListNode_t *curNode = getTopNode_LL(lst);

   while (curNode != NULL) {
      count += 1;
      curNode = curNode->next;
   }

   return count;
}

// add object to top of the list (stack-wise - LIFO)
void addObject_LL(LinkList_t *lst, void *obj) {
   req_NonNull(lst);

   ListNode_t *newNode = allocateObject_MM(listNode_MemMgr);

   lst->length += 1;
   newNode->data = obj;

   if (lst->last == NULL) {
      newNode->next = NULL;
      lst->first = newNode;
      lst->last = newNode;
   }
   else {
		newNode->next = lst->first;
		lst->first = newNode;
   }
}


// synonym for addObject_LL
void pushObject_LL(LinkList_t *lst, void *obj) {
    addObject_LL(lst, obj);
}


// add object to end of the list (stack-wise - FIFO)
void addEndObject_LL(LinkList_t *lst, void *obj) {
   req_NonNull(lst);

   ListNode_t *lastNode = lst->last;
   ListNode_t *newNode  = allocateObject_MM(listNode_MemMgr);

   lst->length += 1;
   newNode->data = obj;
   newNode->next = NULL;

   if (lastNode == NULL) {
      lst->last = newNode;
      lst->first = newNode;
   }
   else {
      // make current last node point at the new node
		lastNode->next = newNode;
		lst->last = newNode;
   }
}


// gets the top element (i.e. the front element) - or NULL (if empty).
// - does not modify the list
void *getTopObject_LL(LinkList_t *lst) {
   req_NonNull(lst);

   ListNode_t *firstNode = lst->first;

   if (firstNode == NULL) {
      return NULL;
   }
   return firstNode->data;
}

void *getHead_LL(LinkList_t *lst) {
   return getTopObject_LL(lst);
}

void *popObject_LL(LinkList_t *lst) {
   return getTopObject_LL(lst);
}

// Gets the end data element in list
void *getEndObject_LL(LinkList_t *lst) {
   req_NonNull(lst);

   ListNode_t *endNode = lst->last;

   if (endNode == NULL) {
      return NULL;
   }
   return endNode->data;
}


// Sets the end data element in list
// - returns the old pointer
void *setEndObject_LL(LinkList_t *lst, void *obj) {
   req_NonNull(lst);

   ListNode_t *endNode = lst->last;

   if (endNode == NULL) {
      return NULL;
   }

   void *result = endNode->data;

   endNode->data = obj;
   return result;
}


// Gets the Nth element (0 based)
// - Negative index counts back from the end
// - If index is out of range, return NULL
void *getNthObject_LL(LinkList_t *lst, int index) {
   req_NonNull(lst);

   if (index < 0) {
      index = (lst->length)+index;
   }

   if (index < 0) {
      return NULL;
   }

   if (lst->length <= index) return NULL;

   ListNode_t *curNode = lst->first;

   for (int count = index; curNode != NULL; count--) {
      if (count == 0) {
         return curNode->data;
      }
      curNode = curNode->next;
   }

   return NULL;
}


// Update Nth object in the list
// - If the allowUpd property is FALSE, then make no change and return NULL.
// - Returns the old pointer ...
// - Negative index counts back from the end
// - If index is out of range, return NULL
void *updateNthObject_LL(LinkList_t *lst, int index, void *newObj) {
   req_NonNull(lst);

   if (!lst->allowUpd) return NULL;

   void *oldObj = NULL;

   // check for negative index - meaning index from end of list
   if (index < 0) {

      // covert to positive index
      index = (lst->length)+index;

		// retest index following update
		if (index < 0) {
		   // index is still out of range
		   return NULL;
		}
   }


   if (lst->length <= index) return NULL;

   ListNode_t *curNode = lst->first;

   for (int count = index; curNode != NULL; count--) {
      if (count == 0) {
         oldObj = curNode->data;
         curNode->data = newObj;
         return oldObj;
      }

      curNode = curNode->next;
   }

   return NULL;
}

// Insert object at Nth position in the list (0 based)
// - Negative index counts back from the end
// - If index is out of range, return with no update
Boolean_t insertNthObject_LL(LinkList_t *lst, int index, void *obj) {
   req_NonNull(lst);

   //Boolean_t result = FALSE;

   //void *oldObj = NULL;

   // check for negative index - meaning index from end of list
   if (index < 0) {

      // covert to positive index
      index = (lst->length)+index;

		// retest index following update
		if (index < 0) {
		   // index is still out of range
		   return FALSE;
		}
   }

   if (lst->length <= index) return FALSE;

   ListNode_t *prevNode = NULL;
   ListNode_t *curNode = lst->first;

   for (int count = index; count >= 0; count--) {
      if (count == 0) {
			ListNode_t *newNode  = allocateObject_MM(listNode_MemMgr);

		   // update the length
			lst->length += 1;

			// update the new node
			newNode->data = obj;
			newNode->next = curNode;

			// position the new node
			if (prevNode == NULL) {
			   // make new node the top node
			   lst->first = newNode;
			}
			else {
			   // make new node follow on from prevNode ...
			   prevNode->next = newNode;
			}

         return TRUE;
      }

      prevNode = curNode;
      curNode = curNode->next;
   }

   return FALSE;
}


// Clone source list into dest list.
void cloneList_LL(LinkList_t *dest, LinkList_t *source) {
   req_NonNull(dest);
   req_NonNull(source);

   // deallocate any current destination nodes
   deallocateNodes(dest->first, dest->finalFn);

   // reset the destination linked list object
   dest->length =  source->length;
   dest->first  =  NULL;
   dest->last   =  NULL;

   ListNode_t *curNode  = source->first;

   ListNode_t *prevNewNode = NULL;
   ListNode_t *curNewNode  = NULL;

   while (curNode != NULL) {
      curNewNode = allocateObject_MM(listNode_MemMgr);

      curNewNode->data  =  curNode->data;


      if (dest->first == NULL) {
         dest->first = curNewNode;
      }

      if (prevNewNode != NULL) {
         prevNewNode->next = curNewNode;
      }

      prevNewNode = curNewNode;

      curNode = curNode->next;
   }

   // Make dest->last points at the last node of the new list.
   dest->last = prevNewNode;
}

// Append source list to end of dest list.
// - destructively modifies the dest list by adding cloned
//   source list.
void nAppendList_LL(LinkList_t *dest, LinkList_t *source) {
   req_NonNull(dest);
   req_NonNull(source);

   // update the length
   dest->length += source->length;

   // the curNode pointer starts at first node of source.
   ListNode_t *curNode  = source->first;

   ListNode_t *prevNewNode = dest->last;  // set to existing last elem.
   ListNode_t *curNewNode  = NULL;

   while (curNode != NULL) {
      // allocate node
      curNewNode = allocateObject_MM(listNode_MemMgr);

      // copy over the data pointer ...
      // - data is shared
      curNewNode->data  =  curNode->data;

      // attach current node to previous new node
      if (prevNewNode != NULL) {
         prevNewNode->next = curNewNode;
      }

      // update the first cell of dest if necessary
      if (dest->first == NULL) {
         dest->first = curNewNode;
      }

      // track the previous node
      prevNewNode = curNewNode;

      // advance current Node
      curNode = curNode->next;
   }

   // dest->last now points at the last node of the new list.
   dest->last = prevNewNode;
}

// reverse-append source list to end of dest list.
// - source list is not modified.
// - dest list is destructively updated with the reverse of source.
// - length of dest is increased by length of source list
void nRevAppendList_LL(LinkList_t *dest, LinkList_t *source) {
   req_NonNull(dest);
   req_NonNull(source);

   // return with
   if (source->length == 0) return ;

   // update the length
   dest->length += source->length;

   ListNode_t *lastNode = dest->last;     // pointer to last node of destination ...
   ListNode_t *curNode  = source->first;  // currrent pointer into source list

   ListNode_t *accumEndNode = NULL;       // place to accumulate the new end list
   ListNode_t *curTopNode   = NULL;
   ListNode_t *curNewNode   = NULL;

   ListNode_t *newLastNode = NULL;  // records the first node added to end list

   while (curNode != NULL) {
      // allocate node
      curNewNode = allocateObject_MM(listNode_MemMgr);

      // keep track of the current top node for new end list
      accumEndNode = curNewNode;

      // record the first new node allocated
      // - this will be the new last node of the dest list
      if (newLastNode == NULL) {
         newLastNode = accumEndNode;
      }

      // update the current new node ...
      // - data is shared
      // - curNewData
      curNewNode->data  =  curNode->data;
      curNewNode->next  =  curTopNode;

      //
      curTopNode = curNewNode;

      // advance current Node to next
      curNode = curNode->next;
   }

   if (dest->first == NULL) {
      dest->first = accumEndNode;
   }

   if (lastNode != NULL) {
     lastNode->next = accumEndNode;
   }

   // dest->last now points at the last node of the new list.
   if (newLastNode != NULL) {
      dest->last = newLastNode;
   }
}

// Destructively reverse given list
// - reuses existing cells - no allocation needed ...
void nReverseList_LL(LinkList_t *lst) {
   req_NonNull(lst);

   // return for null list
   if (lst->length == 0) return;

   // non-null list
   ListNode_t *oldFirstNode = lst->first;
   ListNode_t *oldLastNode = lst->last;

   ListNode_t *curNode  = oldFirstNode;  // currrent pointer into source list
   ListNode_t *nextNode = NULL;

   ListNode_t *accumEndNode = NULL;      // place to accumulate the new reversed list

   while (curNode != NULL) {
      nextNode = curNode->next;
      curNode->next = accumEndNode;

      // keep track of the current top node for new end list
      accumEndNode = curNode;

      // advance current node to next
      curNode = nextNode;
   }

   lst->first = oldLastNode;
   lst->last  = oldFirstNode;
}


/*******************************************************************************
  List Nodes Methods
  - Methods for walking/manipulating list nodes directly
*******************************************************************************/
// Gets the top node
ListNode_t *getTopNode_LL(LinkList_t *lst) {
   req_NonNull(lst);

   return lst->first;
}


// Sets the top node (UNSAFE)
// - returns the old top node (in case it needs to be deallocated)
ListNode_t *setTopNode_LL(LinkList_t *lst, ListNode_t *topNode) {
   req_NonNull(lst);

   ListNode_t *oldTopNode = lst->first;
   lst->first = topNode;

   // returns the old top node
   return oldTopNode;
}


// Deallocate a list node
// - returns the next node
// - the value object can be deallocated via the custom deallocObjFn.
// - if deallocObjFn is NULL, then no deallocation is performed ...
ListNode_t *deallocateNode_LL(ListNode_t *node,  VoidFn_t deallocObjFn) {
   if (node == NULL) return NULL;

   ListNode_t *oldNextNode = node->next;

   VoidFn_t finalObjFn = (deallocObjFn == NULL ? nullVoidFn : deallocObjFn);

   // deallocate object
   finalObjFn(node->data);

   // Nullify node content
   node->data = NULL;
   node->next = NULL;

   // recycle the node
   deallocateObject_MM(listNode_MemMgr, sizeof(ListNode_t), node);

   return oldNextNode;
}

// Gets the Nth node (0-based)
// - Negative index counts back from the end
// - If index is out of range, return NULL
ListNode_t *getNthNode_LL(LinkList_t *lst, int index) {
   req_NonNull(lst);

   if (index < 0) {
      index = (lst->length)+index;
   }

   if (index < 0) {
      return NULL;
   }

   if (lst->length <= index) return NULL;

   ListNode_t *curNode = lst->first;

   for (int count = index; curNode != NULL; count--) {
      if (count == 0) {
         return curNode;
      }
      curNode = curNode->next;
   }

   return NULL;
}


// Allocates a fresh list node
ListNode_t *newNodeObject_LL(void *obj, ListNode_t *nextNode) {
   ListNode_t *newNode = allocateObject_MM(listNode_MemMgr);

   newNode->data = obj;
   newNode->next = nextNode;

   return newNode;
}


// Gets the object from the given node  - or NULL (if empty).
void *getNodeObject_LL(ListNode_t *node) {
   if (node == NULL) return NULL;

   return node->data;
}


// Sets the object from the given node.
// - returns the old pointer
void *setNodeObject_LL(ListNode_t *node, void *newObj) {
   if (node == NULL) return NULL;

   void *result = node->data;

   node->data = newObj;

   return result;
}


// Gets the next node (could be NULL) following the given node ...
ListNode_t *getNextNode_LL(ListNode_t *node) {
   if (node == NULL) return NULL;

   return node->next;
}


// Sets the next node (could be NULL) following the given node ... (UNSAFE)
// - returns the old node (which may need to be disposed of).
// - fails if curNode is NULL.
// - This could break the representation as:
//   - the length is not updated
//   - the last element pointer is not maintained.
// - Update the list after mainipulation.
ListNode_t *setNextNode_LL(ListNode_t *curNode, ListNode_t *newNextNode) {
   req_NonNull(curNode);

   ListNode_t *oldNextNode = curNode->next;
   curNode->next = newNextNode;

   return oldNextNode;
}


/*******************************************************************************
  List representation maintenance ...

  - USE WITH CARE ...
  - in general, these are either UNSAFE (not guaranteed) OR EXPENSIVE.

*******************************************************************************/
// Set length of link list (UNSAFE)
// - Can break the representation
void setLength_LL(LinkList_t *lst, int length) {
   req_NonNull(lst);

   lst->length = length;
}

// Increment length of link list (UNSAFE)
// - Can break the representation
void incrLength_LL(LinkList_t *lst, int increment) {
   req_NonNull(lst);

   lst->length += increment;
}

// Set end of list (UNSAFE)
// - Checks that next node pointer of newEndNode is NULL (fails if not).
// - Can break the representation
void setEndNode_LL(LinkList_t *lst, ListNode_t *newEndNode) {
   req_NonNull(lst);

   if (newEndNode != NULL && newEndNode->next != NULL) {
      diagnostic("setEndNode_LL : End node should have NULL successor ...");
      error_exit();
   }

   lst->last = newEndNode;
}

// Update link list (EXPENSIVE - this traverses list from fromNode)
// - starts from top object
// - ensures the current length is valid
// - ensures that the pointer to end node is valid
// - returns the current length
int updateList_LL(LinkList_t *lst) {
   req_NonNull(lst);

   // pointer to previous node ...
   ListNode_t *prevNode = NULL;

   // walk the list ...
   int count = 0;
   for (ListNode_t *curNode = lst->first; curNode != NULL; count++) {
      prevNode = curNode;
   	curNode = curNode->next;
   }

   // update the length ...
   lst->length = count;

   // update the pointer to the end node ...
   lst->last = prevNode;

   return count;
}
