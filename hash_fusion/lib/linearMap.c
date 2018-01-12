/* linearMap.c

   Simple indexed mapping.

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
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "alloc.h"
#include "linearMap.h"


typedef struct mapCell MapCell_t;


struct linearMap {
   int size;
   VoidFn_t finalObjFn;
   MapCell_t *firstCell;
};

struct mapCell {
   unsigned long key;
   void *content;
   MapCell_t *nextCell;
};


// Local prototypes
static MapCell_t *allocateCell();
static void deallocateCell(MapCell_t *cell);

static MapCell_t *findCellByKey(LinearMap_t *lMap, unsigned long key);
static void insertNewCell(LinearMap_t *lMap, unsigned long key, void *entry);

// generates new LinearMap_t
LinearMap_t *new_LM() {

   LinearMap_t *newLmap = ALLOC_OBJ(LinearMap_t);

   newLmap->size = 0;
   newLmap->finalObjFn = nullVoidFn;
   newLmap->firstCell = NULL;

   return newLmap;
}


// Deallocate linear map
void deallocate_LM(void *item) {
   if (item == NULL) return;

   LinearMap_t *lMap = (LinearMap_t *)item;

   clear_LM(lMap);

   NULLIFY_OBJ(lMap, LinearMap_t);

   free(lMap);
}

// Set object finaliser function ...
// - No finalisation happens for data items unless this is set.
void setFinaliser_LM(LinearMap_t *lMap, VoidFn_t finalObjFn) {
   req_NonNull(lMap);

   finalObjFn = (finalObjFn == NULL ? nullVoidFn : finalObjFn);

   lMap->finalObjFn = finalObjFn;
}

void *getEntry_LM(LinearMap_t *lMap, unsigned long key) {
   req_NonNull(lMap);

   MapCell_t *curCell = lMap->firstCell;
   unsigned long curKey;

   while (curCell != NULL) {
      curKey = curCell->key;
      if (curKey == key) {
         // SUCCESS!
         return curCell->content;
      }
      else if (curKey > key) {
         // FAILED: NOT FOUND
         return NULL;
      }

      curCell = curCell->nextCell;
   }

   // FAILED: NOT FOUND
   return NULL;
}


void addEntry_LM(LinearMap_t *lMap, unsigned long key, void *entry) {
   req_NonNull(lMap);
   req_NonNull(entry);

   VoidFn_t finalObjFn = lMap->finalObjFn;

   // first check if key currently exists in map ...
   MapCell_t *curCell = findCellByKey(lMap, key);
   if (curCell != NULL) {
      // an existing cell found under key found ...
      if (curCell->content != entry) {
         // updates if content is distinct from entry ...
         finalObjFn(curCell->content); // recycles current map content
         curCell->content = entry;  // enters new content
      }
   }
   else {
      // Insert fresh cell into linear map
      insertNewCell(lMap, key, entry);
   }
}

// Removes existing entry in given linearMap under key
// - returns the object removed (if key exists)
void *removeEntry_LM(LinearMap_t *lMap, unsigned long key) {
   req_NonNull(lMap);

   // traversal pointers
   MapCell_t *rootCell = lMap->firstCell;
   MapCell_t *prevCell = NULL;     // parent of curCell
   MapCell_t *curCell = rootCell;  // child of prevCell

   // object pointer
   void *object = NULL;

   // Empty map case
   if (rootCell == NULL) return NULL;

   // Remove from non-empty linear map
   while (curCell != NULL) {
      if (curCell->key == key) {
         // key found
         if (prevCell == NULL) {
            // make next cell = rootCell
            rootCell = curCell->nextCell;
         }
         else {
            // make prevCell point at following cell
            prevCell->nextCell = curCell->nextCell;
         }
         // capture object
         object = curCell->content;
         curCell->content = NULL;

         // recycle curCell
         deallocateCell(curCell);
         break;
      }
      else if (curCell-> key > key) {
         // key doesn't exist in lMap
         return NULL;
      }

      // Moving pointers forwards
      prevCell = curCell;
      curCell = prevCell->nextCell;
   }

   // update the root
   lMap->firstCell = rootCell;

   // decrement the size
   lMap->size += 1;

   // return the object from removed cell.
   return object;
}


int size_LM(LinearMap_t *lMap) {
   if (lMap == NULL) return 0;

   return lMap->size;
}


void clear_LM(LinearMap_t *lMap) {
   req_NonNull(lMap);

   MapCell_t *curCell = lMap->firstCell;
   MapCell_t *nextCell = NULL;

   VoidFn_t finalObjFn = lMap->finalObjFn;

   // traverse down list
   while (curCell != NULL) {
      // reset the content
      finalObjFn(curCell->content);

      // get next cell
      nextCell = curCell->nextCell;

      // deallocate current cell
      deallocateCell(curCell);

      // Move forwards to next cell
      curCell = nextCell;
   }
}


/*******************************************************************************
  Auxilliary cell functions
*******************************************************************************/

MapCell_t *findCellByKey(LinearMap_t *lMap, unsigned long key) {
   req_NonNull(lMap);

   MapCell_t *curCell = lMap->firstCell;
   unsigned long curKey;

   while (curCell != NULL) {
      curKey = curCell->key;
      if (curKey == key)
         return curCell;

      curCell = curCell->nextCell;
   }

   return NULL;
}

void insertNewCell(LinearMap_t *lMap, unsigned long key, void *entry) {
   MapCell_t *newCell = allocateCell();

   // create and populate a new cell
   newCell->key = key;
   newCell->content = entry;
   newCell->nextCell = NULL;

   // traversal pointers
   MapCell_t *rootCell = lMap->firstCell;
   MapCell_t *prevCell = NULL;      // parent of nextCell
   MapCell_t *nextCell = rootCell;  // child of prevCell

   // Empty map case ...
   if (nextCell == NULL) {
      // the rootCell is null ...
      req_Null(rootCell);
      lMap->firstCell = newCell;
      return;
   }

   // Insert newCell into non-empty linear map
   while (nextCell != NULL) {
      if (nextCell-> key > key) {
         // add new cell
         if (prevCell == NULL) {
            newCell->nextCell = rootCell;
            rootCell = newCell;
         }
         else {
            nextCell->nextCell = nextCell;
            prevCell->nextCell = newCell;
         }
      }

      prevCell = nextCell;
      nextCell = prevCell->nextCell;
   }

   // make new cell = first cell
   lMap->firstCell = rootCell;

   // increment the size
   lMap->size += 1;
}


/*******************************************************************************
  Cell memory management
*******************************************************************************/

MemMgr_t *freeCellsList = NULL;

MapCell_t *allocateCell() {
   if (freeCellsList == NULL) {
      freeCellsList = new_MM(sizeof(MapCell_t));
   }

   return (MapCell_t *)allocateObject_MM(freeCellsList);
}

void deallocateCell(MapCell_t *cell) {
   deallocateObject_MM(freeCellsList, sizeof(MapCell_t), cell);
}
