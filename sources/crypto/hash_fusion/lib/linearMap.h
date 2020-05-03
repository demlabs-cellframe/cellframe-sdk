#ifndef __INDEX_MAP_H__
#define __INDEX_MAP_H__

#include "utils.h"
#include "bytevector.h"
#include "stringbuffer.h"


/*******************************************************************************
  linearMap.h

  Linear indexed maps
  - Encodes a mapping as a linear linked list.
  - Keys are encoded as unsigned longs (e.g. can contain void *)
  - Key comparison is UNORDERED and is literal equality.
  
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

typedef struct linearMap LinearMap_t;

// prototypes

// generates new LinearMap_t
LinearMap_t *new_LM();

// Deallocate linear map
void deallocate_LM(void *item);

// Set object finaliser function ...
// - No finalisation happens for data items unless this is set.
void setFinaliser_LM(LinearMap_t *lmap, VoidFn_t finalObjFn);

// Looks up entry in map using the key
void *getEntry_LM(LinearMap_t *lmap, unsigned long key);

// Adds/updates entry under key to given linearMap
void addEntry_LM(LinearMap_t *lmap, unsigned long key, void *entry);

// Removes existing entry in given linearMap under key
// - returns the object removed (if key exists)
void *removeEntry_LM(LinearMap_t *lmap, unsigned long key);

// Calculate size
int size_LM(LinearMap_t *lmap);

// Clear existing map
void clear_LM(LinearMap_t *lmap);

#endif
