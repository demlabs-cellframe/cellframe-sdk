#ifndef __BYTEVECTOR_H__
#define __BYTEVECTOR_H__

#include "utils.h"


/*******************************************************************************
   bytevector.h

   Basic bytevectors  ...

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

typedef struct bytevector ByteVec_t;

#define DEFAULT_BYTEVECTOR_CAPACITY  16


// Allocates a standard size bytevector (with default capacity)
// - uses the default bytevector capacity as initial capacity
// - use ensureCapacity_BV to explicitly extend bytevector capacity.
ByteVec_t *new_BV();


// Allocates a bytevector of specified capacity
// - Setting zero capacity does not allocate any storage.
ByteVec_t *allocate_BV(int capacity);


// Deallocates bytevector
// - if the given bytevector contains foreign data, this returns the data pointer.
// - Otherwise, returns NULL.
// - the bytevector is recycled (with attached zeroed memory) into a allocation structure.
Byte_t *deallocate_BV(ByteVec_t *vec);


// Resets the given bytevector to empty state (i.e. zero length)
// - does not remove non-foreign allocated memory - instead this is zeroed.
// - if bytevector contains foreign data, then the pointer is returned,
//   and the state of the bytevector is reset to non-foreign.
// - resets the appendOnly attribute to FALSE
Byte_t *reset_BV(ByteVec_t *vec);
Byte_t *wipe_BV(ByteVec_t *vec);  // synonym for reset_BV


// gets the memory size allocated
int getCapacity_BV(ByteVec_t *vec);


// gets the data length (always less than the memory size)
size_t getLength_BV(ByteVec_t *vec);


// sets the data length
// - must remain strictly less than the capacity.
// - if bytevector is set append only, then length cannot be decreased.
void setLength_BV(ByteVec_t *vec, size_t length);


// sets the bytevector to be append only
// - once set, this attribute can only be removed by resetting the entire byte vector
void setAppendOnly_BV(ByteVec_t *vec);


// ensures that memory capacity equals or exceeds the given value.
// - if current capacity already equals or exceeds given value then no change.
// - extension involves reallocating memory.
void ensureCapacity_BV(ByteVec_t *vec, int capacity);


// indicates if given bytevector is "empty" ...
// - i.e. doesn't contain data.
Boolean_t isEmpty_BV(ByteVec_t *vec);


// exports pointer to internal data vector
// - this permits the memory to be manipulated externally (UNSAFE).
// - the external pointer returned can become stale due to further
//   extension of the bytevector.
// - use setLength to update the length ...
Byte_t *getContent_BV(ByteVec_t *vec);


// Clones source bytevector into given destination vector.
// - copies content from source to destination
// - both vectors must already exist.
// - destination must not already contain foreign data.
void clone_BV(ByteVec_t *dest, ByteVec_t *source);


// Checks that the bytevectors are equal in _value_ (on content) ...
// - Both must be equally defined i.e. both = NULL or both != NULL
// - byte comparison of content up to length
Boolean_t isEqual_BV(ByteVec_t *vec1, ByteVec_t *vec2);


// indicates if givne bytevector contains foreign data.
// - The bytevector cannot be modified or changed once it contains foreign data.
Boolean_t hasForeignData_BV(ByteVec_t *vec);


// Imports existing data (i.e. foreign pointer);
// - This data is regarded as fixed and unmodifiable.
// - As a consequence, bytevectors containing foreign data are not extendable and
//   cannot be wiped or updated.
void importForeignContent_BV(ByteVec_t *vec, int dataLen, Byte_t *data);


// loads indicated content into byte vector
// - sets bytes from data array
// - uses existing data memory in bytevector where possible,
// - otherwise, extends memory to contain additional content
void setContent_BV(ByteVec_t *vec, int dataLen, Byte_t *data);


// appends indicated content into byte vector
// - appends bytes from data array to end of bytevector
// - uses existing data memory in bytevector where possible,
// - otherwise, extends memory to contain additional content
void appendContent_BV(ByteVec_t *vec, int dataLen, Byte_t *data);


// Generate a randomised bytevector of specified length
void random_BV(ByteVec_t *vec, int dataLen);


// gets current value at given index idx
// - idx always less than current data length
Byte_t getByte_BV(ByteVec_t *vec, int idx);


// sets current value at given index idx
// - setting values can force memory extension.
void setByte_BV(ByteVec_t *vec, int idx, Byte_t newVal);


// Joins two bytevectors together as a new, freshly allocated bytevector.
ByteVec_t *join_BV(ByteVec_t *a, ByteVec_t *b);


// Joins content from two bytevectors a and b into dest bytevector
// - Uses the already allocated memory in dest.
// - Will enlarge allocated memory of dest to ensure sufficient memory ...
// - Dest bytevector must be distinct from given sources
void joinInto_BV(ByteVec_t *dest, ByteVec_t *a, ByteVec_t *b);


// Appends content from source bytevector into dest bytevector
// - Uses already allocated memory in dest
// - Will enlarge allocated memory of dest to ensure sufficient memory ...
void appendInto_BV(ByteVec_t *dest, ByteVec_t *source);


// Shows a short hex fingerprint of the bytevector
// - the output string is volatile
// - 4 <= fpLength <= 16, with default value: 7
char *showFingerprint_BV(ByteVec_t *vec, int fpLength);


// Show bytevector content
// - uses decimal repn.
char *show_BV(ByteVec_t *vec, int width, char *indent);


// Show bytevector content
// - uses hex repn.
char *showHex_BV(ByteVec_t *vec, int width, char *indent);


#endif
