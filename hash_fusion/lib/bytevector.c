/*******************************************************************************
   bytevector.c

   Basic bytevectors ...
   - data length is always less than memory available (capacity), unless both are zero.

     The key invariant is:
        (length == 0 && capacity == 0) || (0 <= length < capacity)

   Bytevectors support foreign data pointers;
   - foreign data is treated as immutable.
   - However, data content pointer can be exported
     - This enables unmanaged data access/update of content.

   Bytevectors can be set to "append only"
   - resetting will

   Bytevectors are allocated via free-list ...

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
#include "random.h"

#include "bytevector.h"


// The bytevector structure ...
struct bytevector {
   int        capacity;   // amount of memory available.
   size_t     length;     // extent of data in use.
   Boolean_t  appendOnly; // indicates append-only.
   Boolean_t  isForeign;  // indicates if pointer is foreign (if so, then the data is internally immutable.)
   Byte_t     *content;   // content pointer
};


// Bytevector Memory Management
MemMgr_t *bytevecMemMgmt = NULL;


// static method prototypes
static void ensureMemMgmt();
static void dispose_BV(void *obj);
static void addContent(ByteVec_t *vec, int dataLen, Byte_t *data);


// Allocates a standard size bytevector (with default capacity)
ByteVec_t *new_BV() {
   return allocate_BV(DEFAULT_BYTEVECTOR_CAPACITY);
}

// Allocates a bytevector of specified capacity
// - Setting zero capacity does not allocate any storage.
ByteVec_t *allocate_BV(int capacity) {

   // ensure the allocation structure is initialised
   ensureMemMgmt();

   // Gets allocated result ...
   ByteVec_t *result = allocateObject_MM(bytevecMemMgmt);

   if (result->capacity == 0) {
      // allocated object has no attached content memory ...
      // - this is also the case if the object were freshly allocated and not recycled.
		if (capacity == 0) {
		   // empty bytevector
		   // - no storage allocated ...
		   result->capacity = 0;
		   result->length  = 0;
		   result->appendOnly = FALSE;
		   result->isForeign = FALSE;
		   result->content = NULL;
		}
		else {
		   // non-empty bytevector - of zero length
		   result->capacity = capacity;
		   result->length  = 0;
		   result->appendOnly = FALSE;
		   result->isForeign = FALSE;
		   result->content = ALLOC_BLK(result->capacity);  // guaranteed zero'd
		}
   }
   else {
      // allocated result has attached memory ... (i.e. recycled)
      // - attached memory was scrubbed at deallocation time
		ensureCapacity_BV(result, capacity);

		// set attributes
		result->capacity = capacity;
		result->length  = 0;
		result->appendOnly = FALSE;
		result->isForeign = FALSE;
   }

   return result;
}


// Deallocates bytevector
// - if the given bytevector contains foreign data, this returns the data content pointer.
// - Otherwise, returns NULL.
// - the bytevector is recycled (with attached memory already zeroed) for reuse.
Byte_t *deallocate_BV(ByteVec_t *vec) {
   if (vec == NULL) {
      return NULL;
   }

   Byte_t *result = NULL;

   if (vec->isForeign) {
      // export the content
      result = vec->content;

      // decouple foreign content from bytevector
      vec->capacity = 0;
      vec->content = NULL;
   }
   else if (vec->capacity > 0) {
      // scrub the attached memory ...
      NULLIFY(vec->content, vec->capacity);
   }

   // reset the object
   vec->length  = 0;
	vec->appendOnly = FALSE;
   vec->isForeign = FALSE;

   // ensure the allocation structure is initialised
   ensureMemMgmt();

   // Now recycle the bytevector itself
   // - by adding it to the bytevector allocation structure ...
   deallocateObject_MM(bytevecMemMgmt, sizeof(ByteVec_t), (void *)vec);

   return result;
}


// Resets the given bytevector to empty state (i.e. zero length)
// - does not remove non-foreign allocated memory - instead this is zeroed.
// - if bytevector contains foreign data, then the pointer is returned,
//   and the state of the bytevector is reset to non-foreign.
// - resets the appendOnly attribute to FALSE
Byte_t *reset_BV(ByteVec_t *vec) {
   req_NonNull(vec);

   // this is used to report any foreign pointer ...
   Byte_t *foreignPtr = NULL;

   // sets the length to zero ...
   vec->length = 0;

   // always set the appendOnly attribute to false
   // - if append only semantics is required, this must be set again
   //   following any reset.
   vec->appendOnly = FALSE;

   // Process foreign vectors
   if (vec->isForeign) {
      // return foreign content pointer
      foreignPtr = vec->content;

      // Now set vec to empty
      vec->capacity = 0;       // no capacity
      vec->isForeign = FALSE;  // vec is no longer foreign
      vec->content = NULL;     // no memory
   }
   else if (vec->capacity > 0) {
      // fill content with zero ...
      NULLIFY(vec->content, vec->capacity);
   }

   // return any foreign pointer
   return foreignPtr;
}

// synonym for reset_BV ...
Byte_t *wipe_BV(ByteVec_t *vec) {
   return reset_BV(vec);
}


int getCapacity_BV(ByteVec_t *vec) {
   req_NonNull(vec);
   return vec->capacity;
}


size_t getLength_BV(ByteVec_t *vec) {
   req_NonNull(vec);
   return vec->length;
}

void setLength_BV(ByteVec_t *vec, size_t length) {
   req_NonNull(vec);

   if (vec->isForeign) {
      // For foreign data, assert the capacity according to given length.
      vec->capacity = length +1;
   }
   else if (vec->appendOnly && length < vec->length) {
      diagnostic("setLength_BV: Bytevector is set to append only - cannot reduce length from %i to smaller length %i"
                , length
                , vec->length);
      error_exit();
   }
   else if (vec->capacity <= length) {
      diagnostic("setLength_BV: new length (%i) exceeds or equals capacity (%i)", length, vec->capacity);
      error_exit();
   }

   vec->length = length;
}


// sets the bytevector to be append only
// - once set, this attribute can only be removed by resetting the entire byte vector using reset_BV
void setAppendOnly_BV(ByteVec_t *vec) {
   req_NonNull(vec);

   vec->appendOnly  =  TRUE;
}


Boolean_t isEmpty_BV(ByteVec_t *vec) {
   req_NonNull(vec);

   return (vec->length == 0 || vec->content == NULL);
}


Byte_t *getContent_BV(ByteVec_t *vec) {
   req_NonNull(vec);

   return vec->content;
}


Boolean_t hasForeignData_BV(ByteVec_t *vec) {
   req_NonNull(vec);
   return vec->isForeign;
}


// Imports existing data (i.e. foreign pointer);
// - This data is regarded as fixed and unmodifiable.
// - As a consequence, bytevectors containing foreign data are not extendable and
//   cannot be wiped or updated.
void importForeignContent_BV(ByteVec_t *vec, int dataLen, Byte_t *foreignData) {
   req_NonNull(vec);

   if (vec->isForeign) {
      diagnostic("bytevector.importForeignContent_BV: Bytevector already contains foreign data - and cannot be extended.");
      codeError_exit();
   }

   if (foreignData == NULL && dataLen > 0) {
      diagnostic("bytevector.importForeignContent_BV: Inconsistent content assignment (content = NULL, but length > 0)");
      codeError_exit();
   }

   // release any existing data
   free(vec->content);

   // update bytevector's attributes
   vec->length = dataLen;
   vec->capacity = dataLen + 1;
   vec->isForeign = TRUE;
   vec->content = foreignData;
}


// loads indicated content into byte vector
// - sets bytes from data array
// - uses existing data memory in bytevector where possible,
// - otherwise, extends memory to contain additional content
void setContent_BV(ByteVec_t *vec, int dataLen, Byte_t *data) {
   req_NonNull(vec);

   if (vec->isForeign) {
      diagnostic("bytevector.setContent_BV: Bytevector contains foreign data - and cannot be extended.");
      codeError_exit();
   }

   if (data == NULL && dataLen > 0) {
      diagnostic("bytevector.setContent_BV: Inconsistent content assignment (content = NULL, but length > 0)");
      codeError_exit();
   }

   if (vec->appendOnly) {
      diagnostic("bytevector.setContent_BV: Bytevector set to append only - cannot set the content arbitrarily.");
      codeError_exit();
   }

   // reset te bytevector ...
   // - ensures that previous data gets zero'ed.
   reset_BV(vec);

   // now add the content ...
   addContent(vec, dataLen, data);
}

// appends indicated content into byte vector
// - appends bytes from data array to end of bytevector
// - uses existing data memory in bytevector where possible,
// - otherwise, extends memory to contain additional content
void appendContent_BV(ByteVec_t *vec, int dataLen, Byte_t *data) {
   req_NonNull(vec);

   if (vec->isForeign) {
      diagnostic("bytevector.appendContent_BV: Bytevector contains foreign data - and cannot be extended.");
      codeError_exit();
   }

   if (data == NULL && dataLen > 0) {
      diagnostic("bytevector.appendContent_BV: Inconsistent content assignment (content = NULL, but length > 0)");
      codeError_exit();
   }

   // now add the content ...
   addContent(vec, dataLen, data);
}


// Internal operation to add data
static void addContent(ByteVec_t *vec, int dataLen, Byte_t *data) {

   int vecDataLen = vec->length;           // current data length
   int newDataLen = vecDataLen + dataLen;  // updated data length

   if (newDataLen >= vec->capacity) {
      ensureCapacity_BV(vec, newDataLen+1);  // guarantees that newDataLen < new capacity of vec
   }

   // copy any new data into vector
   if (dataLen > 0) {
      memcpy(vec->content + vecDataLen, data, dataLen);
   }

   // record new data length.
   vec->length = newDataLen;

   // ensures that sentinel byte is 0 (i.e. safe for C-strings)
   vec->content[newDataLen] = 0;
}


void ensureCapacity_BV(ByteVec_t *vec, int capacity) {

   req_NonNull(vec);
   req_PosZero(capacity);

   // return if capacity requested is zero ...
   if (capacity == 0) return;

   if (vec->isForeign) {
      diagnostic("bytevector.ensureCapacity_BV: Bytevector contains foreign data - and cannot be extended.");
      codeError_exit();
   }

   int    vecCapacity  = vec->capacity;
   Byte_t *vecContent  = vec->content;
   size_t vecLength    = vec->length;

   // check if extra capacity needed ...
   if (capacity <= vecCapacity) {
      return;
   }

   // needs some extra memory ...
   int newCapacity = capacity + vecCapacity;
   Byte_t *newContent = (Byte_t *)ALLOC_BLK(newCapacity);
   //Byte_t *newContent = (Byte_t *)REALLOC_BLK(vecContent, newCapacity);   // using this caused data corruption to vec->length (!!)

   if (vecLength > 0) {
      // copying previous content into new memory ...
      memcpy(newContent, vecContent, vecLength);
   }

   // update vec ...
   vec->capacity   = newCapacity;
   vec->content    = newContent;
   vec->length     = vecLength;

   // free previous memory
   free(vecContent);
}


// Clones source bytevector into given destination vector.
// - copies content from source to destination
// - both vectors must already exist.
// - destination must not already contain foreign data.
void clone_BV(ByteVec_t *dest, ByteVec_t *source) {
   req_NonNull(dest);
   req_NonNull(source);

   if (dest->isForeign) {
      diagnostic("bytevector.clone_BV: Destination bytevector contains foreign data - and cannot be modified/extended.");
      codeError_exit();
   }

   int dataLen = source->length;

   // ensure sufficient capacity to contain the data in the source.
   ensureCapacity_BV(dest, dataLen+1);

   if (dataLen > 0) {
      // copy source data into the destination ...
      memcpy(dest->content, source->content, dataLen);
   }

   // update the length of the destination ...
   dest->length = dataLen;
}


// Checks that the bytevectors are equal in _value_ (on content) ...
// - Both must be equally defined i.e. both = NULL or both != NULL
// - byte comparison of content up to length
Boolean_t isEqual_BV(ByteVec_t *vec1, ByteVec_t *vec2) {
   if (vec1 == NULL) {
      return (vec2 == NULL);
   }
   else if (vec2 == NULL) {
      // i.e. vec1 != NULL and vec2 == NULL
      return FALSE;
   }

   // Know here that: vec1 != NULL and vec2 != NULL

   // check length of content
   int vecLen1 = vec1->length;
   int vecLen2 = vec2->length;

   if (vecLen1 != vecLen2) {
      // vec1 and vec2 have different lengths
      return FALSE;
   }

   // compare memory
   return asBoolean(memcmp(vec1->content, vec2->content, vecLen1) == 0);
}


// Generate a randomised bytevector of specified length
void random_BV(ByteVec_t *vec, int dataLen) {
   req_NonNull(vec);
   req_PosZero(dataLen);

   // check for foreign data
   if (vec->isForeign) {
      diagnostic("bytevector.random_BV: Destination bytevector contains foreign data - and cannot be modified.");
      codeError_exit();
   }

   // ensure the capacity ...
   ensureCapacity_BV(vec, dataLen+1);

   Byte_t *arr = vec->content;
   for (int i = 0; i < dataLen; i++) {
      arr[i] = nextRandom_BYTE();
   }

   // set the length
   vec->length = dataLen;
}


Byte_t getByte_BV(ByteVec_t *vec, int i) {
   req_NonNull(vec);
   req_NonNull(vec->content);

   req_LE(0, i);
   req_LT(i, vec->length);

   return (vec->content)[i];
}


void setByte_BV(ByteVec_t *vec, int idx, Byte_t newVal) {
   req_NonNull(vec);
   req_LE(0, idx);

   if (vec->isForeign) {
      diagnostic("bytevector.setByte_BV: Bytevector contains foreign data - and cannot be modified.");
      codeError_exit();
   }

   if (vec->appendOnly) {
      diagnostic("bytevector.setByte_BV: Bytevector set to append only - no arbitrart modification.");
      codeError_exit();
   }

   // check if update requires memory expansion.
   if (vec->length <= idx) {
      int newLength = idx+1;
      int newCapacity = newLength+1;
      ensureCapacity_BV(vec, newCapacity); // expand memory to include index ...
      vec->length = newLength;           // make length = one greater than index
   }

   // sets content at index to newVal
   (vec->content)[idx] = newVal;
}


// Joins two bytevectors together as a new, freshly allocated bytevector.
ByteVec_t *join_BV(ByteVec_t *a, ByteVec_t *b) {
   req_NonNull(a);
   req_NonNull(b);

   int aDataLen = a->length;
   int bDataLen = b->length;

   int newDataLen = aDataLen + bDataLen;
   int newCapacity = newDataLen + 1;

   ByteVec_t *result = allocate_BV(newCapacity);

   Byte_t *data = result->content;

   // copy the data ...
   if (aDataLen > 0) {
      memcpy(data, a->content, aDataLen);
   }

   if (bDataLen > 0) {
      memcpy(data+aDataLen, b->content, bDataLen);
   }

   // update the length of the result ...
   result->length  = newDataLen;

   return result;
}


void joinInto_BV(ByteVec_t *dest, ByteVec_t *a, ByteVec_t *b) {
   req_NonNull(a);
   req_NonNull(b);
   req_Distinct(a, dest);
   req_Distinct(b, dest);
   req_NonNull(dest);

   // clear the existing content in dest
   wipe_BV(dest);

   appendContent_BV(dest, a->length, a->content);
   appendContent_BV(dest, b->length, b->content);
}


void appendInto_BV(ByteVec_t *dest, ByteVec_t *source) {

   req_NonNull(source);
   req_NonNull(dest);
   req_Distinct(source, dest);

   if (dest->isForeign) {
      diagnostic("bytevector.appendInto_BV: Destination bytevector contains foreign data - and cannot be modified.");
      codeError_exit();
   }

   appendContent_BV(dest, source->length, source->content);
}


/*******************************************************************************
   Fingerprinting
*******************************************************************************/
// Extracts a short fingerprint of the bytevector
// - the output string is volatile
// - 4 <= fpLength <= 16, with default value: 7
static char fpBuf[LINE_BUFSIZE+1];
static int DEFAULT_FP_LENGTH = 7;
char *showFingerprint_BV(ByteVec_t *vec, int fpLength) {
   if (vec == NULL) return NULL_STR;

   char *sPtr = fpBuf;
   Byte_t *bytes = vec->content;

   if (bytes == NULL) return NULL_STR;

   // constrain the fpLength
   fpLength = (fpLength <= 0 ? DEFAULT_FP_LENGTH : fpLength);
   fpLength = minmax(4, fpLength, 16);
   fpLength = min(fpLength, vec->length);

   // pack content as hex into hashBuffer
   int sz = 0;
   char *sep = "";
   for(int i = 0; i < fpLength; i++) {
      sz = sprintf(sPtr, "%s%02x", sep, bytes[i]);
      sPtr += sz;
      sep = ":";
   }

   sprintf(sPtr, " ... [%lu bytes]", vec->length);

   return fpBuf;
}


/*******************************************************************************
   Show methods
*******************************************************************************/
static ByteVec_t *showBuffer = NULL;

// local prototypes
static char *auxShow_BV(ByteVec_t *vec, const char *fmt, int width, char *indent);


// Show bytevector
// - uses decimal repn.
char *show_BV(ByteVec_t *vec, int width, char *indent) {
   return auxShow_BV(vec, "%3i ", width, indent);
}

// Show bytevector
// - uses hex repn.
char *showHex_BV(ByteVec_t *vec, int width, char *indent) {
   return auxShow_BV(vec, "%02x ", width, indent);
}


static char *auxShow_BV(ByteVec_t *vec, const char *fmt, int width, char *indent) {
   req_NonNull(vec);
   req_NonEmptyStr((char *)fmt);

   // ensure that indent is a string ...
   indent = (isa_Null(indent) ?  "   " :  indent);

   // ensure that width is at least 5 items wide
   width = max(width, 5);

   // current byte
   Byte_t curByte = 0;

   // lengths
   int indentLen  = strlen(indent);
   int vecLen     = vec->length;

   // display characteristics
   int linecount = 0;
   int widthcount = 0;

   // local string buffer
   char strBuf[17];  // fmt must define strings that are less than 16 chars in width
   int bufSz = 0;    // number of chars in strBuf

   // initialise showBuffer
   if (showBuffer == NULL) {
      int allocation = max(DEFAULT_BYTEVECTOR_CAPACITY, 10 * (vec->length));
      showBuffer = allocate_BV(allocation);
   }
   else {
      reset_BV(showBuffer);
   }

   // add content to showBuffer
   // - this will automatically extend as needed ...
   for (int i=0; i < vecLen; i++) {
      if (widthcount == 0) {
         appendContent_BV(showBuffer, indentLen, (Byte_t *)indent);
      }

      curByte = getByte_BV(vec, i);
      bufSz   = sprintf(strBuf, fmt, curByte);

      // add content to showBuffer
      appendContent_BV(showBuffer, bufSz, (Byte_t *)strBuf);

      widthcount += 1;
      if (widthcount >= width) {
         widthcount = 0;
         linecount += 1;
         appendContent_BV(showBuffer, 1, (Byte_t *)"\n");

         if (linecount >= 10) {
            appendContent_BV(showBuffer, 1, (Byte_t *)"\n");
         }
      }
   }

   if (widthcount != 0) {
      // add a newline to terminate current line
      appendContent_BV(showBuffer, 1, (Byte_t *)"\n");
   }

   return (char *)showBuffer->content;
}


/*******************************************************************************
   Static Methods
*******************************************************************************/

// Initialisation of allocation structure
static void ensureMemMgmt() {
	if (bytevecMemMgmt == NULL) {
      bytevecMemMgmt = new_MM(sizeof(ByteVec_t));
      setFinaliser_MM(bytevecMemMgmt, dispose_BV);
   }
}

// Disposal of bytevector object ...
static void dispose_BV(void *obj) {
   if (obj == NULL) return;

   ByteVec_t *vec = (ByteVec_t *)obj;

   // First free the content ...
   free(vec->content);

   // Now free the bytevector structure itself ...
   free(vec);
}
