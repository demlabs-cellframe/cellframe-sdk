/*******************************************************************************
  exptLib.c

  Experimental management framework utilities

  - Managing key identifiers (numbers)

  - Managing values

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

#include "exptLib.h"
#include "random.h"


/*******************************************************************************
  Variables and Arrays
*******************************************************************************/

static Boolean_t seenKey[MAX_KEY_VALUE];  // 0 .. MAX_KEY_VALUE - with valid keys being 1 .. MAX_KEY_VALUE
static Key_t keyIndex[MAX_KEYS];

// Invariant: availKeys + numKeys == MAX_KEYS
static int availKeys = MAX_KEYS;          // 1 .. MAX_KEYS   -- number of available keys
static int numKeys   = 0;                 // number of keys in use

// object map
static void *objIndex[MAX_KEY_VALUE];     // Object mapping


/*******************************************************************************
  Methods
*******************************************************************************/

// generate new key
Key_t freshKey() {
   if (availKeys <= 0) return NULL_KEY;

   int possKey  =  nextRandom_Range(1, MAX_KEY_VALUE);

   int key = 0;

   // scan keys to find the next available
   for (int i=1; i <= MAX_KEY_VALUE; i++) {
      if (!seenKey[possKey]) {
         key = possKey;

         registerKey(key);

         return key;
      }

      // increment possKey
      possKey += 1;
      if (possKey > MAX_KEY_VALUE) possKey = 1;
   }

   return NULL_KEY;
}


// gets a randomly selected registered key - and then unregistering it from the key index
Key_t getKey() {

  if (numKeys <= 0) return NULL_KEY;

  int index = nextRandom_Range(0, numKeys-1);

  Key_t key = keyIndex[index];

  seenKey[key] = FALSE;

  if (numKeys > 0) {

     numKeys -= 1;
     availKeys += 1;

     keyIndex[index] = keyIndex[numKeys];
     keyIndex[numKeys] = NULL_KEY;
  }
  else {
     numKeys = 0;
     availKeys = MAX_KEYS;
  }

  return key;
}


// Add value to the store
void addValue(Key_t key, void *value) {
   if (key < 1 || key > MAX_KEY_VALUE) return;

   objIndex[key] = value;
}


// checks if key currently allocated/in use
Boolean_t allocatedKey(Key_t key) {
   if (key < 1 || key > MAX_KEY_VALUE) return FALSE;
   return seenKey[key];
}


// Fetch associated value ...
void *fetchValue(Key_t key) {
   if (key < 1 || key > MAX_KEY_VALUE) return NULL;
   return objIndex[key];
}


// Registers a key as being in use ...
// - return TRUE if registration was OK.
Boolean_t registerKey(Key_t key) {
   if (availKeys <= 0) return FALSE;
   if (key < 1 || key > MAX_KEY_VALUE) return FALSE;
   if (seenKey[key]) return FALSE;

   // selecting key
   seenKey[key] = TRUE;
   keyIndex[numKeys] = key;

   availKeys -= 1;
   numKeys    += 1;

   return TRUE;
}


// Unregisters a key as being in use ...
// - return TRUE if deregistration was OK.
Boolean_t unregisterKey(Key_t key) {
   if (numKeys < 1) return FALSE;
   if (key < 1 || key > MAX_KEY_VALUE) return FALSE;
   if (!seenKey[key]) return FALSE;

   // deselecting key
   availKeys  += 1; // increase number of keys
   numKeys    -= 1; // decrease the number of used keys

   Key_t lastKey = keyIndex[numKeys];

   // mark key as not seen
   seenKey[key] = FALSE;

   // locate index for key ...
   int index = 0;
   while (keyIndex[index] != key) {
      index += 1;
      if (index >= MAX_KEYS) return TRUE;
   }

   keyIndex[index]   = lastKey;
   keyIndex[numKeys] = NULL_KEY;

   return TRUE;
}


int getKeysInUse() {
   return numKeys;
}
