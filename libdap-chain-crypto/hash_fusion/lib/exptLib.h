#ifndef __EXPT_LIB_H__
#define __EXPT_LIB_H__

#include "utils.h"


/*******************************************************************************
  exptLib.h

  Experimental framework

  - Managing key identifiers (as numbers)

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

#define MAX_KEYS       10000
#define MAX_KEY_VALUE  100000


/*******************************************************************************
  Key Management Methods
*******************************************************************************/

// Generate a fresh randomly generated key
Key_t freshKey();

// Add value to the store
void addValue(Key_t key, void *value);

// Checks if key currently allocated/in use
Boolean_t allocatedKey(Key_t key);

// Gets a randomly selected registered key - and then unregisters it from the key index
Key_t getKey();

// Fetch associated value ...
void *fetchValue(Key_t key);

// Registers a key as being in use ...
// - return TRUE if registration was OK.
Boolean_t registerKey(Key_t key);

// Unregisters a key as being in use ...
// - return TRUE if deregistration was OK.
Boolean_t unregisterKey(Key_t key);

// Number of keys in use
int getKeysInUse();

#endif
