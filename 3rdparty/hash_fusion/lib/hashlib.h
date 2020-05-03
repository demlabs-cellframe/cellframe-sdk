#ifndef __HASHLIB_H__
#define __HASHLIB_H__

/*******************************************************************************
   hashlib.h

   Some management wrappers for OpenSSL
   - Uses OpenSSL libraries to provide standard hash functions

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
#include "bytevector.h"

// Hash digest objects ...
typedef struct hashDigest Digest_t;

// Hash spec codes ...
// - Note: size of digest is encoded: (HSP_SHA384 % 1000) == 384 bits
typedef  enum {
      HSP_NULL       =  1110000,   // Represents null/undefined hashspec
      HSP_SHA224     =  1110224,   // Represents sha 224
      HSP_SHA256     =  1110256,   // Represents sha 256
      HSP_SHA384     =  1110384,   // Represents sha 384
      HSP_SHA512     =  1110512,   // Represents sha 512
      HSP_RIPEMD160  =  1111160    // Represents ripemd 160
   }
   HashSpec_t;


// Hash operations state
// - The std operations cycle is:  ready->init->proc->...->final
// - There is also an error state - which can only be cleared by reset_DG.
typedef enum {
      HST_READY = 60,  // Ready (default) state
      HST_INIT,        // Digest initialised
      HST_PROCESS,     // Digest in process
      HST_FINAL,       // Digest finalised - hash-value available.
      HST_ERROR        // Error state ... digest needs reset ...
   }
   Hashstate_t;


// Maximum Digest Size (in bytes)
// - larger than that specified by OpenSSL
#define MAX_DIGEST_SIZE   128


// Allocates a hash digest object
Digest_t *new_DG(HashSpec_t hSpec);


// Deallocates hash digest object
void deallocate_DG(Digest_t *dgst);


// Resets hash digest object
// - No allocation performed ...
// - Results in a digest object in ready state.
// - If hSpec = 0, reuse existing hSpec value.
void reset_DG(Digest_t *dgst, HashSpec_t hSpec);


// Gets the number of bytes hashed so far.
int getBytesHashed_DG(Digest_t *dgst);


// Gets the current hash spec value.
HashSpec_t getHashSpec_DG(Digest_t *dgst);


// Extracts nominal string of the hash spec value
const char *showHashSpec_DG(HashSpec_t hSpec);


// Digest length (in bytes)
int getDigestLength_DG(HashSpec_t hSpec);


// Checks that the digests are equal in value ...
// - Both must be equally defined i.e. both = NULL or both != NULL
Boolean_t isEqual_DG(Digest_t *dgst1, Digest_t *dgst2);


// Clones a digest value from source digest to destination digest.
// - the source digest state should be final.
// - Destination digest state becomes final.
// - Result is false if no data transferred - otherwise true.
Boolean_t clone_DG(Digest_t *dest, Digest_t *source);


// Extracts the (binary) hash value from the current digest and appends to the given bytevector ...
// - The digest must have already been finalised.
// - The result is TRUE if the digest hash value was appended.
Boolean_t getHashValue_DG(Digest_t *dgst, ByteVec_t *resultBV);


// Sets the (binary) hash value of the digest from the given bytevector ...
// - The length of the (binary) data must exactly match the required digest size.
// - THe digest state should be Ready or Init
// - If successful, the digest state becomes Final.
// - The result is TRUE only if the digest hash value was successfully set.
Boolean_t setHashValue_DG(Digest_t *dgst, ByteVec_t *sourceBV);

// Extracts a hex string of the hash value
// - the output string is volatile
char *showHexHashValue_DG(Digest_t *dgst);


// Shows a short fingerprint of the hash value
// - the output string is volatile
// - 4 <= fpLength <= 16, with default value: 7
char *showFingerprint_DG(Digest_t *dgst, int fpLength);


// Extracts the current state
// - getHashState_DG produces current state value
// - showHashState_DG produces a print string
Hashstate_t getHashState_DG(Digest_t *dgst);
char *showHashState_DG(Digest_t *dgst);


// Hash an entire byte vector in a single step.
// - The digest state should be ready.
// - Hashes the input data and computes the final hashvalue
// - The hashValue is placed into the Digest_t object.
// - The result indicates if the hash operation was successful.
//   + If successful, the hash state becomes HST_FINAL.
//   + Otherwise, remains unchanged.
Boolean_t hashBV_DG(Digest_t *dgst, ByteVec_t *dataInput);


/*******************************************************************************
   Hashing sequences of data blocks ...
   - The data blocks are themselves wrapped within bytevectors.
*******************************************************************************/

// Initialise the Digest_t object ready to hash a sequence of data blocks.
// - the hashstate starts in HST_READY and ends in HST_INIT
Boolean_t hashInit_DG(Digest_t *dgst);


// Add a data block byte vector to current digest.
// - The hashstate starts in either state HST_INIT or HST_PROCESS and transitions to HST_PROCESS
Boolean_t addOneBlock_DG(Digest_t *dgst, ByteVec_t *dataInput);


// Hash a given sequence of data blocks, where each block is contained in a bytevector.
// - The hashstate starts in either state HST_INIT or HST_PROCESS and transitions to HST_PROCESS
Boolean_t hashBlocks_DG(Digest_t *dgst, int length, ByteVec_t *blocks[]);


// Finalise the current sequence ...
// - The final hash-value is computed.
// - The hashstate should be HST_PROCESS or HST_FINAL  and transitions t0 HST_FINAL.
Boolean_t hashFinal_DG(Digest_t *dgst);


#endif
