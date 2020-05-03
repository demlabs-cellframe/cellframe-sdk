/*******************************************************************************
   hashlib.c

   Management wrappers for OpenSSL
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
#include <openssl/evp.h>

#include "utils.h"
#include "bytevector.h"
#include "stringbuffer.h"
#include "alloc.h"

#include "hashlib.h"


/*******************************************************************************
   Hash Digest
*******************************************************************************/
// The hashDigest object (Digest_t) encapsulates all infomation needed to coordinate
// hashing operations.
struct hashDigest {
   ByteVec_t       *result;      // Resulting hash-digest (as a bytevector)
   int              bytesHashed; // Number of bytes hashed
   HashSpec_t       hashSpec;    // Hash specification - e.g. sha256 etc.
   Hashstate_t      hashState;   // Phase of hash operations.

   // OpenSSL components
   const EVP_MD  *md;            // Internal OpenSSL message digest specifier
   EVP_MD_CTX    *mdctx;         // Internal OpenSSL message digest content
};


// Static method prototypes
static unsigned int digestBytes(const EVP_MD *md, int length, Byte_t *bytes, Byte_t *digest);
static EVP_MD_CTX *contextInit(const EVP_MD *md);
static Boolean_t processBlock(EVP_MD_CTX *mdctx, int length, Byte_t *bytes);
static unsigned int digestFinal(EVP_MD_CTX *mdctx, Byte_t *digest);

static Boolean_t isHashSpec(HashSpec_t hSpec);

static const EVP_MD *getMD(HashSpec_t hSpec);
static void ensureMemMgmt();
static void dispose_DG(void *obj);


// hashDigest Memory Management
MemMgr_t *hashDigest_MemMgr = NULL;


// Allocates a hash digest object
Digest_t *new_DG(HashSpec_t hSpec) {
   if (!isHashSpec(hSpec)) {
      diagnostic("hashlib.new_DG: Expected a HashSpec value - instead, got (%i)", hSpec);
      codeError_exit();
   }

	// Ensure that the allocation structure has been setup.
	ensureMemMgmt();

	// allocate digest object
	Digest_t *dgst = allocateObject_MM(hashDigest_MemMgr);

	dgst->result = allocate_BV(0);  // allocate byte vector (no local memory)
	dgst->bytesHashed = 0;
	dgst->hashSpec = hSpec;
	dgst->hashState = HST_READY;

	dgst->md = getMD(hSpec);  // message digest info. corresponding to hSpec
	dgst->mdctx = NULL;       // message digest context

   // return allocated digest object
   return dgst;
}


// Deallocates hash digest object
void deallocate_DG(Digest_t *dgst) {
	if (dgst == NULL) return;

	// Ensure that the allocation structure has been setup.
	ensureMemMgmt();

	// deallocate the byte vector ...
	deallocate_BV(dgst->result);

	// check for any EVP_MD_CTX object
   if (dgst->mdctx != NULL) {
      // releases any EVP_MD_CTX object
      EVP_MD_CTX_destroy(dgst->mdctx);
      dgst->md = NULL;
      dgst->mdctx = NULL;
   }

   // recycle the digest object on the allocation structure
   deallocateObject_MM(hashDigest_MemMgr, sizeof(Digest_t), dgst);
}


// Resets hash digest object
// - no allocation performed ...
// - results in a digest object in ready state.
// - if hSpec == 0, then reuse existing hSpec value.
void reset_DG(Digest_t *dgst, HashSpec_t hSpec) {
   req_NonNull(dgst);

   if (hSpec == 0) {
      hSpec = dgst->hashSpec;
   }

   if (!isHashSpec(hSpec)) {
      diagnostic("hashlib.new_DG: Expected a HashSpec value - instead, got (%i)", hSpec);
      codeError_exit();
   }

	// check for any EVP_MD_CTX object
   if (dgst->mdctx != NULL) {
      // releases EVP_MD_CTX object
      EVP_MD_CTX_destroy(dgst->mdctx);
      dgst->md = NULL;
      dgst->mdctx = NULL;
   }

   // reinitialise dgst
   reset_BV(dgst->result);

	dgst->bytesHashed = 0;
	dgst->hashSpec = hSpec;
	dgst->hashState = HST_READY;

	dgst->md = getMD(hSpec);  // gets the message digest info. corresponding to hSpec
	dgst->mdctx = NULL;
}


// Gets the number of bytes hashed so far
int getBytesHashed_DG(Digest_t *dgst) {
   req_NonNull(dgst);

   return dgst->bytesHashed;
}


// Gets the current hash spec value.
HashSpec_t getHashSpec_DG(Digest_t *dgst) {
   req_NonNull(dgst);

   return dgst->hashSpec;
}

// Extracts nominal string of the hash spec value
const char *showHashSpec_DG(HashSpec_t hSpec) {
   switch (hSpec) {
      case HSP_SHA224:      return "SHA-224";
      case HSP_SHA256:      return "SHA-256";
      case HSP_SHA384:      return "SHA-384";
      case HSP_SHA512:      return "SHA-512";
      case HSP_RIPEMD160:   return "RIPEMD-160";

      default:
         diagnostic("hashlib.showHashSpec_DG: Unrecognised hash-spec (%i)", hSpec);
         codeError_exit();
   }
}


// Digest length (in bytes)
int getDigestLength_DG(HashSpec_t hSpec) {
   return ((hSpec % 1000) / 8);
}


// Extracts the (binary) hash value from the current digest and appends to the given bytevector ...
// - The digest must have already been finalised.
// - The result is TRUE if the digest hash value was appended.
Boolean_t getHashValue_DG(Digest_t *dgst, ByteVec_t *resultBV) {
   req_NonNull(dgst);
   req_NonNull(resultBV);

   if (dgst->hashState != HST_FINAL) {
      return FALSE;
   }
   else {
      appendInto_BV(resultBV, dgst->result);

      return TRUE;
   }
}


// Sets the (binary) hash value of the digest from the given bytevector ...
// - The length of the (binary) data must exactly match the required digest size.
// - THe digest state should be Ready or Init
// - If successful, the digest state becomes Final.
// - The result is TRUE only if the digest hash value was successfully set.
Boolean_t setHashValue_DG(Digest_t *dgst, ByteVec_t *sourceBV) {
   req_NonNull(dgst);
   req_NonNull(sourceBV);

   int srcLength   =  getLength_BV(sourceBV);
   int digestSize  =  getDigestLength_DG(dgst->hashSpec);

   if (srcLength != digestSize) {
      diagnostic("hashlib.setHashValue_DG: Bytevector provided %i bytes, but expected %i bytes instead", srcLength, digestSize);
      codeError_exit();
   }

   if (dgst->hashState != HST_INIT && dgst->hashState != HST_READY) {

      return FALSE;
   }
   else {
      wipe_BV(dgst->result);
      appendInto_BV(dgst->result, sourceBV);

      dgst->hashState = HST_FINAL;

      return TRUE;
   }
}


// Checks that the digests are equal in value ...
// - Both must be as _equally_ defined i.e. both = NULL or both != NULL
Boolean_t isEqual_DG(Digest_t *dgst1, Digest_t *dgst2) {
   if (dgst1 == NULL) {
      return (dgst2 == NULL);
   }
   else if (dgst2 == NULL) {
      // i.e. dgst1 != NULL and dgst2 == NULL
      return FALSE;
   }

   // dgst1 != NULL and dgst2 != NULL
   return isEqual_BV(dgst1->result, dgst2->result);
}


// Clones a digest value from source digest to destination digest.
// - the source digest state should be final.
// - Destination digest state becomes final.
// - Result is false if no data transferred - otherwise true.
Boolean_t clone_DG(Digest_t *dest, Digest_t *source) {
   req_NonNull(dest);
   req_NonNull(source);

   if (source->hashState != HST_FINAL) {
      return FALSE;
   }
   else {
      clone_BV(dest->result, source->result);
      dest->hashState = HST_FINAL;
      return TRUE;
   }
}


// Extracts a hex string of the hash value
// - the output string is volatile (i.e. could change ...)
static char hashBuffer[2 * MAX_DIGEST_SIZE + 1];
char *showHexHashValue_DG(Digest_t *dgst) {
   if (dgst == NULL) return NULL_STR;

   char *sPtr = hashBuffer;

   int len       = getLength_BV(dgst->result);
   Byte_t *bytes = getContent_BV(dgst->result);

   // check for null content ...
   if (bytes == NULL) {
      return NULL_STR;
   }

   // pack content as hex into hashBuffer
   for(int i = 0; i < len; i++) {
      sprintf(sPtr, "%02x", bytes[i]);
      sPtr += 2;
   }

   return hashBuffer;
}


// Shows a short fingerprint of the hash value
// - the output string is volatile
// - 4 <= fpLength <= 16, with default value: 7
// - the output string is volatile
char *showFingerprint_DG(Digest_t *dgst, int fpLength) {
   if (dgst == NULL) return NULL_STR;

   return showFingerprint_BV(dgst->result, fpLength);
}


// Extracts the current state
// - getHashState_DG produces current state value
// - showHashState_DG produces a print string
Hashstate_t getHashState_DG(Digest_t *dgst) {
   req_NonNull(dgst);

   return dgst->hashState;
}

char *showHashState_DG(Digest_t *dgst) {
   switch (dgst->hashState) {
      case HST_READY:    return "Ready";
      case HST_INIT:     return "Initialised";
      case HST_PROCESS:  return "Processing";
      case HST_FINAL:    return "Finalised";

      default:
         return "<Unknown hash-state>";
   }
}


// Hash an entire byte vector in a single step.
// - The digest state should be ready.
// - Hashes the input data and computes the final hashvalue
// - The hashValue is placed into the Digest_t object.
// - The result indicates if the hash operation was successful.
//   + If successful, the hash state becomes HST_FINAL.
//   + Otherwise, remains unchanged.
Boolean_t hashBV_DG(Digest_t *dgst, ByteVec_t *dataInput) {

   req_NonNull(dataInput);

   Hashstate_t hState = dgst->hashState;
   if (hState != HST_READY) {
      return FALSE;
   }

   int  dataLen = getLength_BV(dataInput);
   Byte_t *data = getContent_BV(dataInput);

   // Ensure that the dgst result has sufficient space for digest result
   ensureCapacity_BV(dgst->result, MAX_DIGEST_SIZE+1);

   // calculate the hash value from given bytes ...
   int mdLen = digestBytes(dgst->md, dataLen, data, getContent_BV(dgst->result));

   if (mdLen > 0) {
      // set the length of the bytevector ...
      setLength_BV(dgst->result, mdLen);

      // set the bytesHashed to dataLen
      dgst->bytesHashed = dataLen;

      // set hashState
      dgst->hashState = HST_FINAL;
      return TRUE;
   }
   else {
      // An error occurred ...

      // Reset the digest result vector ...
      reset_BV(dgst->result);
      return FALSE;
   }
}


/*******************************************************************************
   Hashing sequences of data blocks ...
   - The data blocks are themselves wrapped within bytevectors.
   - These do not "fail"/"abort" - instead, status is reported by return value.
*******************************************************************************/

// Initialise the Digest_t object ready to hash a sequence of data blocks.
// - the hashstate starts in HST_READY and ends in HST_INIT
Boolean_t hashInit_DG(Digest_t *dgst) {
   req_NonNull(dgst);

   // check hash state  ...
   if (dgst->hashState != HST_READY) {
      return FALSE;
   }

   // create and initialise the context ...
   dgst->mdctx = contextInit(dgst->md);

   // set hash state
   dgst->hashState = HST_INIT;

   return TRUE;
}


// Add a data block byte vector to current digest.
// - The hashstate starts in either state HST_INIT or HST_PROCESS and transitions to HST_PROCESS
Boolean_t addOneBlock_DG(Digest_t *dgst, ByteVec_t *dataInput) {
   req_NonNull(dgst);
   req_NonNull(dataInput);

   // check hash state  ..
   if (dgst->hashState != HST_INIT && dgst->hashState != HST_PROCESS) {
      return FALSE;
   }

   int  dataLen = getLength_BV(dataInput);
   Byte_t *data = getContent_BV(dataInput);

   // Ensure that the dgst result has sufficient space for digest result
   ensureCapacity_BV(dgst->result, MAX_DIGEST_SIZE+1);

   // calculate the hash value ...
   int mdLen = digestBytes(dgst->md, dataLen, data, getContent_BV(dgst->result));

   if (mdLen > 0) {
      // set the length of the bytevector ...
      setLength_BV(dgst->result, mdLen);

      // add dataLen to the bytesHashed
      dgst->bytesHashed += dataLen;

      // set hashState
      dgst->hashState = HST_PROCESS;
      return TRUE;
   }
   else {
      // An error occurred ...

      // wipe the result ...
      reset_BV(dgst->result);

      return FALSE;
   }
}


// Hashes the given sequence of data blocks, where each data block is
// contained in a bytevector.
// - The hashstate starts in either state HST_INIT or HST_PROCESS and transitions to HST_PROCESS
Boolean_t hashBlocks_DG(Digest_t *dgst, int length, ByteVec_t *blocks[]) {
   req_NonNull(dgst);

   // check hash state  ...
   if (dgst->hashState != HST_INIT && dgst->hashState != HST_PROCESS) {
      return FALSE;
   }

   ByteVec_t *curVec = NULL;
   int dataLen = 0;

   for (int i = 0; i<length; i++) {
      curVec = blocks[i];

      if (curVec != NULL) {
         dataLen = getLength_BV(curVec);

         if (dataLen > 0) {
            if (processBlock(dgst->mdctx, dataLen, getContent_BV(curVec))) {
               dgst->bytesHashed += dataLen;
            }
            else {

            }
         }
      }
   }

   // set hash state
   dgst->hashState = HST_PROCESS;

   return TRUE;
}

// Finalise the current sequence ...
// - The final hash-value is computed.
// - The hashstate should be HST_PROCESS and transitions to HST_FINAL.
Boolean_t hashFinal_DG(Digest_t *dgst) {
   req_NonNull(dgst);

   if (dgst->hashState == HST_FINAL) {
      return TRUE;
   }

   // check hash state  ...
   if (dgst->hashState != HST_PROCESS) {
      return FALSE;
   }

   // extract the hash value ...
   int mdLen = digestFinal(dgst->mdctx, getContent_BV(dgst->result));

   if (mdLen > 0) {
      // set the length of the bytevector ...
      setLength_BV(dgst->result, mdLen);

      // set hashState
      dgst->hashState = HST_FINAL;
      return TRUE;
   }
   else {
      // An error occurred ...

      // wipe the result ...
      reset_BV(dgst->result);

      // set hashState
      dgst->hashState = HST_FINAL;

      return FALSE;
   }
}


/*******************************************************************************l
   Wrappers for standard hash digest calc. using OpenSSL digest algorithms
*******************************************************************************/

// Single-shot hashing of a single block of data
static unsigned int digestBytes(const EVP_MD *md, int length, Byte_t *bytes, Byte_t *digest) {
   req_NonNull(digest);

   EVP_MD_CTX *mdctx = contextInit(md);

   // Hash the data ...
   if (1 != EVP_DigestUpdate(mdctx, bytes, length)) {
      EVP_MD_CTX_destroy(mdctx);

      // ensure safe digest value
      digest[0] = 0;
      return 0;
   }

   return digestFinal(mdctx, digest);
}


// Generate and initialise the digest
static EVP_MD_CTX *contextInit(const EVP_MD *md) {
   EVP_MD_CTX *mdctx;

   // Set up digest context
   mdctx = EVP_MD_CTX_create();

   // Bind message digest to context
   EVP_DigestInit_ex(mdctx, md, NULL);

   // return the context
   return mdctx;
}


static Boolean_t processBlock(EVP_MD_CTX *mdctx, int length, Byte_t *bytes) {
   return asBoolean( EVP_DigestUpdate(mdctx, bytes, length) );
}


static unsigned int digestFinal(EVP_MD_CTX *mdctx, Byte_t *digest) {
   unsigned int md_len = 0;

   // Finalise
   EVP_DigestFinal_ex(mdctx, digest, &md_len);
   EVP_MD_CTX_destroy(mdctx);

   // return the length
   return md_len;
}


/*******************************************************************************
   Auxilliaries
*******************************************************************************/
static Boolean_t isHashSpec(HashSpec_t hSpec) {
   switch (hSpec) {
      case HSP_SHA224:      // FALLTHROUGH
      case HSP_SHA256:      // FALLTHROUGH
      case HSP_SHA384:      // FALLTHROUGH
      case HSP_SHA512:      // FALLTHROUGH
      case HSP_RIPEMD160:   return TRUE;

      default:
         return FALSE;
   }
}


static const EVP_MD *getMD(HashSpec_t hSpec) {
   switch (hSpec) {
      case HSP_SHA224:      return EVP_sha224();
      case HSP_SHA256:      return EVP_sha256();
      case HSP_SHA384:      return EVP_sha384();
      case HSP_SHA512:      return EVP_sha512();
      case HSP_RIPEMD160:   return EVP_ripemd160();

      default:
         diagnostic("hashlib.getMD: Unrecognised hash-spec (%i)", hSpec);
         codeError_exit();
   }
}

// setup allocation structure
static void ensureMemMgmt() {
   if (hashDigest_MemMgr == NULL) {
      hashDigest_MemMgr = new_MM(sizeof(Digest_t));
      setFinaliser_MM(hashDigest_MemMgr, dispose_DG);
   }
}

// disposal of digest memory ...
static void dispose_DG(void *obj) {
   if (obj == NULL) return;

   Digest_t *dgst = (Digest_t *)obj;

   if (dgst->mdctx != NULL) {
      // releases the EVP_MD_CTX objects
      EVP_MD_CTX_destroy(dgst->mdctx);
      dgst->mdctx = NULL;
   }

   // free the Digest_t object itself.
   free(dgst);
}


/*

//unsigned int digestBlocks(const EVP_MD *md, Byte_t *blocks[], int maxBlocks, int totalChars, Byte_t *digest);
//static int calcTotalBlocks(Byte_t *blocks[], int maxBlocks);

// Single-shot hash processing
unsigned int digestBytes(const EVP_MD *md, ByteVec_t *bytes, Byte_t *md_value) {
   EVP_MD_CTX *mdctx;
   unsigned int md_len = 0;

   // Set up context
   mdctx = EVP_MD_CTX_create();

   // Bind message digest to context
   EVP_DigestInit_ex(mdctx, md, NULL);

   // Hash the data
   EVP_DigestUpdate(mdctx, getContent_BV(bytes), getLength_BV(bytes));

   // Finalise
   EVP_DigestFinal_ex(mdctx, md_value, &md_len);
   EVP_MD_CTX_destroy(mdctx);

   return md_len;
}


// Processes a seqeunce of blocks (same size = BLOCKSIZE, except possibly the last one)
unsigned int digestBlocks(const EVP_MD *md, Byte_t *blocks[], int maxBlocks, int totalChars, Byte_t *md_value) {
   EVP_MD_CTX *mdctx;
   unsigned int md_len = 0;

   int totalBlocks = calcTotalBlocks(blocks, maxBlocks);

   size_t charsRemaining = totalChars;
   size_t thisBlkSz = 0;
   void *blockPtr  = NULL;  // current ptr to data block

   // Set up context
   mdctx = EVP_MD_CTX_create();

   // Bind message digest to context
   EVP_DigestInit_ex(mdctx, md, NULL);

   // hash all blocks
   // - assumes that all but the last block has size BLOCKSIZE.
   for (int posn = 0; posn < totalBlocks && charsRemaining > 0; posn++) {
      blockPtr = (void *)blocks[posn];
      thisBlkSz = (charsRemaining <= BLOCKSIZE ? charsRemaining : BLOCKSIZE);
      EVP_DigestUpdate(mdctx, blockPtr, thisBlkSz);
      charsRemaining -= thisBlkSz;
   }

   // Finalise
   EVP_DigestFinal_ex(mdctx, md_value, &md_len);
   EVP_MD_CTX_destroy(mdctx);

   return md_len;
}


static int calcTotalBlocks(Byte_t *blocks[], int maxBlocks) {
// count the number of non-null blocks
   int totalBlocks = 0;
   for (int i = 0; i < maxBlocks; i++) {
      if (blocks[i] != NULL) {
         totalBlocks++;
      }
   }

   return totalBlocks;
}
*/
