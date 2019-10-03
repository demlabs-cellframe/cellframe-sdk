#ifndef __BLISS_B_H__
#define __BLISS_B_H__

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include "sha3/fips202.h"

//#include "KeccakHash.h"
//#include "SimpleFIPS202.h"

#define BLISS_B_CRYPTO_SECRETKEYBYTES 256
#define BLISS_B_CRYPTO_PUBLICKEYBYTES 85
#define BLISS_B_CRYPTO_BYTES 128

/* Generates a public key and a secret key.  The function returns 0 on
 * success, and a negative error code otherwise. */
extern int32_t bliss_b_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/* Given a secret key and a message, computes the signed message.  The
 * function returns 0 on success, and a negative error code otherwise. */
extern int32_t bliss_b_crypto_sign(uint8_t *sm, uint64_t *smlen, const uint8_t *m,
                                uint64_t mlen, const uint8_t *sk);

/* Given the public key, and a signed message, checks the validity of
 * the signature, and if successful produces the original message.
 * The function returns 0 on success, -1 on failure, and a negative
 * error code, different from -1, otherwise. */
extern int32_t crypto_sign_open(uint8_t *m, uint64_t *mlen, const uint8_t *sm,
                                uint64_t smlen, const uint8_t *pk);

typedef enum {
  BLISS_B_NO_ERROR = 0,
  BLISS_B_VERIFY_FAIL = 1,
  BLISS_B_NO_MEM =  -1,
  BLISS_B_BAD_DATA = -2,
  BLISS_B_BAD_ARGS = -3
} bliss_b_error_t;


/*  Zeros len bytes of a int32_t array ptr, designed in such a way as to NOT be
 *  optimized out by compilers. If the ptr is NULL, the operation
 *  is a noop.
 *   - ptr, pointer to int32_t to be zeroed.
 *   - len, the number of int32_t to be zeroed.  */
extern void zero_int_array(int32_t *ptr, size_t len);

static inline void secure_free(int32_t **ptr_p, size_t len){
  zero_int_array(*ptr_p, len);
  free(*ptr_p);
  *ptr_p = NULL;
}

/* Computes the max norm of a vector of a given length.
 * - v a vector of length n
 * - n the length
 * returns the componentwise max */
extern int32_t vector_max_norm(const int32_t *v, uint32_t n);

/* Computes the scalar product of two vectors of a given length.
 * - v1 a vector of length n
 * - v2 a vector of length n
 * - n the length
 * returns the scalar product (ignore overflows).  */
extern int32_t vector_scalar_product(const int32_t *v1, const int32_t *v2, uint32_t n);

/* Square of the Euclidean norm of v (ignore overflows) */
extern int32_t vector_norm2(const int32_t *v, uint32_t n);

///=========================================================================

/* Simple implementation of modq */
static inline int32_t smodq(int32_t x, int32_t q){
  assert(q > 0);
  int32_t y = x % q;
  return y + ((y >> 31) & q);
}

#endif
