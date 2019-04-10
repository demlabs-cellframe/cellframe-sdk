#ifndef __BLISS_B_PARAMS__
#define __BLISS_B_PARAMS__

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "bliss_b.h"

#define SHA3_512_DIGEST_LENGTH 64
#define EPOOL_HASH_COUNT 10
#define HASH_LEN_UINT16  (SHA3_512_DIGEST_LENGTH/sizeof(uint16_t))
#define HASH_LEN_UINT64  (SHA3_512_DIGEST_LENGTH/sizeof(uint64_t))

typedef struct entropy_s {
  uint64_t   bit_pool;
  uint8_t    char_pool[SHA3_512_DIGEST_LENGTH * EPOOL_HASH_COUNT];
  uint16_t   int16_pool[HASH_LEN_UINT16 * EPOOL_HASH_COUNT];
  uint64_t   int64_pool[HASH_LEN_UINT64 * EPOOL_HASH_COUNT];
  uint8_t    seed[SHA3_512_DIGEST_LENGTH];
  uint32_t   bit_index;
  uint32_t   char_index;
  uint32_t   int16_index;
  uint32_t   int64_index;
 } entropy_t;


/* Initialize using a random seed (64 bytes) */
extern void entropy_init(entropy_t *entropy, const uint8_t *seed);

/* Get one random bit, unsigned char, or 64-bit unsigned integer */
extern bool entropy_random_bit(entropy_t *entropy);
extern uint8_t entropy_random_uint8(entropy_t *entropy);
extern uint16_t  entropy_random_uint16(entropy_t *entropy);
extern uint64_t  entropy_random_uint64(entropy_t *entropy);

/* Return n random bits
 * - n must be no more than 32
 * - the n bits are low-order bits of the returned integer. */
extern uint32_t entropy_random_bits(entropy_t *entropy, uint32_t n);

///========================================================================

/* Names for the five varieties of bliss-b */
typedef enum { BLISS_B_0, BLISS_B_1, BLISS_B_2, BLISS_B_3, BLISS_B_4 } bliss_kind_t;

/* Rule of Thumb: if it used as a bound for a for loop, then it should be uint rather than int.
 * But we keep the modulii related parameters as signed since they are used as operands to * and % 
 * with other signed values as operands, and so we do not want their unsignedness to corrupt 
 * the signed values. */
typedef struct {
  bliss_kind_t kind;     /* the kind of bliss-b (i.e. *this* choice of parameters)  */
  int32_t q;             /* field modulus  */
  uint32_t n;            /* ring size (x^n+1)  */
  uint32_t d;            /* bit drop shift  */
  int32_t mod_p;         /* magic modulus  (derived from d) */
  int32_t q2;            /* 2 * field modulus  */
  int32_t q_inv;         /* floor(2^32/q)      */
  int32_t q2_inv;        /* floor(2^32/q2)     */
  int32_t one_q2;        /* 1/(q+2) mod 2q     */
  uint32_t kappa;        /* index vector size  */  
  uint32_t b_inf;        /* infinite norm  */
  uint32_t b_l2;         /* L2 norm  */  
  uint32_t nz1;          /* nonzero +-1  aka delta_1*n in L Ducas' Bliss-B paper */
  uint32_t nz2;          /* nonzero +-2  aka delta_2*n  in L Ducas' Bliss-B paper */  
  uint32_t sigma;        /* standard deviation  */
  uint32_t M;            /*  We use P_{max} given on page 7 of L Ducas' Bliss-B  paper */
  double m;              /* repetition rate  */

  /* Tables for the NTT transform  */
  const int32_t *w;     /* n roots of unity (mod q)  */
  const int32_t *r;     /* w[i]/n (mod q)  */

  /* parameters used by the sampler (in addition to sigma)  */
  uint32_t ell;         /* number of rows in table for Gaussian sampling */
  uint32_t precision;   /* 8 * number of columns in the table */

} bliss_param_t;

extern bool bliss_params_init(bliss_param_t *params, bliss_kind_t kind);

/* bliss-b private key
 * The only reason we do not declare s1,s2, and a to be [512] arrays
 * is that down the track we may need to beef n up to say 1024 and beyond.
 * so this way we are flexible, and stay less committed to a fixed n. */
typedef struct {
  bliss_kind_t kind;                 /* the kind of bliss       */
  int32_t *s1;                       /* sparse polynomial s1    */
  int32_t *s2;                       /* sparse polynomial s2    */
  int32_t *a;                        /* NTT of s1/s2            */
} bliss_private_key_t;

/* bliss-b public key  */
typedef struct {
  bliss_kind_t kind;                /* the kind of bliss       */
  int32_t *a;                       /* NTT of s1/s2           */
} bliss_public_key_t;

/* PRIVATE KEY API */

/* Allocates (uninitialized space) for the private key, and generates a new private key,
 * given a particular choice of kind.
 *
 * - private_key: structure to store the result.
 * - kind: the kind describes the choice of parameters in the particular variety of bliss-b that we are using.
 * - entropy: our source of randomness, an initialized entropy object.
 *
 * Returns 0 on success, or a negative error code on failure (see bliss_b_error_t). */
extern int32_t bliss_b_private_key_gen(bliss_private_key_t *private_key, bliss_kind_t kind, entropy_t *entropy);

/* Delete the memory associated with the private_key */
extern void bliss_b_private_key_delete(bliss_private_key_t *private_key);


/* PUBLIC KEY API */

/* Allocates (uninitialized space) for the public key, and exports it
 * from the given generated private_key.
 * Returns 0 on success, or a negative error code on failure. */
extern int32_t bliss_b_public_key_extract(bliss_public_key_t *public_key, const bliss_private_key_t *private_key);

/* Delete the memory associated with the public_key */
extern void bliss_b_public_key_delete(bliss_public_key_t *public_key);

///===========================================================================================

typedef struct {
  bliss_kind_t kind;                 /* the kind of bliss       */
  int32_t *z1;                       /* bliss signature polynomial                */
  int32_t *z2;                       /* bliss signature polynomial                */
  uint32_t *c;                       /* indices of sparse vector of size kappa    */
} bliss_signature_t;

/*  Generates a signature of a message given a bliss_b private key.
 *  - signature; structure to store the result
 *  - private_key; a valid bliss-b private key
 *  - msg; the message to be signed
 *  - msg_sz; the size of the message
 *  - entropy;  our source of randomness, an initialized entropy object.
 *  Returns 0 on success, or a negative error code on failure. */
extern int32_t bliss_b_sign(bliss_signature_t *signature,  const bliss_private_key_t *private_key, const uint8_t *msg, size_t msg_sz, entropy_t *entropy);

extern int32_t bliss_b_verify(const bliss_signature_t *signature,  const bliss_public_key_t *public_key, const uint8_t *msg, size_t msg_sz);

extern void bliss_signature_delete(bliss_signature_t *signature);


#endif


