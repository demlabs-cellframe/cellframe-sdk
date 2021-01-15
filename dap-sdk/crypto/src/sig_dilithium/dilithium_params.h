#ifndef __DILITHIUM_PARAMS__
#define __DILITHIUM_PARAMS__

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "dap_crypto_common.h"

#define SEEDBYTES		32U
#define CRHBYTES		48U

//#ifdef N
//#error N defined
//#endif

#define NN 				256U

#define Q 				8380417U
#define QBITS 			23U
#define ROOT_OF_UNITY	1753U
#define D 				14U
#define GAMMA1 ((Q - 1U)/16U)
#define GAMMA2 (GAMMA1/2U)
#define ALPHA (2U*GAMMA2)


///========================================================================
/* Names for the four varieties of Dilithium */
typedef enum { MODE_0, MODE_1, MODE_2, MODE_3 } __attribute__((aligned(4))) dilithium_kind_t;

typedef struct {
  dilithium_kind_t kind;     /* the kind of Dilithium (i.e. *this* choice of parameters)  */
  uint32_t PARAM_K;
  uint32_t PARAM_L;
  uint32_t PARAM_ETA;
  uint32_t PARAM_SETABITS;
  uint32_t PARAM_BETA;
  uint32_t PARAM_OMEGA;

  uint32_t PARAM_POL_SIZE_PACKED;
  uint32_t PARAM_POLT1_SIZE_PACKED;
  uint32_t PARAM_POLT0_SIZE_PACKED;
  uint32_t PARAM_POLETA_SIZE_PACKED;
  uint32_t PARAM_POLZ_SIZE_PACKED;
  uint32_t PARAM_POLW1_SIZE_PACKED;
  uint32_t PARAM_POLVECK_SIZE_PACKED;
  uint32_t PARAM_POLVECL_SIZE_PACKED;

  uint32_t CRYPTO_PUBLICKEYBYTES;
  uint32_t CRYPTO_SECRETKEYBYTES;
  uint32_t CRYPTO_BYTES;

} dilithium_param_t;

///==========================================================================================
typedef struct {
  dilithium_kind_t kind;                 /* the kind of dilithium       */
  unsigned char *data;
} dilithium_private_key_t;

typedef struct {
  dilithium_kind_t kind;                 /* the kind of dilithium       */
  unsigned char *data;
} dilithium_public_key_t;

typedef struct {
  dilithium_kind_t kind;                      /* the kind of dilithium       */
  unsigned char *sig_data;
  uint64_t sig_len;
} dilithium_signature_t;


///==========================================================================================
bool dilithium_params_init(dilithium_param_t *, dilithium_kind_t );

int dilithium_crypto_sign_keypair(dilithium_public_key_t *public_key, dilithium_private_key_t *private_key,
        dilithium_kind_t kind, const void * seed, size_t seed_size);

int dilithium_crypto_sign(dilithium_signature_t *, const unsigned char *, unsigned long long, const dilithium_private_key_t *);

int dilithium_crypto_sign_open( unsigned char *, unsigned long long, dilithium_signature_t *, const dilithium_public_key_t *);

void dilithium_private_key_delete(dilithium_private_key_t *private_key);
void dilithium_public_key_delete(dilithium_public_key_t *public_key);
void dilithium_private_and_public_keys_delete(dilithium_private_key_t *private_key, dilithium_public_key_t *public_key);

void dilithium_signature_delete(dilithium_signature_t *sig);

///==========================================================================================

#endif


