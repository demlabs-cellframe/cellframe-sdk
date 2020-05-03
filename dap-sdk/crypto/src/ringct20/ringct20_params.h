#ifndef __RINGCT20_PARAMS__
#define __RINGCT20_PARAMS__

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "dap_crypto_common.h"
#include "poly.h"
#include "ring.h"




///========================================================================
/* Names for the four varieties of Ring CT2.0 */
//typedef enum { RINGCT20_MINSEC, RINGCT20_MIDSEC, RINGCT20_MAXSEC} ringct20_kind_t;
typedef enum  {
    RINGCT20_MINSEC = 0, RINGCT20_MIDSEC, RINGCT20_MAXSEC
}DAP_RINGCT20_SIGN_SECURITY;

typedef struct {
  DAP_RINGCT20_SIGN_SECURITY kind;                 /* the kind of ringct20       */
  unsigned char *data;
}ringct20_public_key_t;


typedef struct {
  DAP_RINGCT20_SIGN_SECURITY kind;    //  the kind of Dilithium (i.e. *this* choice of parameters)
  int M;
  int mLen;
  int wLen;//number of public key
  int Pi;//number of our key//known prk
  poly_ringct20 *A;//fixed PubParams
  poly_ringct20 *H;//fixed PubParams

  ringct20_public_key_t *allpbk;
  int allpbknum;

  size_t POLY_RINGCT20_SIZE_PACKED;
  size_t POLY_RINGCT20_SIZE;
  size_t RINGCT20_PBK_SIZE;
  size_t RINGCT20_PRK_SIZE;
  size_t RINGCT20_SIG_SIZE;

/*  uint32_t PARAM_K;
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

  uint32_t CRYPTO_BYTES;
*/
} ringct20_param_t;

///==========================================================================================
typedef struct {
  DAP_RINGCT20_SIGN_SECURITY kind;                 /* the kind of ringct20       */
  unsigned char *data;
} ringct20_private_key_t;

typedef struct {
  DAP_RINGCT20_SIGN_SECURITY kind;                      /* the kind of ringct20       */
  unsigned char *sig_data;
  unsigned long long sig_len;
} ringct20_signature_t;


///==========================================================================================
bool ringct20_params_init(ringct20_param_t *ringct20_p, DAP_RINGCT20_SIGN_SECURITY kind);
void ringct20_params_free(ringct20_param_t *ringct20_p);

int ringct20_crypto_sign_keypair(ringct20_public_key_t *, ringct20_private_key_t *, DAP_RINGCT20_SIGN_SECURITY );

int ringct20_crypto_sign(ringct20_signature_t *, const unsigned char *, unsigned long long, const ringct20_private_key_t *);

int ringct20_crypto_sign_open(const unsigned char *, const unsigned long long,const ringct20_signature_t *, const ringct20_public_key_t *);

void ringct20_private_key_delete(ringct20_private_key_t *private_key);
void ringct20_public_key_delete(ringct20_public_key_t *public_key);
void ringct20_private_and_public_keys_delete(ringct20_private_key_t *private_key, ringct20_public_key_t *public_key);

void ringct20_signature_delete(ringct20_signature_t *sig);

///==========================================================================================

#endif


