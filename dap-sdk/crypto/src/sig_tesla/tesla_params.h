#ifndef __TESLA_PARAMS__
#define __TESLA_PARAMS__

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include "dap_crypto_common.h"

#define CRYPTO_RANDOMBYTES 32
#define CRYPTO_SEEDBYTES 32
#define CRYPTO_C_BYTES 32

///========================================================================
/* Names for the five varieties of Tesla */
typedef enum { qTESLA_I, qTESLA_III_size, qTESLA_III_speed, qTESLA_p_I, qTESLA_p_III } tesla_kind_t;

typedef struct {
  tesla_kind_t kind;     /* the kind of qTesla (i.e. *this* choice of parameters)  */
  uint32_t PARAM_N;
  uint32_t PARAM_N_LOG;
  float    PARAM_SIGMA;
  float    PARAM_Xi;
  uint32_t PARAM_Q;
  uint32_t PARAM_Q_LOG;
  uint32_t PARAM_QINV;
  uint32_t PARAM_BARR_MULT;
  uint32_t PARAM_BARR_DIV;
  uint32_t PARAM_B;
  uint32_t PARAM_B_BITS;

  uint32_t PARAM_K;
  float    PARAM_SIGMA_E;

  uint32_t PARAM_W;
  uint32_t PARAM_D;

  uint32_t PARAM_GEN_A;

  uint32_t PARAM_KEYGEN_BOUND_E;
  uint32_t PARAM_REJECTION;
  uint32_t PARAM_KEYGEN_BOUND_S;
  uint32_t PARAM_U;
  uint32_t PARAM_R2_INVN;

  // Contains signature (z,c). z is a polynomial bounded by B, c is the output of a hashed string
  uint32_t CRYPTO_BYTES;
  // Contains polynomial s and e, and seeds seed_a and seed_y
  uint32_t CRYPTO_SECRETKEYBYTES;
  // Contains seed_a and polynomials t
  uint32_t CRYPTO_PUBLICKEYBYTES;

} tesla_param_t;

///==========================================================================================
typedef struct {
  tesla_kind_t kind;                 /* the kind of tesla       */
  unsigned char *data;
} tesla_private_key_t;

typedef struct {
  tesla_kind_t kind;                 /* the kind of tesla       */
  unsigned char *data;
} tesla_public_key_t;

typedef struct {
  tesla_kind_t kind;                      /* the kind of tesla       */
  unsigned char *sig_data;
  unsigned long long sig_len;
} tesla_signature_t;

///==========================================================================================
typedef	int64_t poly;//[ 2048 ]; //PARAM_N __attribute__ ((aligned(32)))
typedef	int64_t poly_k;//[ 5 * 2048]; // PARAM_K * PARAM_N __attribute__ ((aligned(32)))

#ifdef __cplusplus
extern "C" {
#endif

///==========================================================================================
bool tesla_params_init(tesla_param_t *, tesla_kind_t );

int tesla_crypto_sign_keypair(tesla_public_key_t *public_key, tesla_private_key_t *private_key, tesla_kind_t kind, const void * seed, size_t seed_size);

int tesla_crypto_sign(tesla_signature_t *, const unsigned char *, unsigned long long, const tesla_private_key_t *);

int tesla_crypto_sign_open(tesla_signature_t *, const unsigned char *, unsigned long long, const tesla_public_key_t *);

void tesla_private_key_delete(tesla_private_key_t *private_key);
void tesla_public_key_delete(tesla_public_key_t *public_key);
void tesla_private_and_public_keys_delete(tesla_private_key_t *private_key, tesla_public_key_t *public_key);

void tesla_signature_delete(tesla_signature_t *signature);

int64_t init_mass_poly(poly *zeta, poly *zetainv, tesla_param_t *p);
int64_t reduce(int64_t a, tesla_param_t *p);
int64_t barr_reduce(int64_t a, tesla_param_t *p);
void ntt(poly *a, const poly *w, tesla_param_t *p);
void nttinv(poly *a, const poly *w, tesla_param_t *p);
void poly_pointwise(poly *result, const poly *x, const poly *y, tesla_param_t *p);
void poly_ntt(poly *x_ntt, const poly *x, tesla_param_t *p);
void poly_mul(poly *result, const poly *x, const poly *y, tesla_param_t *p);
void poly_add(poly *result, const poly *x, const poly *y, tesla_param_t *p);
void poly_sub(poly *result, const poly *x, const poly *y, tesla_param_t *p);
void poly_uniform(poly_k *a, const unsigned char *seed, tesla_param_t *p);


///==========================================================================================
void sample_y(int64_t *y, const unsigned char *seed, int nonce, tesla_param_t *p);
void sample_gauss_poly(int64_t *x, const unsigned char *seed, int nonce, tesla_param_t *p);
void encode_c(uint32_t *pos_list, int16_t *sign_list, unsigned char *c_bin, tesla_param_t *p);

#ifdef __cplusplus
}
#endif

#endif


