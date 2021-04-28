#ifndef _DAP_ENC_SIGN_ECDSA_
#define _DAP_ENC_SIGN_ECDSA_

#include "dap_enc_key.h"
#include "dap_enc_curve_types.h"
#include "TrezorCrypto/bignum.h"
#include "TrezorCrypto/ecdsa.h"
#include "TrezorCrypto/rand.h"
#include "TrezorCrypto/ed25519.h"
#include "TrezorCrypto/nist256p1.h"
#include "TrezorCrypto/secp256k1.h"
#include "TrezorCrypto/ed25519-donna/ed25519-blake2b.h"
#include "TrezorCrypto/sodium/keypair.h"

typedef struct dap_enc_key_public_ecdsa{
    dap_enc_curve_types_t curve_type;
    uint8_t *data;
    size_t size_key;
}dap_enc_key_public_ecdsa_t;
typedef struct dap_enc_key_private_ecdsa{
    dap_enc_curve_types_t curve_type;
    uint8_t *data;
    size_t size_key;
}dap_enc_key_private_ecdsa_t;

#ifdef __cplusplus 
extern "C" {
#endif

void dap_enc_sign_ecdsa_key_new(struct dap_enc_key *a_key);
void dap_enc_sign_ecdsa_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                            const void *seed, size_t seed_size, size_t key_size);
size_t dap_enc_sign_ecdsa_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size);
size_t dap_enc_sign_ecdsa_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size);
void dap_enc_sign_ecdsa_key_delete(struct dap_enc_key *a_key);

size_t dap_enc_sign_ecdsa_calc_signature_size(void);
size_t dap_enc_sign_ecdsa_calc_signature_serialized_size(void);

uint8_t* dap_enc_sign_ecdsa_write_signature(uint8_t *a_sign, size_t *a_sign_out);
uint8_t* dap_enc_sign_ecdsa_read_signature(uint8_t *a_buff, size_t a_buff_size);
uint8_t *dap_enc_sign_ecdsa_write_private_key(const dap_enc_key_private_ecdsa_t *a_private_key, size_t *a_buflen_out);
uint8_t *dap_enc_sign_ecdsa_write_public_key(const dap_enc_key_public_ecdsa_t *a_public_key, size_t *a_buflen_out);
dap_enc_key_private_ecdsa_t *dap_enc_sign_ecdsa_read_private_key(const uint8_t *a_buf, size_t a_buflen);
dap_enc_key_public_ecdsa_t *dap_enc_sign_ecdsa_read_public_key(const uint8_t *a_buf, size_t a_buflen);

#ifdef __cplusplus 
}
#endif

#endif //_DAP_ENC_SIGN_ECDSA_
