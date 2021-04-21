#ifndef _DAP_ENC_SIGN_ECDSA_
#define _DAP_ENC_SIGN_ECDSA_

#include "dap_enc_key.h"
#include "TrezorCrypto/bignum.h"
#include "TrezorCrypto/ecdsa.h"

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
size_t dap_enc_sign_ecdsa_calc_signature_serialized_size();

uint8_t* dap_enc_sign_ecdsa_write_signature(uint8_t *a_sign, size_t *a_sign_out);
uint8_t* dap_enc_sign_ecdsa_read_signature(uint8_t *a_buff, size_t a_buff_size);

#ifdef __cplusplus 
}
#endif

#endif //_DAP_ENC_SIGN_ECDSA_
