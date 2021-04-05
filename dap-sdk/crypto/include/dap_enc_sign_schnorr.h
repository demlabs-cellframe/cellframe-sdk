#ifndef _DAP_ENC_SIGN_SCHNORR_
#define _DAP_ENC_SIGN_SCHNORR_
#include "dap_enc_key.h"

#ifdef __cplusplus 
extern "C" {
#endif

void dap_enc_sign_schnorr_key_new(struct dap_enc_key * a_key);
void dap_enc_sign_schnorr_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                            const void *seed, size_t seed_size, size_t key_size);
size_t dap_enc_sign_schnorr_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size);
size_t dap_enc_sign_schnorr_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size);
void dap_enc_sign_schnorr_key_delete(struct dap_enc_key *a_key);

size_t dap_enc_sign_schnorr_calc_signature_size(void);
//size_t dap_enc_sign_schnorr_calc_signature_serialized_size(dap_enc_sign_schnorr_signature_t* a_sign);

//uint8_t* dap_enc_sign_schnorr_write_signature(dap_enc_sign_schnorr_signature_t *a_sign, size_t *a_sign_out);
//dap_enc_sign_schnorr_signature_t* dap_enc_sign_schnorr_read_signature(uint8_t *a_buff, size_t a_buff_size);
//uint8_t *dap_enc_sign_schnorr_write_private_key(const dap_enc_sign_schnorr_private_key_t *a_private_key, size_t *a_buflen_out);
//unit8_t *dap_enc_sign_schnorr_write_public_key(const dap_enc_sign_schnorr_public_key_t *a_private_key, size_t *a_buflen_out);
//dap_enc_sign_schnorr_private_key_t *dap_enc_sign_schnoor_read_private_key(const uint8_t *a_buf, size_t a_buflen);
//dap_enc_sign_schnorr_public_key_t *dap_enc_sign_schnoor_read_public_key(const uint8_t *a_buf, size_t a_buflen);

#ifdef __cplusplus 
}
#endif

#endif //_DAP_ENC_SIGN_SCHNORR_