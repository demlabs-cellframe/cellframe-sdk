#pragma once

#include "sig_bliss/bliss_b_params.h"
#include "dap_enc_key.h"


enum DAP_BLISS_SIGN_SECURITY {
    TOY = 0, MAX_SPEED, MIN_SIZE, SPEED_AND_SECURITY, MAX_SECURITY
};

void dap_enc_sig_bliss_set_type(enum DAP_BLISS_SIGN_SECURITY type);

void dap_enc_sig_bliss_key_new(struct dap_enc_key *key);

void dap_enc_sig_bliss_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

int dap_enc_sig_bliss_get_sign(struct dap_enc_key * key,const void * msg,
                                  const size_t msg_size, void * signature, const size_t signature_size);

int dap_enc_sig_bliss_verify_sign(struct dap_enc_key * key,const void * msg,
                                     const size_t msg_size, void * signature, const size_t signature_size);

void dap_enc_sig_bliss_key_delete(struct dap_enc_key *key);
size_t dap_enc_sig_bliss_key_pub_output_size(struct dap_enc_key *l_key);
int dap_enc_sig_bliss_key_pub_output(struct dap_enc_key *l_key, void * l_output);


uint8_t* dap_enc_sig_bliss_write_signature(bliss_signature_t* a_sign, size_t *a_sign_out);
bliss_signature_t* dap_enc_sig_bliss_read_signature(const uint8_t *a_buf, size_t a_buflen);
uint8_t* dap_enc_sig_bliss_write_private_key(const bliss_private_key_t* a_private_key, size_t *a_buflen_out);
uint8_t* dap_enc_sig_bliss_write_public_key(const bliss_public_key_t* a_public_key, size_t *a_buflen_out);
bliss_private_key_t* dap_enc_sig_bliss_read_private_key(const uint8_t *a_buf, size_t a_buflen);
bliss_public_key_t* dap_enc_sig_bliss_read_public_key(const uint8_t *a_buf, size_t a_buflen);


