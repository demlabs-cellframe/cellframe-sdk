#pragma once

#include "sig_tesla/tesla_params.h"
#include "dap_enc_key.h"


enum DAP_TESLA_SIGN_SECURITY {
    TESLA_TOY = 0, HEURISTIC_MAX_SECURITY_AND_MIN_SIZE, HEURISTIC_MAX_SECURITY_AND_MAX_SPEED, PROVABLY_SECURITY, PROVABLY_MAX_SECURITY
};

void dap_enc_sig_tesla_set_type(enum DAP_TESLA_SIGN_SECURITY type);

void dap_enc_sig_tesla_key_new(struct dap_enc_key *key);

void dap_enc_sig_tesla_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

size_t dap_enc_sig_tesla_get_sign(struct dap_enc_key * key,const void * msg,
                                  const size_t msg_size, void * signature, const size_t signature_size);

size_t dap_enc_sig_tesla_verify_sign(struct dap_enc_key * key,const void * msg,
                                     const size_t msg_size, void * signature, const size_t signature_size);

void dap_enc_sig_tesla_key_delete(struct dap_enc_key * key);

size_t dap_enc_tesla_calc_signature_size(void);
size_t dap_enc_tesla_calc_signature_serialized_size(tesla_signature_t* a_sign);

uint8_t* dap_enc_tesla_write_signature(tesla_signature_t* a_sign, size_t *a_sign_out);
tesla_signature_t* dap_enc_tesla_read_signature(uint8_t *a_buf, size_t a_buflen);
uint8_t* dap_enc_tesla_write_private_key(const tesla_private_key_t* a_private_key, size_t *a_buflen_out);
uint8_t* dap_enc_tesla_write_public_key(const tesla_public_key_t* a_public_key, size_t *a_buflen_out);
tesla_private_key_t* dap_enc_tesla_read_private_key(const uint8_t *a_buf, size_t a_buflen);
tesla_public_key_t* dap_enc_tesla_read_public_key(const uint8_t *a_buf, size_t a_buflen);

