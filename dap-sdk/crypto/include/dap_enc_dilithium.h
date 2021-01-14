#ifndef _DAP_ENC_DILITHIUM_H_
#define _DAP_ENC_DILITHIUM_H_

#include "sig_dilithium/dilithium_params.h"
#include "dap_enc_key.h"


enum DAP_DILITHIUM_SIGN_SECURITY {
    DILITHIUM_TOY = 0, DILITHIUM_MAX_SPEED, DILITHIUM_MIN_SIZE, DILITHIUM_MAX_SECURITY
};

void dap_enc_sig_dilithium_set_type(enum DAP_DILITHIUM_SIGN_SECURITY type);

void dap_enc_sig_dilithium_key_new(struct dap_enc_key *key);

void dap_enc_sig_dilithium_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

size_t dap_enc_sig_dilithium_get_sign(struct dap_enc_key * key,const void * msg,
                                  const size_t msg_size, void * signature, const size_t signature_size);

size_t dap_enc_sig_dilithium_verify_sign(struct dap_enc_key * key,const void * msg,
                                     const size_t msg_size, void * signature, const size_t signature_size);

void dap_enc_sig_dilithium_key_delete(struct dap_enc_key * key);

size_t dap_enc_dilithium_calc_signature_unserialized_size(void);

static inline size_t dap_enc_dilithium_calc_signagture_size(dilithium_signature_t* a_sign)
{
    return sizeof(size_t) + sizeof(dilithium_kind_t) + a_sign->sig_len + sizeof(unsigned long long);
}

uint8_t* dap_enc_dilithium_write_signature(dilithium_signature_t* a_sign, size_t *a_sign_out);
dilithium_signature_t* dap_enc_dilithium_read_signature(uint8_t *a_buf, size_t a_buflen);
dilithium_signature_t* dap_enc_dilithium_read_signature_old(uint8_t *a_buf, size_t a_buflen);
dilithium_signature_t* dap_enc_dilithium_read_signature_old2(uint8_t *a_buf, size_t a_buflen);

uint8_t* dap_enc_dilithium_write_private_key(const dilithium_private_key_t* a_private_key, size_t *a_buflen_out);
uint8_t* dap_enc_dilithium_write_public_key(const dilithium_public_key_t* a_public_key, size_t *a_buflen_out);
dilithium_private_key_t* dap_enc_dilithium_read_private_key(const uint8_t *a_buf, size_t a_buflen);
dilithium_private_key_t* dap_enc_dilithium_read_private_key_old(const uint8_t *a_buf, size_t a_buflen);

dilithium_public_key_t* dap_enc_dilithium_read_public_key(const uint8_t *a_buf, size_t a_buflen);
dilithium_public_key_t* dap_enc_dilithium_read_public_key_old(const uint8_t *a_buf, size_t a_buflen);
dilithium_public_key_t* dap_enc_dilithium_read_public_key_old2(const uint8_t *a_buf, size_t a_buflen);
#endif
