#ifndef DAP_ENC_RINGCT20_H
#define DAP_ENC_RINGCT20_H

#include "ringct20/ringct20_params.h"
#include "dap_enc_key.h"


enum DAP_RINGCT20_SIGN_SECURITY {
    RINGCT20_TOY = 0, RINGCT20_MAX_SPEED, RINGCT20_MIN_SIZE, RINGCT20_MAX_SECURITY
};

void dap_enc_sig_ringct20_set_type(enum DAP_RINGCT20_SIGN_SECURITY type);

void dap_enc_sig_ringct20_key_new(struct dap_enc_key *key);

void dap_enc_sig_ringct20_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

size_t dap_enc_sig_ringct20_get_sign(struct dap_enc_key * key,const void * msg,
                                  const size_t msg_size, void * signature, const size_t signature_size);

size_t dap_enc_sig_ringct20_verify_sign(struct dap_enc_key * key,const void * msg,
                                     const size_t msg_size, void * signature, const size_t signature_size);

void dap_enc_sig_ringct20_key_delete(struct dap_enc_key * key);

size_t dap_enc_ringct20_calc_signature_size(void);

uint8_t* dap_enc_ringct20_write_signature(ringct20_signature_t* a_sign, size_t *a_sign_out);
ringct20_signature_t* dap_enc_ringct20_read_signature(uint8_t *a_buf, size_t a_buflen);
uint8_t* dap_enc_ringct20_write_private_key(const ringct20_private_key_t* a_private_key, size_t *a_buflen_out);
uint8_t* dap_enc_ringct20_write_public_key(const ringct20_public_key_t* a_public_key, size_t *a_buflen_out);
ringct20_private_key_t* dap_enc_ringct20_read_private_key(const uint8_t *a_buf, size_t a_buflen);
ringct20_public_key_t* dap_enc_ringct20_read_public_key(const uint8_t *a_buf, size_t a_buflen);


#endif // DAP_ENC_RINGCT20_H
