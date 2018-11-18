
#ifndef _DAP_ENC_BLISS_H_
#define _DAP_ENC_BLISS_H_

#include "sig_bliss/bliss_b_params.h"
#include "dap_enc_key.h"

#undef LOG_TAG
#define LOG_TAG "dap_enc_sig_bliss"

enum DAP_BLISS_SIGN_SECURITY {
    TOY = 0, MAX_SPEED, MIN_SIZE, SPEED_AND_SECURITY, MAX_SECURITY
};

void dap_enc_sig_bliss_set_type(enum DAP_BLISS_SIGN_SECURITY type);

void dap_enc_sig_bliss_key_new(struct dap_enc_key *key);

void dap_enc_sig_bliss_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

size_t dap_enc_sig_bliss_get_sign(struct dap_enc_key * key,const void * msg,
                                  const size_t msg_size, void * signature, const size_t signature_size);

size_t dap_enc_sig_bliss_verify_sign(struct dap_enc_key * key,const void * msg,
                                     const size_t msg_size, void * signature, const size_t signature_size);

void dap_enc_sig_bliss_key_delete(struct dap_enc_key *key);


#endif
