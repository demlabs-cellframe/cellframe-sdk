
#ifndef _DAP_ENC_BLISS_H_
#define _DAP_ENC_BLISS_H_

#include "sig_bliss/bliss_b_params.h"
#include "dap_enc_key.h"

#define LOG_TAG "dap_enc_sig_bliss"

void dap_enc_sig_bliss_key_new(struct dap_enc_key *key);

void dap_enc_sig_bliss_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

size_t dap_enc_sig_bliss_get_sign(struct dap_enc_key * key, const void * msg, size_t msg_size, void ** signature);

size_t dap_enc_sig_bliss_verify_sign(struct dap_enc_key * key, const void * msg, size_t msg_size, void ** signature);

void dap_enc_sig_bliss_key_delete(struct dap_enc_key *key);


#endif
