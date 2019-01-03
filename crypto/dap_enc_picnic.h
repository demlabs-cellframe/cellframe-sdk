#ifndef _DAP_ENC_PICNIC_H_
#define _DAP_ENC_PICNIC_H_

#ifdef __cplusplus
extern "C" {
#endif

//#include "../sig_picnic/picnic.h"
#include "dap_enc_key.h"

#undef LOG_TAG
#define LOG_TAG "dap_enc_picnic_sig"

#define DAP_PICNIC_SIGN_PARAMETR 1;//determination of the scheme and level of resistance {1-6}

void dap_enc_sig_picnic_key_new(struct dap_enc_key *key);

void dap_enc_sig_picnic_key_delete(struct dap_enc_key *key);

void dap_enc_sig_picnic_key_new_generate(struct dap_enc_key * key, const void *kex_buf, size_t kex_size,
        const void * seed, size_t seed_size,
        size_t key_size);

size_t dap_enc_sig_picnic_get_sign(struct dap_enc_key * key, const void* message, size_t message_len,
        void* signature, size_t signature_len);

size_t dap_enc_sig_picnic_verify_sign(struct dap_enc_key * key, const void* message, size_t message_len,
        void* signature, size_t signature_len);

size_t dap_enc_picnic_calc_signature_size(struct dap_enc_key *key);

#ifdef __cplusplus
}
#endif

#endif

