#ifndef _DAP_ENC_FALCON_H
#define _DAP_ENC_FALCON_H

#include "dap_enc_key.h"
#include "falcon/falcon_params.h"


void dap_enc_sig_falcon_set_degree(falcon_sign_degree_t a_falcon_sign_degree);
void dap_enc_sig_falcon_set_kind(falcon_kind_t a_falcon_kind);
void dap_enc_sig_falcon_set_type(falcon_sign_type_t a_falcon_sign_type);

void dap_enc_sig_falcon_key_new(struct dap_enc_key *key);

void dap_enc_sig_falcon_key_new_generate(struct dap_enc_key *key, const void *kex_buf, size_t kex_size,
        const void* seed, size_t seed_size, size_t key_size);

size_t dap_enc_sig_falcon_get_sign(struct dap_enc_key* key, const void * msg, const size_t msg_size,
        void* signature, const size_t signature_size);

size_t dap_enc_sig_falcon_verify_sign(struct dap_enc_key* key, const void* msg, const size_t msg_size, void* signature,
        const size_t signature_size);

void dap_enc_sig_falcon_key_delete(struct dap_enc_key *key);

uint8_t* dap_enc_falcon_write_signature(const falcon_signature_t* a_sign, size_t *a_sign_out);
falcon_signature_t* dap_enc_falcon_read_signature(const uint8_t* a_buf, size_t a_buflen);

uint8_t* dap_enc_falcon_write_private_key(const falcon_private_key_t* a_private_key, size_t* a_buflen_out);
uint8_t* dap_enc_falcon_write_public_key(const falcon_public_key_t* a_public_key, size_t* a_buflen_out);
falcon_private_key_t* dap_enc_falcon_read_private_key(const uint8_t* a_buf, size_t a_buflen);
falcon_public_key_t* dap_enc_falcon_read_public_key(const uint8_t* a_buf, size_t a_buflen);

size_t dap_enc_falcon_calc_signature_unserialized_size(dap_enc_key_t *key);

#endif //_DAP_ENC_FALCON_H
