#ifndef _DAP_ENC_SEED_H_
#define _DAP_ENC_SEED_H_

#include <stddef.h>
#include "dap_enc_key.h"
#include "seed/seed.h"

#ifdef __cplusplus
extern "C" {
#endif
void dap_enc_seed_key_delete(struct dap_enc_key *a_key);
void dap_enc_seed_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size, size_t key_size);
//------SEED_OFB---------
void dap_enc_seed_ofb_key_new(struct dap_enc_key * a_key);

size_t dap_enc_seed_ofb_calc_decode_size(const size_t size_in);
size_t dap_enc_seed_ofb_calc_encode_size(const size_t size_in);

size_t dap_enc_seed_ofb_decrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out);
size_t dap_enc_seed_ofb_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out);

// Writes result ( out ) in already allocated buffer
size_t dap_enc_seed_ofb_decrypt_fast(struct dap_enc_key * a_key, const void * a_in,
        size_t a_in_size, void * buf_out, size_t buf_out_size);
// Writes result ( out ) in already allocated buffer
size_t dap_enc_seed_ofb_encrypt_fast(struct dap_enc_key * a_key, const void * a_in,
        size_t a_in_size, void * buf_out, size_t buf_out_size);

#ifdef __cplusplus
}
#endif

#endif
