#pragma once
#include "dap_common.h"
#include "dap_enc_key.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dap_enc_key;

void dap_enc_threefish_key_new(struct dap_enc_key *a_key);

void dap_enc_threefish_key_delete(struct dap_enc_key *a_key);
void dap_enc_threefish_generate(struct dap_enc_key *a_key);
//void dap_enc_aes_key_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
//                              const void * seed, size_t seed_size, size_t key_size);

size_t dap_enc_threefish_encrypt(struct dap_enc_key *a_key, const void *a_in_data, size_t a_size_in_data, void **a_out);
size_t dap_enc_threefish_decrypt(struct dap_enc_key *a_key, const void *a_in_data, size_t a_size_in_data, void **a_out);

#ifdef __cplusplus
}
#endif
