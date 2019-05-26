#ifndef _DAP_ENC_AES_H_
#define _DAP_ENC_AES_H_

#include <stddef.h>
#include <stdint.h>
#include "iaes/dap_iaes_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dap_enc_key;

void dap_enc_aes_key_new(struct dap_enc_key * a_key);

void dap_enc_aes_key_delete(struct dap_enc_key *a_key);
void dap_enc_aes_key_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                              const void * seed, size_t seed_size, size_t key_size);

size_t dap_enc_iaes256_calc_decode_size(const size_t size_in);
size_t dap_enc_iaes256_calc_encode_size(const size_t size_in);

size_t dap_enc_iaes256_cbc_decrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out);
size_t dap_enc_iaes256_cbc_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out);

// Writes result ( out ) in already allocated buffer
size_t dap_enc_iaes256_cbc_decrypt_fast(struct dap_enc_key * a_key, const void * a_in,
                                        size_t a_in_size, void * buf_out, size_t buf_out_size);
// if "a_in size mod IAES_BLOCK_SIZE = 0" encryption will be faster
size_t dap_enc_iaes256_cbc_encrypt_fast(struct dap_enc_key * a_key, const void * a_in,
                                        size_t a_in_size, void * buf_out, size_t buf_out_size);
#ifdef __cplusplus
}
#endif

#endif
