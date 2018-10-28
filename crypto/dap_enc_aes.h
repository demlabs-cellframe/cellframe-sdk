#ifndef _DAP_ENC_AES_H_
#define _DAP_ENC_AES_H_

#include <stddef.h>
#include <stdint.h>
#include "IAES/dap_iaes_proto.h"

#define AES_BLOCK_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

struct dap_enc_key;

void dap_enc_aes_key_new(struct dap_enc_key * a_key);
void dap_enc_aes_key_new_from_seed(struct dap_enc_key * a_key, const void * seed, size_t a_in_size);
void dap_enc_aes_key_new_from_str(struct dap_enc_key * a_key, const char * a_in);
void dap_enc_aes_key_delete(struct dap_enc_key *a_key);
void dap_enc_aes_key_generate_from_kex_and_seed(struct dap_enc_key * a_key, struct dap_enc_key * kex_key, const void * id_session, size_t id_size);

size_t dap_enc_aes256_cbc_decrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out);
size_t dap_enc_aes256_cbc_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out);

#ifdef __cplusplus
}
#endif

#endif
