#ifndef _DAP_ENC_AES_H_
#define _DAP_ENC_AES_H_

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

struct dap_enc_key;

void dap_enc_aes_key_new_generate(struct dap_enc_key * a_key,size_t a_size);
void dap_enc_aes_key_new_from_data(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size);
void dap_enc_aes_key_delete(struct dap_enc_key *a_key);
int test_key_aes();

size_t dap_enc_aes_decode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out);
size_t dap_enc_aes_encode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out);

#endif
