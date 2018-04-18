#ifndef _DAP_ENC_MSRLN16_H_
#define _DAP_ENC_MSRLN16_H_

#include <stddef.h>

typedef struct dap_enc_key dap_enc_key_t;

void dap_enc_msrln16_key_new_generate(dap_enc_key_t * a_key, size_t a_size);
void dap_enc_msrln16_key_new_from_data(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size);
void dap_enc_msrln16_key_new_from_data_public(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size);

void dap_enc_msrln16_key_delete(dap_enc_key_t *a_key);

size_t dap_enc_msrln16_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public);

size_t dap_enc_msrln16_decode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out);
size_t dap_enc_msrln16_encode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out);

#endif
