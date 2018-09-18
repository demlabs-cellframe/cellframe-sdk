#ifndef _DAP_ENC_NEWHOPE_H_
#define _DAP_ENC_NEWHOPE_H_

#include <stddef.h>

typedef struct dap_enc_key dap_enc_key_t;

void dap_enc_newhope_key_new(dap_enc_key_t * a_key);
void dap_enc_newhope_key_new_size(dap_enc_key_t * a_key, size_t a_size);
void dap_enc_newhope_key_new_from_data(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size);
void dap_enc_newhope_key_new_from_data_public(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size);

void dap_enc_newhope_key_delete(dap_enc_key_t *a_key);

size_t dap_enc_newhope_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public);

size_t dap_enc_newhope_decode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out);
size_t dap_enc_newhope_encode(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size,void * a_out);

#endif
