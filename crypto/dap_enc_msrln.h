#ifndef _DAP_ENC_MSRLN_H_
#define _DAP_ENC_MSRLN_H_

#include <stddef.h>
#include "MSRLN/MSRLN.h"
#include "dap_enc_key.h"

//typedef struct dap_enc_key dap_enc_key_t;

typedef struct dap_enc_msrln_key{
    void* private_key;
    size_t private_length;
    uint8_t* public_key;
    size_t public_length;
} dap_enc_msrln_key_t;

#define DAP_ENC_KEY_TYPE_MSRLN(a) ((dap_enc_msrln_key_t *)((a)->_inheritor))

void dap_enc_msrln_key_new_generate(struct dap_enc_key* a_key, size_t a_size);
void dap_enc_msrln_key_new_from_data(struct dap_enc_key* a_key, void **a_priv, size_t *a_in_size);
void dap_enc_msrln_key_new_from_data_public(dap_enc_key_t* a_key, const void * a_in, size_t a_in_size);

void dap_enc_msrln_key_delete(struct dap_enc_key* a_key);

size_t dap_enc_msrln_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public);

size_t dap_enc_msrln_encode(struct dap_enc_key* b_key, unsigned char *a_pub, size_t *a_pub_size, unsigned char **b_pub);
size_t dap_enc_msrln_decode(struct dap_enc_key* a_key, const void* a_priv, size_t *a_key_len, unsigned char * b_pub);

#endif
