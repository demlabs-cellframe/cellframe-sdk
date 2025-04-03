#ifndef _DAP_ENC_MSRLN_H_
#define _DAP_ENC_MSRLN_H_

#include <stddef.h>
#include "msrln/msrln.h"
#include "dap_enc_key.h"

//typedef struct dap_enc_msrln_key{
//    void* private_key;
//    size_t private_length;
//    uint8_t* public_key;
//    size_t public_length;
//} dap_enc_msrln_key_t;

#define DAP_ENC_KEY_TYPE_MSRLN(a) ((dap_enc_msrln_key_t *)((a)->_inheritor))

void dap_enc_msrln_key_new(dap_enc_key_t *a_key);
void dap_enc_msrln_key_generate(dap_enc_key_t * a_key, const void *kex_buf,
                                size_t kex_size, const void *seed, size_t seed_size,
                                size_t key_size);

//void dap_enc_msrln_key_new_from_data(dap_enc_key_t *a_key, void **a_priv, size_t *a_in_size);
void dap_enc_msrln_key_new_from_data_public(dap_enc_key_t *a_key, const void *a_in, size_t a_in_size);

void dap_enc_msrln_key_delete(dap_enc_key_t *a_key);

size_t dap_enc_msrln_key_public_raw(dap_enc_key_t *a_key, void **a_key_public);

size_t dap_enc_msrln_gen_bob_shared_key(dap_enc_key_t *a_bob_key, const void *a_alice_pub, size_t a_alice_pub_size, void **a_cypher_msg);
size_t dap_enc_msrln_gen_alice_shared_key(dap_enc_key_t *a_alice_key, const void *a_alice_priv,
                               size_t a_cypher_msg_size, uint8_t *a_cypher_msg);

#endif
