#ifndef _DAP_ENC_DEFEO_H_
#define _DAP_ENC_DEFEO_H_


#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "dap_common.h"
#include "dap_enc_key.h"

struct dap_enc_key;

typedef struct dap_enc_defeo_key{
    unsigned int alice_msg_len;
    unsigned int bob_msg_len;
    unsigned int key_len;
    uint16_t estimated_classical_security;
    uint16_t estimated_quantum_security;
} dap_enc_defeo_key_t;

#define LOG_TAG "dap_enc_defeo"

#define DAP_ENC_DEFEO_KEY(a) ((dap_enc_defeo_key_t *)((a)->_inheritor))

void dap_enc_defeo_key_new(struct dap_enc_key* a_key);

void dap_enc_defeo_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

void dap_enc_defeo_key_new_from_data(struct dap_enc_key* a_key, void **a_priv, size_t a_in_size);
void dap_enc_defeo_key_delete(struct dap_enc_key* a_key);

size_t dap_enc_defeo_gen_bob_shared_key(struct dap_enc_key* b_key, const void* a_pub, size_t a_pub_size, void **b_pub);
size_t dap_enc_defeo_gen_alice_shared_key(struct dap_enc_key* a_key, const void* a_priv, size_t b_pub_size, unsigned char * b_pub);

#endif
