#pragma once

#include "sig_bliss/bliss_b_params.h"
#include "dap_enc_key.h"


enum DAP_BLISS_SIGN_SECURITY {
    TOY = 0, MAX_SPEED, MIN_SIZE, SPEED_AND_SECURITY, MAX_SECURITY
};

void dap_enc_sig_bliss_set_type(enum DAP_BLISS_SIGN_SECURITY type);

void dap_enc_sig_bliss_key_new(dap_enc_key_t *a_key);

void dap_enc_sig_bliss_key_new_generate(dap_enc_key_t *key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

int dap_enc_sig_bliss_get_sign(dap_enc_key_t *key,const void *msg,
                                  const size_t msg_size, void *signature, const size_t signature_size);

int dap_enc_sig_bliss_verify_sign(dap_enc_key_t *key,const void *msg,
                                     const size_t msg_size, void *signature, const size_t signature_size);

void dap_enc_sig_bliss_key_delete(dap_enc_key_t *key);
size_t dap_enc_sig_bliss_key_pub_output_size(dap_enc_key_t *l_key);
int dap_enc_sig_bliss_key_pub_output(dap_enc_key_t *l_key, void * l_output);

uint8_t *dap_enc_sig_bliss_write_signature(const void *a_sign, size_t *a_buflen_out);
uint8_t *dap_enc_sig_bliss_write_private_key(const void *a_skey, size_t *a_buflen_out);
uint8_t *dap_enc_sig_bliss_write_public_key(const void *a_pkey, size_t *a_buflen_out);

void *dap_enc_sig_bliss_read_signature(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_bliss_read_private_key(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_bliss_read_public_key(const uint8_t *a_buf, size_t a_buflen);


DAP_STATIC_INLINE uint64_t dap_enc_sig_bliss_deser_sig_size(UNUSED_ARG const void *a_in)
{
    return sizeof(bliss_signature_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_bliss_deser_private_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(bliss_private_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_bliss_deser_public_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(bliss_public_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_bliss_ser_sig_size(const void *a_sign)
{
    bliss_param_t p;
    if(!a_sign || !bliss_params_init( &p, (((bliss_signature_t *)a_sign)->kind) ))
        return 0;
    return sizeof(uint64_t) + sizeof(uint32_t) + p.n * 2 * sizeof(int32_t) + p.kappa * sizeof(int32_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_bliss_ser_private_key_size(const void *a_skey)
{
// sanity check
    bliss_param_t l_p;
    if(!a_skey || !bliss_params_init(&l_p, ((bliss_private_key_t *)a_skey)->kind))
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) + 3 * l_p.n * sizeof(int32_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_bliss_ser_public_key_size(const void *a_pkey)
{
// sanity check
    bliss_param_t l_p;
    if(!a_pkey || !bliss_params_init(&l_p, ((bliss_public_key_t *)a_pkey)->kind))
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) + l_p.n * sizeof(int32_t);
}
