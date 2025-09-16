#pragma once

#include "sig_tesla/tesla_params.h"
#include "dap_enc_key.h"


enum DAP_TESLA_SIGN_SECURITY {
    TESLA_TOY = 0, HEURISTIC_MAX_SECURITY_AND_MIN_SIZE, HEURISTIC_MAX_SECURITY_AND_MAX_SPEED, PROVABLY_SECURITY, PROVABLY_MAX_SECURITY
};

void dap_enc_sig_tesla_set_type(enum DAP_TESLA_SIGN_SECURITY type);

void dap_enc_sig_tesla_key_new(dap_enc_key_t *a_key);

void dap_enc_sig_tesla_key_new_generate(dap_enc_key_t *key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size);

int dap_enc_sig_tesla_get_sign(dap_enc_key_t *a_key, const void *a_msg,
        const size_t a_msg_size, void *a_sig, const size_t a_sig_size);

int dap_enc_sig_tesla_verify_sign(dap_enc_key_t *a_key, const void *a_msg,
        const size_t a_msg_size, void *a_sig, const size_t a_sig_size);

void dap_enc_sig_tesla_key_delete(dap_enc_key_t *key);

size_t dap_enc_sig_tesla_calc_signature_size(void);

uint8_t *dap_enc_sig_tesla_write_signature(const void *a_sign, size_t *a_buflen_out);
uint8_t *dap_enc_sig_tesla_write_private_key(const void *a_skey, size_t *a_buflen_out);
uint8_t *dap_enc_sig_tesla_write_public_key(const void *a_pkey, size_t *a_buflen_out);

void *dap_enc_sig_tesla_read_signature(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_tesla_read_private_key(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_tesla_read_public_key(const uint8_t *a_buf, size_t a_buflen);

DAP_STATIC_INLINE uint64_t dap_enc_sig_tesla_deser_sig_size(UNUSED_ARG const void *a_in)
{
    return sizeof(tesla_signature_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_tesla_deser_private_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(tesla_private_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_tesla_deser_public_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(tesla_public_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_tesla_ser_sig_size(const void *a_sign)
{
    if (!a_sign)
        return 0;
    return sizeof(uint64_t) * 2 + sizeof(uint32_t) + ((tesla_signature_t *)a_sign)->sig_len;
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_tesla_ser_private_key_size(const void *a_skey)
{
// sanity check
    tesla_param_t l_p;
    if(!a_skey || !tesla_params_init(&l_p, ((tesla_public_key_t *)a_skey)->kind))
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) + l_p.CRYPTO_SECRETKEYBYTES;
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_tesla_ser_public_key_size(const void *a_pkey)
{
// sanity check
    tesla_param_t l_p;
    if(!a_pkey || !tesla_params_init(&l_p, ((tesla_public_key_t *)a_pkey)->kind))
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) + l_p.CRYPTO_PUBLICKEYBYTES;
}
