#ifndef _DAP_ENC_DILITHIUM_H_
#define _DAP_ENC_DILITHIUM_H_

#include "sig_dilithium/dilithium_params.h"
#include "dap_enc_key.h"


enum DAP_DILITHIUM_SIGN_SECURITY {
    DILITHIUM_TOY = 0, DILITHIUM_MAX_SPEED, DILITHIUM_MIN_SIZE, DILITHIUM_MAX_SECURITY
};

void dap_enc_sig_dilithium_set_type(enum DAP_DILITHIUM_SIGN_SECURITY type);

void dap_enc_sig_dilithium_key_new(dap_enc_key_t *a_key);

void dap_enc_sig_dilithium_key_new_generate(dap_enc_key_t *key, const void *kex_buf,
                                    size_t kex_size, const void *seed, size_t seed_size,
                                    size_t key_size);
void dap_enc_sig_dilithium_key_delete(dap_enc_key_t *a_key);

int dap_enc_sig_dilithium_get_sign(dap_enc_key_t *a_key, const void *a_msg,
        const size_t a_msg_size, void *a_sig, const size_t a_sig_size);

int dap_enc_sig_dilithium_verify_sign(dap_enc_key_t *a_key, const void *a_msg,
        const size_t a_msg_size, void *a_sig, const size_t a_sig_size);


uint8_t *dap_enc_sig_dilithium_write_signature(const void *a_sign, size_t *a_buflen_out);
uint8_t *dap_enc_sig_dilithium_write_private_key(const void *a_private_key, size_t *a_buflen_out);
uint8_t *dap_enc_sig_dilithium_write_public_key(const void *a_public_key, size_t *a_buflen_out);
void *dap_enc_sig_dilithium_read_signature(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_dilithium_read_private_key(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_dilithium_read_public_key(const uint8_t *a_buf, size_t a_buflen);


DAP_STATIC_INLINE uint64_t dap_enc_sig_dilithium_deser_sig_size(UNUSED_ARG const void *a_in)
{
    return sizeof(dilithium_signature_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_dilithium_deser_private_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(dilithium_private_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_dilithium_deser_public_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(dilithium_public_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_dilithium_ser_sig_size(const void *a_sign)
{
    if (!a_sign)
        return 0;
    return sizeof(uint64_t) * 2 + sizeof(uint32_t) + ((dilithium_signature_t *)a_sign)->sig_len;
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_dilithium_ser_private_key_size(const void *a_skey)
{
// sanity check
    dilithium_param_t l_p;
    if(!a_skey || !dilithium_params_init(&l_p, ((dilithium_private_key_t *)a_skey)->kind))
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) + l_p.CRYPTO_SECRETKEYBYTES;
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_dilithium_ser_public_key_size(const void *a_pkey)
{
// sanity check
    dilithium_param_t l_p;
    if(!a_pkey || !dilithium_params_init(&l_p, ((dilithium_public_key_t *)a_pkey)->kind))
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) + l_p.CRYPTO_PUBLICKEYBYTES;
}
#endif
