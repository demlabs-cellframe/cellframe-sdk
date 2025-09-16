#ifndef _DAP_ENC_SPHINCSPLUS_H
#define _DAP_ENC_SPHINCSPLUS_H

#include "dap_enc_key.h"
#include "sphincsplus/sphincsplus_params.h"

void dap_enc_sig_sphincsplus_key_new(dap_enc_key_t *a_key);
void sphincsplus_public_key_delete(void *a_pkey);
void sphincsplus_private_key_delete(void *a_skey);
void sphincsplus_private_and_public_keys_delete(void *a_skey, void *a_pkey);
void sphincsplus_signature_delete(void *a_sig);

void dap_enc_sig_sphincsplus_key_new_generate(dap_enc_key_t *a_key, const void *a_kex_buf, size_t a_kex_size,
        const void *a_seed, size_t a_seed_size, size_t a_key_size);

int dap_enc_sig_sphincsplus_get_sign(dap_enc_key_t *a_key, const void *a_msg, const size_t a_msg_size,
        void *a_sign, const size_t a_sign_size);
size_t dap_enc_sig_sphincsplus_get_sign_msg(dap_enc_key_t *a_key, const void *a_msg, const size_t a_msg_size,
        void *a_sign_out, const size_t a_out_size_max);

int dap_enc_sig_sphincsplus_verify_sign(dap_enc_key_t *a_key, const void *a_msg, const size_t a_msg_size, void *a_sign,
const size_t a_sign_size);
size_t dap_enc_sig_sphincsplus_open_sign_msg(dap_enc_key_t *a_key, const void *a_sign_in, const size_t a_sign_size, void *a_msg_out,
        const size_t a_out_size_max);

void dap_enc_sig_sphincsplus_key_delete(dap_enc_key_t *a_key);


uint8_t *dap_enc_sig_sphincsplus_write_signature(const void *a_sign, size_t *a_buflen_out);
uint8_t *dap_enc_sig_sphincsplus_write_private_key(const void *a_private_key, size_t *a_buflen_out);
uint8_t *dap_enc_sig_sphincsplus_write_public_key(const void* a_public_key, size_t *a_buflen_out);
void *dap_enc_sig_sphincsplus_read_signature(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_sphincsplus_read_private_key(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_sphincsplus_read_public_key(const uint8_t *a_buf, size_t a_buflen);

uint64_t dap_enc_sig_sphincsplus_crypto_sign_secretkeybytes();
uint64_t dap_enc_sig_sphincsplus_crypto_sign_publickeybytes();
uint64_t dap_enc_sig_sphincsplus_crypto_sign_bytes();
uint64_t dap_enc_sig_sphincsplus_crypto_sign_seedbytes();

DAP_STATIC_INLINE uint64_t dap_enc_sig_sphincsplus_deser_sig_size(UNUSED_ARG const void *a_in)
{
    return sizeof(sphincsplus_signature_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_sphincsplus_deser_private_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(sphincsplus_private_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_sphincsplus_deser_public_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(sphincsplus_public_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_sphincsplus_ser_sig_size(const void *a_sign)
{
    if (!a_sign)
        return 0;
        
    return ((sphincsplus_signature_t *)a_sign)->sig_len + sizeof(uint64_t) * 2 + sizeof(sphincsplus_base_params_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_sphincsplus_ser_private_key_size(const void *a_skey)
{
// sanity check
    if(!a_skey)
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(sphincsplus_base_params_t) + dap_enc_sig_sphincsplus_crypto_sign_secretkeybytes(&((sphincsplus_private_key_t *)a_skey)->params);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_sphincsplus_ser_public_key_size(const void *a_pkey)
{
// sanity check
    if(!a_pkey)
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(sphincsplus_base_params_t) + dap_enc_sig_sphincsplus_crypto_sign_publickeybytes(&((sphincsplus_public_key_t *)a_pkey)->params);
}

#ifdef DAP_CRYPTO_TESTS
void dap_enc_sig_sphincsplus_set_default_config (sphincsplus_config_t  a_new_config);
int dap_enc_sig_sphincsplus_get_configs_count();
#endif

#endif //_DAP_ENC_SPHINCSPLUS_H
