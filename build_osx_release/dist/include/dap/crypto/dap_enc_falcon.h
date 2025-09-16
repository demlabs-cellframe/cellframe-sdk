#ifndef _DAP_ENC_FALCON_H
#define _DAP_ENC_FALCON_H

#include "dap_enc_key.h"
#include "falcon/falcon_params.h"


void dap_enc_sig_falcon_set_degree(falcon_sign_degree_t a_falcon_sign_degree);
void dap_enc_sig_falcon_set_kind(falcon_kind_t a_falcon_kind);
void dap_enc_sig_falcon_set_type(falcon_sign_type_t a_falcon_sign_type);

void dap_enc_sig_falcon_key_new(dap_enc_key_t *a_key);

void dap_enc_sig_falcon_key_new_generate(dap_enc_key_t *key, const void *kex_buf, size_t kex_size,
        const void* seed, size_t seed_size, size_t key_size);

int dap_enc_sig_falcon_get_sign(dap_enc_key_t *key, const void *msg, const size_t msg_size,
        void* signature, const size_t signature_size);

int dap_enc_sig_falcon_verify_sign(dap_enc_key_t *key, const void *msg, const size_t msg_size, void* signature,
        const size_t signature_size);

void dap_enc_sig_falcon_key_delete(dap_enc_key_t *key);



uint8_t *dap_enc_sig_falcon_write_signature(const void *a_sign, size_t *a_buflen_out);
uint8_t *dap_enc_sig_falcon_write_private_key(const void *a_private_key, size_t *a_buflen_out);
uint8_t *dap_enc_sig_falcon_write_public_key(const void *a_public_key, size_t *a_buflen_out);
void *dap_enc_sig_falcon_read_signature(const uint8_t *a_buf, size_t a_buflen);
void *dap_enc_sig_falcon_read_private_key(const uint8_t* a_buf, size_t a_buflen);
void *dap_enc_sig_falcon_read_public_key(const uint8_t* a_buf, size_t a_buflen);

DAP_STATIC_INLINE uint64_t dap_enc_sig_falcon_deser_sig_size(UNUSED_ARG const void *a_in)
{
    return sizeof(falcon_signature_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_falcon_deser_private_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(falcon_private_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_falcon_deser_public_key_size(UNUSED_ARG const void *a_in)
{
    return sizeof(falcon_public_key_t);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_falcon_ser_sig_size(const void *a_sign)
{
    if (!a_sign)
        return 0;
    return sizeof(uint64_t) * 2 + sizeof(uint32_t) * 3 + ((falcon_signature_t *)a_sign)->sig_len;
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_falcon_ser_private_key_size(const void *a_skey)
{
// sanity check
    if(!a_skey)
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) * 3 + FALCON_PRIVKEY_SIZE(((falcon_private_key_t *)a_skey)->degree);
}

DAP_STATIC_INLINE uint64_t dap_enc_sig_falcon_ser_public_key_size(const void *a_pkey)
{
// sanity check
    if(!a_pkey)
        return 0;
// func work
    return sizeof(uint64_t) + sizeof(uint32_t) * 3 + FALCON_PUBKEY_SIZE(((falcon_public_key_t *)a_pkey)->degree);
}

#endif //_DAP_ENC_FALCON_H
