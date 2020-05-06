#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dap_enc_GOST.h"
#include "dap_common.h"
#include "rand/dap_rand.h"
#include "sha3/KeccakHash.h"

#define LOG_TAG "dap_enc_gost"

void dap_enc_gost_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size, size_t key_size)
{
    if(key_size < 32)
    {
        log_it(L_ERROR, "GOST key cannot be less than 32 bytes.");
    }
    a_key->last_used_timestamp = time(NULL);


    a_key->priv_key_data_size = 32;
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t, a_key->priv_key_data_size);

    Keccak_HashInstance Keccak_ctx;
    Keccak_HashInitialize(&Keccak_ctx, 1088,  512, a_key->priv_key_data_size*8, 0x06);
    Keccak_HashUpdate(&Keccak_ctx, kex_buf, kex_size*8);
    if(seed_size)
        Keccak_HashUpdate(&Keccak_ctx, seed, seed_size*8);
    Keccak_HashFinal(&Keccak_ctx, a_key->priv_key_data);
}

void dap_enc_gost_key_delete(struct dap_enc_key *a_key)
{
    if(a_key->priv_key_data != NULL)
    {
        randombytes(a_key->priv_key_data,a_key->priv_key_data_size);
        //DAP_DELETE(a_key->priv_key_data);
    }
    //a_key->priv_key_data_size = 0;
}
//------GOST_OFB-----------
void dap_enc_gost_ofb_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = NULL;
    a_key->_inheritor_size = 0;
    a_key->type = DAP_ENC_KEY_TYPE_GOST_OFB;
    a_key->enc = dap_enc_gost_ofb_encrypt;
    a_key->dec = dap_enc_gost_ofb_decrypt;
    a_key->enc_na = dap_enc_gost_ofb_encrypt_fast;
    a_key->dec_na = dap_enc_gost_ofb_decrypt_fast;
}


size_t dap_enc_gost_ofb_decrypt(struct dap_enc_key *a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    size_t l_out_size = a_in_size - kBlockLen89;
    if(l_out_size <= 0) {
        log_it(L_ERROR, "gost_ofb decryption ct with iv must be more than kBlockLen89 bytes");
        return 0;
    }
    *a_out = DAP_NEW_SIZE(uint8_t, a_in_size - kBlockLen89);
    l_out_size = dap_enc_gost_ofb_decrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(l_out_size == 0)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}

size_t dap_enc_gost_ofb_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    if(a_in_size <= 0) {
        log_it(L_ERROR, "gost ofb encryption pt cannot be 0 bytes");
        return 0;
    }
    size_t l_out_size = a_in_size + kBlockLen89;
    *a_out = DAP_NEW_SIZE(uint8_t, l_out_size);
    l_out_size = dap_enc_gost_ofb_encrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(l_out_size == 0)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}

size_t dap_enc_gost_ofb_calc_encode_size(const size_t size_in)
{
    return size_in + kBlockLen89;
}

size_t dap_enc_gost_ofb_calc_decode_size(const size_t size_in)
{
    if(size_in <= kBlockLen89) {
        log_it(L_ERROR, "gost_ofb decryption size_in ct with iv must be more than kBlockLen89 bytes");
        return 0;
    }
    return size_in - kBlockLen89;
}

size_t dap_enc_gost_ofb_decrypt_fast(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void * a_out, size_t buf_out_size) {
    size_t l_out_size = a_in_size - kBlockLen89;
    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "gost_ofb fast_decryption too small buf_out_size");
        return 0;
    }
    uint8_t iv[kBlockLen89];

    memcpy(iv, a_in, kBlockLen89);

    unsigned char ctx[kOfb89ContextLen];
    if(init_ofb_89(a_key->priv_key_data, ctx, kBlockLen89, iv, kBlockLen89,NULL, NULL))//, print_array, print_uint_array))
    {
         return 0;
    }
    if(crypt_ofb(ctx, a_in + kBlockLen89, a_out, a_in_size - kBlockLen89))
    {
         return 0;
    }
    free_ofb(ctx);
    return l_out_size;
}

size_t dap_enc_gost_ofb_encrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void * a_out,size_t buf_out_size)
{
    //generate iv and put it in *a_out first bytes
    size_t l_out_size = a_in_size + kBlockLen89;
    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "gost_ofb fast_encryption too small buf_out_size");
        return 0;
    }

    uint8_t iv[kBlockLen89];
    if(randombytes(iv, kBlockLen89) == 1)
    {
        log_it(L_ERROR, "failed to get kBlockLen89 bytes iv gost ofb");
        return 0;
    }

    memcpy(a_out, iv, kBlockLen89);
    unsigned char ctx[kOfb89ContextLen];
    if(init_ofb_89(a_key->priv_key_data, ctx, kBlockLen89, iv, kBlockLen89,NULL, NULL))//, print_array, print_uint_array))
    {
        return 0;
    }
    if(crypt_ofb(ctx, a_in, a_out + kBlockLen89, a_in_size))
    {
        return 0;
    }
    free_ofb(ctx);
    return l_out_size;
 }

//------KUZN_OFB-----------
void dap_enc_kuzn_ofb_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = NULL;
    a_key->_inheritor_size = 0;
    a_key->type = DAP_ENC_KEY_TYPE_GOST_OFB;
    a_key->enc = dap_enc_kuzn_ofb_encrypt;
    a_key->dec = dap_enc_kuzn_ofb_decrypt;
    a_key->enc_na = dap_enc_kuzn_ofb_encrypt_fast;
    a_key->dec_na = dap_enc_kuzn_ofb_decrypt_fast;
}



size_t dap_enc_kuzn_ofb_calc_encode_size(const size_t size_in)
{
    return size_in + kBlockLen14;
}

size_t dap_enc_kuzn_ofb_calc_decode_size(const size_t size_in)
{
    if(size_in <= kBlockLen14) {
        log_it(L_ERROR, "gost_ofb decryption size_in ct with iv must be more than kBlockLen14 bytes");
        return 0;
    }
    return size_in - kBlockLen14;
}

size_t dap_enc_kuzn_ofb_encrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void * a_out,size_t buf_out_size)
{
    //generate iv and put it in *a_out first bytes
    size_t l_out_size = a_in_size + kBlockLen14;
    if(a_in_size <= 0) {
        log_it(L_ERROR, "kuzn_ofb fast_encryption too small a_in_size");
        return 0;
    }
    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "kuzn_ofb fast_encryption too small buf_out_size");
        return 0;
    }

    if(randombytes(a_out, kBlockLen14) == 1)//iv
    {
        log_it(L_ERROR, "failed to get kBlockLen14 bytes iv gost ofb");
        return 0;
    }


    unsigned char ctx[kOfb14ContextLen];


    if(init_ofb_14(a_key->priv_key_data, ctx, kBlockLen14, a_out, kBlockLen14, NULL,NULL))
         return -1;

    if(crypt_ofb(ctx, a_in, a_out + kBlockLen14, a_in_size))
         return -1;

    free_ofb(ctx);
    return l_out_size;
 }

size_t dap_enc_kuzn_ofb_decrypt_fast(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void * a_out, size_t buf_out_size)
{
    size_t l_out_size = a_in_size - kBlockLen14;
    if(l_out_size <= 0) {
        log_it(L_ERROR, "kuzn_ofb fast_decryption too small a_in_size");
        return 0;
    }

    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "kuzn_ofb fast_decryption too small buf_out_size");
        return 0;
    }

    unsigned char ctx[kOfb14ContextLen];
    //iv first kBlockLen14 a_in bytes

    if(init_ofb_14(a_key->priv_key_data, ctx, kBlockLen14, a_in, kBlockLen14, NULL, NULL))
         return -1;

    if(decrypt_ofb(ctx, a_in + kBlockLen14, a_out, l_out_size))
         return -1;

    free_ofb(ctx);
    return l_out_size;
}
size_t dap_enc_kuzn_ofb_decrypt(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void ** a_out) {

    size_t l_out_size = a_in_size - kBlockLen14;
    if(l_out_size <= 0) {
        log_it(L_ERROR, "kuzn_ofb decryption too small a_in_size");
        return 0;
    }

    *a_out = DAP_NEW_SIZE(uint8_t, l_out_size);
    l_out_size = dap_enc_kuzn_ofb_decrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(!l_out_size)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}

size_t dap_enc_kuzn_ofb_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    //generate iv and put it in *a_out first bytes
    if(a_in_size <= 0) {
        log_it(L_ERROR, "kuzn fast_encryption too small a_in_size");
        return 0;
    }
    size_t l_out_size = a_in_size + kBlockLen14;
    *a_out = DAP_NEW_SIZE(uint8_t, l_out_size);

    l_out_size = dap_enc_kuzn_ofb_encrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(!l_out_size)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}
