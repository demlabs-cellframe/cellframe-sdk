#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dap_enc_bf.h"
#include "dap_common.h"
#include "rand/dap_rand.h"
#include "sha3/KeccakHash.h"

#define LOG_TAG "dap_enc_blowfish"


void dap_enc_bf_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size, size_t key_size)
{
    a_key->last_used_timestamp = time(NULL);


    a_key->priv_key_data_size = sizeof(BF_KEY);
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t, sizeof(BF_KEY));

    uint8_t *tmp_buf = DAP_NEW_SIZE(uint8_t, (BF_ROUNDS + 2)*4);
    Keccak_HashInstance Keccak_ctx;
    Keccak_HashInitialize(&Keccak_ctx, 1088,  512, (BF_ROUNDS + 2)*4*8, 0x06);
    Keccak_HashUpdate(&Keccak_ctx, kex_buf, kex_size*8);
    if(seed_size)
        Keccak_HashUpdate(&Keccak_ctx, seed, seed_size*8);
    Keccak_HashFinal(&Keccak_ctx, tmp_buf);

    BF_set_key(a_key->priv_key_data, (BF_ROUNDS + 2)*4, tmp_buf);
    DAP_DELETE(tmp_buf);
 }
void dap_enc_bf_key_delete(struct dap_enc_key *a_key)
{
    if(a_key->priv_key_data != NULL)
    {
        randombytes(a_key->priv_key_data,a_key->priv_key_data_size);
        DAP_DELETE(a_key->priv_key_data);
    }
    a_key->priv_key_data_size = 0;
}
//------CBC-----------
size_t dap_enc_bf_cbc_decrypt(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void ** a_out) {
    uint8_t iv[8];
    //BF_KEY *key=a_key->priv_key_data;
    if(a_in_size <= 8 || a_in_size%8) {
        log_it(L_ERROR, "blowfish_cbc decryption ct with iv must be more than 8 bytes and equal to 8*k");
        return 0;
    }


    *a_out = DAP_NEW_SIZE(uint8_t, a_in_size - 8);
    memcpy(iv, a_in, 8);
    BF_cbc_encrypt((unsigned char *)(a_in + 8), *a_out, a_in_size - 8,
                   a_key->priv_key_data, iv, BF_DECRYPT);
    int bf_cbc_padding_length = *(uint8_t*)(*a_out + a_in_size - 8 - 1);

//    for(int i=0;i < bf_cbc_padding_length + 4 + 1; ++i)
//        printf("%.2x ", *(uint8_t*)(*a_out + a_in_size - 8 - 1 - bf_cbc_padding_length - 4 + i));
//    for(int i=0;i < a_in_size - 8; ++i)
//        printf("%.2x ", *(uint8_t*)(*a_out + i));
//    printf("\n");
//    fflush(stdout);
    size_t a_out_size = *(uint32_t*)(*a_out + a_in_size - 8 - 1 - bf_cbc_padding_length - 4);
    return a_out_size;
}



size_t dap_enc_bf_cbc_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    //generate iv and put it in *a_out first bytes
    uint8_t iv[8];
    randombytes(iv, 8);

    if(a_in_size <= 0) {
        log_it(L_ERROR, "blowfish_cbc encryption pt cannot be 0 bytes");
        return 0;
    }

//    BF_KEY *key = a_key->priv_key_data;


    size_t a_out_size = (a_in_size + 4 + 1 + 7)/8*8 + 8;
    *a_out = DAP_NEW_SIZE(uint8_t, a_out_size);
    memcpy(*a_out, iv, 8);
    BF_cbc_encrypt((unsigned char *)(a_in), *a_out + 8, a_in_size,
                   a_key->priv_key_data, iv, BF_ENCRYPT);
    return a_out_size;
}

size_t dap_enc_bf_cbc_calc_encode_size(const size_t size_in)
{
    return (size_in + 4 + 1 + 7)/8*8 + 8;
}

size_t dap_enc_bf_cbc_calc_decode_size(const size_t size_in)
{
    if(size_in <= 8) {
        log_it(L_ERROR, "blowfish_cbc decryption size_in ct with iv must be more than 8 bytes");
        return 0;
    }
    return size_in - 8;
}

size_t dap_enc_bf_cbc_decrypt_fast(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void * a_out, size_t buf_out_size) {
    if(a_in_size - 8 > buf_out_size || a_in_size %8) {
        log_it(L_ERROR, "blowfish_cbc fast_decryption too small buf_out_size or not 8*k");
        return 0;
    }
    uint8_t iv[8];
    //BF_KEY *key=a_key->priv_key_data;

    memcpy(iv, a_in, 8);
    BF_cbc_encrypt((unsigned char *)(a_in + 8), a_out, a_in_size - 8,
                   a_key->priv_key_data, iv, BF_DECRYPT);

    int bf_cbc_padding_length = *(uint8_t*)(a_out + a_in_size - 8 - 1);

    size_t a_out_size = *(uint32_t*)(a_out + a_in_size - 8 - 1 - bf_cbc_padding_length - 4);
    return a_out_size;
}



size_t dap_enc_bf_cbc_encrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void * a_out,size_t buf_out_size)
{
    //generate iv and put it in *a_out first bytes
    size_t a_out_size = (a_in_size + 4 + 1 + 7)/8*8 + 8;
    if(a_out_size > buf_out_size) {
        log_it(L_ERROR, "blowfish_cbc fast_encryption too small buf_out_size");
        return 0;
    }

    uint8_t iv[8];
    randombytes(iv, 8);

//    BF_KEY *key = a_key->priv_key_data;


    memcpy(a_out, iv, 8);
    BF_cbc_encrypt((unsigned char *)(a_in), a_out + 8, a_in_size,
                   a_key->priv_key_data, iv, BF_ENCRYPT);
    return a_out_size;
 }


void dap_enc_bf_cbc_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = NULL;
    a_key->_inheritor_size = 0;
    a_key->type = DAP_ENC_KEY_TYPE_BF_CBC;
    a_key->enc = dap_enc_bf_cbc_encrypt;
    a_key->dec = dap_enc_bf_cbc_decrypt;
    a_key->enc_na = dap_enc_bf_cbc_encrypt_fast;
    a_key->dec_na = dap_enc_bf_cbc_decrypt_fast;
}

//------OFB-----------

size_t dap_enc_bf_ofb_decrypt(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void ** a_out) {
    uint8_t iv[8];

    if(a_in_size <= 8) {
        log_it(L_ERROR, "blowfish_ofb decryption ct with iv must be more than 8 bytes");
        return 0;
    }


    *a_out = DAP_NEW_SIZE(uint8_t, a_in_size - 8);
    memcpy(iv, a_in, 8);
    int num = 0;//need for concatenate encryptions or decryptions
    BF_ofb64_encrypt((unsigned char *)(a_in + 8), *a_out, a_in_size - 8,
                   a_key->priv_key_data, iv, &num);
    size_t a_out_size = a_in_size - 8;
    return a_out_size;
}



size_t dap_enc_bf_ofb_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    //generate iv and put it in *a_out first bytes
    uint8_t iv[8];
    randombytes(iv, 8);

    if(a_in_size <= 0) {
        log_it(L_ERROR, "blowfish_ofb encryption pt cannot be 0 bytes");
        return 0;
    }




    size_t a_out_size = a_in_size + 8;
    *a_out = DAP_NEW_SIZE(uint8_t, a_out_size);
    memcpy(*a_out, iv, 8);
    int num = 0;//need for concatenate encryptions or decryptions
    BF_ofb64_encrypt((unsigned char *)(a_in), *a_out + 8, a_in_size,
                   a_key->priv_key_data, iv, &num);
    return a_out_size;
}

size_t dap_enc_bf_ofb_calc_encode_size(const size_t size_in)
{
    return size_in + 8;
}

size_t dap_enc_bf_ofb_calc_decode_size(const size_t size_in)
{
    if(size_in <= 8) {
        log_it(L_ERROR, "blowfish_ofb decryption size_in ct with iv must be more than 8 bytes");
        return 0;
    }
    return size_in - 8;
}

size_t dap_enc_bf_ofb_decrypt_fast(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void * a_out, size_t buf_out_size) {
    if(a_in_size - 8 > buf_out_size) {
        log_it(L_ERROR, "blowfish_ofb fast_decryption too small buf_out_size");
        return 0;
    }
    uint8_t iv[8];
    //BF_KEY *key=a_key->priv_key_data;

    memcpy(iv, a_in, 8);
    int num = 0;//need for concatenate encryptions or decryptions

    BF_ofb64_encrypt((unsigned char *)(a_in + 8), a_out, a_in_size - 8,
                   a_key->priv_key_data, iv, &num);

    size_t a_out_size = a_in_size - 8;
    return a_out_size;
}



size_t dap_enc_bf_ofb_encrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void * a_out,size_t buf_out_size)
{
    //generate iv and put it in *a_out first bytes
    size_t a_out_size = a_in_size + 8;
    if(a_out_size > buf_out_size) {
        log_it(L_ERROR, "blowfish_ofb fast_encryption too small buf_out_size");
        return 0;
    }

    uint8_t iv[8];
    randombytes(iv, 8);

    memcpy(a_out, iv, 8);
    int num = 0;//need for concatenate encryptions or decryptions
    BF_ofb64_encrypt((unsigned char *)(a_in), a_out + 8, a_in_size,
                   a_key->priv_key_data, iv, &num);
    return a_out_size;
 }
void dap_enc_bf_ofb_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = NULL;
    a_key->_inheritor_size = 0;
    a_key->type = DAP_ENC_KEY_TYPE_BF_OFB;
    a_key->enc = dap_enc_bf_ofb_encrypt;
    a_key->dec = dap_enc_bf_ofb_decrypt;
    a_key->enc_na = dap_enc_bf_ofb_encrypt_fast;
    a_key->dec_na = dap_enc_bf_ofb_decrypt_fast;
}


