#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

//#include "oaes_lib.h"
#include "dap_enc_bf_cbc.h"
#include "dap_common.h"
#include "rand/dap_rand.h"
#include"sha3/KeccakHash.h"

#define LOG_TAG "dap_enc_bf_cbc"

//todo clear l/8 and iv things
size_t dap_enc_bf_cbc_decrypt(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void ** a_out) {
    uint8_t iv[8];
    //BF_KEY *key=a_key->priv_key_data;


    *a_out = DAP_NEW_SIZE(uint8_t, a_in_size - 8);
    memcpy(iv, a_in, 8);
    BF_cbc_encrypt((unsigned char *)(a_in + 8), *a_out, a_in_size - 8,
                   a_key->priv_key_data, iv, BF_DECRYPT);
    size_t a_out_size = a_in_size - 8;
    return a_out_size;
}



size_t dap_enc_bf_cbc_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    //generate iv and put it in *a_out first bytes
    uint8_t iv[8];
    randombytes(iv, 8);

//    BF_KEY *key = a_key->priv_key_data;


    *a_out = DAP_NEW_SIZE(uint8_t, a_in_size + 8);
    memcpy(*a_out, iv, 8);
    BF_cbc_encrypt((unsigned char *)(a_in), *a_out + 8, a_in_size,
                   a_key->priv_key_data, iv, BF_ENCRYPT);
    size_t a_out_size = a_in_size + 8;
    return a_out_size;
}

size_t dap_enc_bf_cbc_calc_encode_size(const size_t size_in)
{
    return size_in + 8;
}

size_t dap_enc_bf_cbc_calc_decode_size(const size_t size_in)
{
    return size_in - 8;
}

size_t dap_enc_bf_cbc_decrypt_fast(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void * a_out,size_t buf_out_size) {
    uint8_t iv[8];
    //BF_KEY *key=a_key->priv_key_data;


    memcpy(iv, a_in, 8);
    BF_cbc_encrypt((unsigned char *)(a_in + 8), a_out, a_in_size - 8,
                   a_key->priv_key_data, iv, BF_DECRYPT);
    size_t a_out_size = a_in_size - 8;
    return a_out_size;
}



size_t dap_enc_bf_cbc_encrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void * a_out,size_t buf_out_size)
{
    //generate iv and put it in *a_out first bytes
    uint8_t iv[8];
    randombytes(iv, 8);

//    BF_KEY *key = a_key->priv_key_data;


    memcpy(a_out, iv, 8);
    BF_cbc_encrypt((unsigned char *)(a_in), a_out + 8, a_in_size,
                   a_key->priv_key_data, iv, BF_ENCRYPT);
    size_t a_out_size = a_in_size + 8;
    return a_out_size;
 }


void dap_enc_bf_cbc_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = NULL;//(uint8_t *) bf_cbc_alloc();
    a_key->_inheritor_size = 0;//sizeof(bf_cbc_ctx);
    a_key->type = DAP_ENC_KEY_TYPE_BF_CBC;
    a_key->enc = dap_enc_bf_cbc_encrypt;
    a_key->dec = dap_enc_bf_cbc_decrypt;
    a_key->enc_na = dap_enc_bf_cbc_encrypt_fast;//maybe exclude it
    a_key->dec_na = dap_enc_bf_cbc_decrypt_fast;//maybe exclude it
}

void dap_enc_bf_cbc_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
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
 }
void dap_enc_bf_cbc_key_delete(struct dap_enc_key *a_key)
{
    if(a_key->priv_key_data != NULL)
    {
        randombytes(a_key->priv_key_data,a_key->priv_key_data_size);
        DAP_DELETE(a_key->priv_key_data);
    }
    a_key->priv_key_data_size = 0;
}

#ifdef NOT_REVISED_YET







// Writes result ( out ) in already allocated buffer
size_t dap_enc_bf_cbc_decrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size,
        void * buf_out, size_t buf_out_size)
{
    OAES_CTX *ctx = get_bf_cbc_ctx(a_key);
    if(!ctx)
        return 0;

    OAES_RET ret = bf_cbc_decrypt(ctx, a_in, a_in_size, buf_out, &buf_out_size);
    if(ret != OAES_RET_SUCCESS) {
        buf_out_size = 0;
    }
    return buf_out_size;
}

// Writes result ( out ) in already allocated buffer
size_t dap_enc_bf_cbc_encrypt_fast(struct dap_enc_key * a_key, const void * a_in,
        size_t a_in_size, void * buf_out, size_t buf_out_size)
{
    OAES_CTX *ctx = get_bf_cbc_ctx(a_key);
    if(!ctx)
        return 0;

    OAES_RET ret = bf_cbc_encrypt(ctx, a_in, a_in_size, buf_out, &buf_out_size);
    if(ret != OAES_RET_SUCCESS) {
        buf_out_size = 0;
    }
    return buf_out_size;
}

#endif
