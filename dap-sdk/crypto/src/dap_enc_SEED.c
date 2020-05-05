#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dap_enc_SEED.h"
#include "dap_common.h"
#include "rand/dap_rand.h"
#include "sha3/KeccakHash.h"

#define LOG_TAG "dap_enc_seed"
//#  define SEED_BLOCK_SIZE 16
//#  define SEED_KEY_LENGTH 16

void dap_enc_seed_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size, size_t key_size)
{
    if(key_size < SEED_KEY_LENGTH)
    {
        log_it(L_ERROR, "seed key cannot be less than SEED_KEY_LENGTH bytes.");
    }
    a_key->last_used_timestamp = time(NULL);


    a_key->priv_key_data_size = SEED_KEY_LENGTH;
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t, a_key->priv_key_data_size);

    Keccak_HashInstance Keccak_ctx;
    Keccak_HashInitialize(&Keccak_ctx, 1088,  512, a_key->priv_key_data_size*8, 0x06);
    Keccak_HashUpdate(&Keccak_ctx, kex_buf, kex_size*8);
    if(seed_size)
        Keccak_HashUpdate(&Keccak_ctx, seed, seed_size*8);
    Keccak_HashFinal(&Keccak_ctx, a_key->priv_key_data);
}

void dap_enc_seed_key_delete(struct dap_enc_key *a_key)
{
    if(a_key->priv_key_data != NULL)
    {
        randombytes(a_key->priv_key_data,a_key->priv_key_data_size);
        //DAP_DELETE(a_key->priv_key_data);
    }
    //a_key->priv_key_data_size = 0;
}
//------SEED_OFB-----------
void dap_enc_seed_ofb_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = NULL;
    a_key->_inheritor_size = 0;
    a_key->type = DAP_ENC_KEY_TYPE_SEED_OFB;
    a_key->enc = dap_enc_seed_ofb_encrypt;
    a_key->dec = dap_enc_seed_ofb_decrypt;
    a_key->enc_na = dap_enc_seed_ofb_encrypt_fast;
    a_key->dec_na = dap_enc_seed_ofb_decrypt_fast;
}


size_t dap_enc_seed_ofb_decrypt(struct dap_enc_key *a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    size_t l_out_size = a_in_size - SEED_BLOCK_SIZE;
    if(l_out_size <= 0) {
        log_it(L_ERROR, "seed_ofb decryption ct with iv must be more than SEED_BLOCK_SIZE bytes");
        return 0;
    }
    *a_out = DAP_NEW_SIZE(uint8_t, a_in_size - SEED_BLOCK_SIZE);
    l_out_size = dap_enc_seed_ofb_decrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(l_out_size == 0)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}

size_t dap_enc_seed_ofb_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    if(a_in_size <= 0) {
        log_it(L_ERROR, "seed ofb encryption pt cannot be 0 bytes");
        return 0;
    }
    size_t l_out_size = a_in_size + SEED_BLOCK_SIZE;
    *a_out = DAP_NEW_SIZE(uint8_t, l_out_size);
    l_out_size = dap_enc_seed_ofb_encrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(l_out_size == 0)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}

size_t dap_enc_seed_ofb_calc_encode_size(const size_t size_in)
{
    return size_in + SEED_BLOCK_SIZE;
}

size_t dap_enc_seed_ofb_calc_decode_size(const size_t size_in)
{
    if(size_in <= SEED_BLOCK_SIZE) {
        log_it(L_ERROR, "seed_ofb decryption size_in ct with iv must be more than SEED_BLOCK_SIZE bytes");
        return 0;
    }
    return size_in - SEED_BLOCK_SIZE;
}

size_t dap_enc_seed_ofb_decrypt_fast(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void * a_out, size_t buf_out_size) {
    size_t l_out_size = a_in_size - SEED_BLOCK_SIZE;
    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "seed_ofb fast_decryption too small buf_out_size");
        return 0;
    }
    uint8_t iv[SEED_BLOCK_SIZE];
    memcpy(iv, a_in, SEED_BLOCK_SIZE);
    SEED_KEY_SCHEDULE ctx;
    SEED_set_key(a_key->priv_key_data, &ctx);
    int num = 0;
    SEED_ofb128_encrypt(a_in + SEED_BLOCK_SIZE, a_out, a_in_size - SEED_BLOCK_SIZE, &ctx, iv, &num);
    return l_out_size;
}

size_t dap_enc_seed_ofb_encrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void * a_out,size_t buf_out_size)
{
    //generate iv and put it in *a_out first bytes
    size_t l_out_size = a_in_size + SEED_BLOCK_SIZE;
    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "seed_ofb fast_encryption too small buf_out_size");
        return 0;
    }
    uint8_t iv[SEED_BLOCK_SIZE];
    if(randombytes(iv, SEED_BLOCK_SIZE) == 1)
    {
        log_it(L_ERROR, "failed to get SEED_BLOCK_SIZE bytes iv seed ofb");
        return 0;
    }
    memcpy(a_out, iv, SEED_BLOCK_SIZE);
    SEED_KEY_SCHEDULE ctx;
    SEED_set_key(a_key->priv_key_data, &ctx);
    int num = 0;
    SEED_ofb128_encrypt(a_in, a_out + SEED_BLOCK_SIZE, a_in_size, &ctx, iv, &num);
    return l_out_size;
 }
