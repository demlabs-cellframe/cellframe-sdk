#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "dap_enc_salsa2012.h"
#include "dap_common.h"
#include "rand/dap_rand.h"
#include "sha3/KeccakHash.h"

#define LOG_TAG "dap_enc_salsa2012"
#define SALSA20_KEY_SIZE 32
#define SALSA20_NONCE_SIZE 8

/**
 * @brief dap_enc_salsa2012_key_generate
 * 
 * Generate key for Salsa20 crypto alghorithm. Key is stored in a_key->priv_key_data
 * 
 * @param a_key - dap_enc_key key descriptor
 * @param kex_buf - 
 * @param kex_size 
 * @param seed 
 * @param seed_size 
 * @param key_size 
 */
void dap_enc_salsa2012_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size, size_t key_size)
{
    if(key_size < SALSA20_KEY_SIZE)
    {
        log_it(L_ERROR, "SALSA20 key cannot be less than 32 bytes but got %zd",key_size);
    }
    a_key->last_used_timestamp = time(NULL);


    a_key->priv_key_data_size = SALSA20_KEY_SIZE;
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t, a_key->priv_key_data_size);

    Keccak_HashInstance Keccak_ctx;
    Keccak_HashInitialize(&Keccak_ctx, 1088,  512, a_key->priv_key_data_size*8, 0x06);
    Keccak_HashUpdate(&Keccak_ctx, kex_buf, kex_size*8);
    if(seed_size)
        Keccak_HashUpdate(&Keccak_ctx, seed, seed_size*8);
    Keccak_HashFinal(&Keccak_ctx, a_key->priv_key_data);
}

/**
 * @brief dap_enc_salsa2012_key_delete 
 * 
 * @param a_key 
 */
void dap_enc_salsa2012_key_delete(struct dap_enc_key *a_key)
{
    if(a_key->priv_key_data != NULL)
    {
        randombytes(a_key->priv_key_data,a_key->priv_key_data_size);
        //DAP_DELETE(a_key->priv_key_data);
    }
    //a_key->priv_key_data_size = 0;
}

//------SALSA2012-----------
/**
 * @brief dap_enc_salsa2012_key_new
 * 
 * @param a_key 
 */
void dap_enc_salsa2012_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = NULL;
    a_key->_inheritor_size = 0;
    a_key->type = DAP_ENC_KEY_TYPE_SALSA2012;
    a_key->enc = dap_enc_salsa2012_encrypt;
    a_key->dec = dap_enc_salsa2012_decrypt;
    a_key->enc_na = dap_enc_salsa2012_encrypt_fast;
    a_key->dec_na = dap_enc_salsa2012_decrypt_fast;
}

/**
 * @brief dap_enc_salsa2012_decrypt
 * 
 * @param a_key 
 * @param a_in 
 * @param a_in_size 
 * @param a_out 
 * @return size_t 
 */
size_t dap_enc_salsa2012_decrypt(struct dap_enc_key *a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    size_t l_out_size = a_in_size - SALSA20_NONCE_SIZE;
    if(l_out_size <= 0) {
        log_it(L_ERROR, "salsa2012 decryption ct with iv must be more than kBlockLen89 bytes");
        return 0;
    }
    *a_out = DAP_NEW_SIZE(uint8_t, a_in_size - SALSA20_NONCE_SIZE);
    l_out_size = dap_enc_salsa2012_decrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(l_out_size == 0)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}

/**
 * @brief dap_enc_salsa2012_encrypt
 * 
 * @param a_key 
 * @param a_in 
 * @param a_in_size 
 * @param a_out 
 * @return size_t 
 */
size_t dap_enc_salsa2012_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    if(a_in_size <= 0) {
        log_it(L_ERROR, "gost ofb encryption pt cannot be 0 bytes");
        return 0;
    }
    size_t l_out_size = a_in_size + SALSA20_NONCE_SIZE;
    *a_out = DAP_NEW_SIZE(uint8_t, l_out_size);
    l_out_size = dap_enc_salsa2012_encrypt_fast(a_key, a_in, a_in_size, *a_out, l_out_size);
    if(l_out_size == 0)
        DAP_DEL_Z(*a_out);
    return l_out_size;
}

/**
 * @brief dap_enc_salsa2012_calc_encode_size
 * 
 * @param size_in 
 * @return size_t 
 */
size_t dap_enc_salsa2012_calc_encode_size(const size_t size_in)
{
    return size_in + SALSA20_NONCE_SIZE;
}

/**
 * @brief dap_enc_salsa2012_calc_decode_size
 * 
 * @param size_in 
 * @return size_t 
 */
size_t dap_enc_salsa2012_calc_decode_size(const size_t size_in)
{
    if(size_in <= SALSA20_NONCE_SIZE) {
        log_it(L_ERROR, "salsa2012 decryption size_in ct with iv must be more than kBlockLen89 bytes");
        return 0;
    }
    return size_in - SALSA20_NONCE_SIZE;
}

/**
 * @brief dap_enc_salsa2012_decrypt_fast
 * 
 * @param a_key 
 * @param a_in 
 * @param a_in_size 
 * @param a_out 
 * @param buf_out_size 
 * @return size_t 
 */
size_t dap_enc_salsa2012_decrypt_fast(struct dap_enc_key *a_key, const void * a_in,
        size_t a_in_size, void * a_out, size_t buf_out_size) {
    size_t l_out_size = a_in_size - SALSA20_NONCE_SIZE;
    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "salsa2012 fast_decryption too small buf_out_size");
        return 0;
    }

    //memcpy(nonce, a_in, SALSA20_NONCE_SIZE);
    crypto_stream_salsa2012_xor(a_out, a_in + SALSA20_NONCE_SIZE, a_in_size - SALSA20_NONCE_SIZE, a_in, a_key->priv_key_data);
    return l_out_size;
}

/**
 * @brief dap_enc_salsa2012_encrypt_fast
 * 
 * @param a_key 
 * @param a_in 
 * @param a_in_size 
 * @param a_out 
 * @param buf_out_size 
 * @return size_t 
 */
size_t dap_enc_salsa2012_encrypt_fast(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void * a_out,size_t buf_out_size)
{
    size_t l_out_size = a_in_size + SALSA20_NONCE_SIZE;
    if(l_out_size > buf_out_size) {
        log_it(L_ERROR, "salsa2012 fast_encryption too small buf_out_size");
        return 0;
    }

    if(randombytes(a_out, SALSA20_NONCE_SIZE) == 1)
    {
        log_it(L_ERROR, "failed to get SALSA20_NONCE_SIZE bytes nonce");
        return 0;
    }

    crypto_stream_salsa2012_xor(a_out + SALSA20_NONCE_SIZE, a_in, a_in_size, a_out, a_key->priv_key_data);
    return l_out_size;
 }

