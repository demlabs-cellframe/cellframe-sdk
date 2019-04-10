#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "dap_enc_key.h"
#include "dap_enc_iaes.h"
#include "sha3/fips202.h"
#include "dap_common.h"


#define LOG_TAG "dap_enc_aes"

typedef struct dap_enc_aes_key {
    unsigned char ivec[IAES_BLOCK_SIZE];
} dap_enc_aes_key_t;

#define DAP_ENC_AES_KEY(a) ((dap_enc_aes_key_t *)((a)->_inheritor) )

void dap_enc_aes_key_delete(struct dap_enc_key *a_key)
{
    free(a_key->_inheritor);
    //No need any specific actions
}

/**
 * @brief dap_enc_aes_key_new_generate
 * @param a_key
 * @param a_size
 */
void dap_enc_aes_key_new(struct dap_enc_key * a_key)
{
    a_key->_inheritor = DAP_NEW_Z(dap_enc_aes_key_t);
    a_key->_inheritor_size = sizeof (dap_enc_aes_key_t);
    a_key->type = DAP_ENC_KEY_TYPE_IAES;
    a_key->enc = dap_enc_iaes256_cbc_encrypt;
    a_key->dec = dap_enc_iaes256_cbc_decrypt;
    a_key->enc_na = dap_enc_iaes256_cbc_encrypt_fast;
    a_key->dec_na = dap_enc_iaes256_cbc_decrypt_fast;
    //a_key->delete_callback = dap_enc_aes_key_delete;

    a_key->priv_key_data = (uint8_t *)malloc(IAES_KEYSIZE);
    a_key->priv_key_data_size = IAES_KEYSIZE;
}

void dap_enc_aes_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
                                                size_t kex_size, const void * seed, size_t seed_size,
                                                size_t key_size)
{
    (void)key_size;
    a_key->last_used_timestamp = time(NULL);

    uint8_t * id_concat_kex = (uint8_t *) malloc(kex_size + seed_size);

    memcpy(id_concat_kex,seed, seed_size);
    memcpy(id_concat_kex + seed_size, kex_buf, kex_size);
    shake256(a_key->priv_key_data, IAES_KEYSIZE, id_concat_kex, (kex_size + seed_size));
    shake128(DAP_ENC_AES_KEY(a_key)->ivec, IAES_BLOCK_SIZE, seed, seed_size);

    free(id_concat_kex);
}


/**
 * @brief ap_enc_aes256_cbc_decrypt
 * @param a_key
 * @param a_in
 * @param a_in_size
 * @param a_out
 * @return
 */

size_t dap_enc_iaes256_cbc_decrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    if (a_in_size % 16) {
        log_it(L_ERROR, "Bad in data size");
        return 0;
    }

    *a_out = (uint8_t *) malloc(a_in_size);

    return IAES_256_CBC_decrypt(a_in, *a_out, DAP_ENC_AES_KEY(a_key)->ivec, a_in_size, a_key->priv_key_data);
}

size_t dap_enc_iaes256_cbc_decrypt_fast(struct dap_enc_key * a_key, const void * a_in,
                                        size_t a_in_size, void * buf_out, size_t buf_out_size)
{
    if (a_in_size % 16) {
        log_it(L_ERROR, "Bad in size");
        return 0;
    } else if(buf_out_size < a_in_size) {
        log_it(L_ERROR, "buf_out_size < a_in_size");
        return 0;
    }

    return IAES_256_CBC_decrypt(a_in, buf_out, DAP_ENC_AES_KEY(a_key)->ivec,
                                a_in_size, a_key->priv_key_data);
}

size_t dap_enc_iaes256_cbc_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    size_t length_data_new;
    uint8_t *data_new;

    length_data_new = iaes_block128_padding(a_in, &data_new, a_in_size);
    *a_out = (uint8_t *)malloc(length_data_new);

    IAES_256_CBC_encrypt(data_new, *a_out, DAP_ENC_AES_KEY(a_key)->ivec, length_data_new, a_key->priv_key_data);

    free(data_new);
    return length_data_new;
}

size_t dap_enc_iaes256_calc_encode_size(const size_t size_in)
{
    return iaes_calc_block128_size(size_in);
}

size_t dap_enc_iaes256_calc_decode_size(const size_t size_in)
{
    return size_in;
}

size_t dap_enc_iaes256_cbc_encrypt_fast(struct dap_enc_key * a_key, const void * a_in,
                                        size_t a_in_size, void * buf_out, size_t buf_out_size)
{
    size_t out_size = iaes_calc_block128_size(a_in_size);

    if((a_in_size % IAES_BLOCK_SIZE) == 0) {
        IAES_256_CBC_encrypt(a_in, buf_out, DAP_ENC_AES_KEY(a_key)->ivec, out_size, a_key->priv_key_data);
        return out_size;
    }

    if(buf_out_size < out_size) {
        log_it(L_ERROR, "buf_out_size less than expected encrypt out size data");
        return 0;
    }
    uint8_t* data_in_new;
    iaes_block128_padding(a_in, &data_in_new, a_in_size);

    IAES_256_CBC_encrypt(data_in_new, buf_out, DAP_ENC_AES_KEY(a_key)->ivec,
                         out_size, a_key->priv_key_data);

    free(data_in_new);

    return out_size;
}
