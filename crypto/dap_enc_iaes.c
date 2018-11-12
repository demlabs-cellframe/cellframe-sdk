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
        log_it(L_ERROR, "Bad in size");
        return 0;
    }

    uint8_t *data = (uint8_t *)malloc(a_in_size);

    IAES_256_CBC_decrypt(a_in, data, DAP_ENC_AES_KEY(a_key)->ivec, a_in_size, a_key->priv_key_data);

    size_t padding = 0;
    size_t end = a_in_size-16 > 0 ? a_in_size-16 : 0;
    size_t i;
    for( i = a_in_size-1; i >= end; i--)
    {
        if(*(char*)(data + i) == (char)0)
            padding++;
        else
            break;
    }

    * a_out = (uint8_t *) malloc(a_in_size);
    memcpy(* a_out, data,(a_in_size));
    free(data);

    return a_in_size - padding;
}

size_t dap_enc_iaes256_cbc_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    size_t length_data_new;
    uint8_t *data_new;

    length_data_new = block128_padding(a_in, &data_new, a_in_size);
    *a_out = (uint8_t *)malloc(length_data_new);

    IAES_256_CBC_encrypt(data_new, *a_out, DAP_ENC_AES_KEY(a_key)->ivec, length_data_new, a_key->priv_key_data);

    free(data_new);
    return length_data_new;
}

///**
// * @brief dap_enc_aes_key_new_from_data
// * @param a_key
// * @param a_in
// * @param a_in_size
// */
//void dap_enc_aes_key_new_from_seed(struct dap_enc_key * a_key, const void * seed, size_t a_in_size)
//{
//    if(a_in_size < AES_KEYSIZE)
//        return;

//    a_key->last_used_timestamp = time(NULL);
//    a_key->priv_key_data = (unsigned char*)malloc(AES_KEYSIZE);
//    memcpy(a_key->priv_key_data,seed,AES_KEYSIZE);
//    a_key->priv_key_data_size = AES_KEYSIZE;
//    a_key->type=DAP_ENC_KEY_TYPE_AES;
//    a_key->enc=dap_enc_aes256_cbc_encrypt;
//    a_key->dec=dap_enc_aes256_cbc_decrypt;
//    a_key->delete_callback=dap_enc_aes_key_delete;
//}

///**
// * @brief dap_enc_aes_key_new_from_str
// * @param a_key
// * @param a_in
// * @param a_in_size
// */
//void dap_enc_aes_key_new_from_str(struct dap_enc_key * a_key, const char * a_in)
//{
//    if(strlen(a_in) < AES_KEYSIZE || a_key->priv_key_data_size != AES_KEYSIZE) {
//        log_it(L_ERROR, "bad input parameters");
//        return;
//    }

//    a_key->last_used_timestamp = time(NULL);
//    memcpy(a_key->priv_key_data , a_in, AES_KEYSIZE);
//}

