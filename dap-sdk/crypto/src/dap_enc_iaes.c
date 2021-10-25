#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "dap_enc_key.h"
#include "dap_enc_iaes.h"
#include "sha3/fips202.h"

//#include "KeccakHash.h"
//#include "SimpleFIPS202.h"

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
    //SHAKE256(a_key->priv_key_data, IAES_KEYSIZE, id_concat_kex, (kex_size + seed_size));
    //SHAKE128(DAP_ENC_AES_KEY(a_key)->ivec, IAES_BLOCK_SIZE, seed, seed_size);
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
    if (a_in_size % IAES_BLOCK_SIZE) {
        log_it(L_ERROR, "Bad in data size");
        return 0;
    }

    *a_out = (uint8_t *) malloc(a_in_size);

    return dap_enc_iaes256_cbc_decrypt_fast(a_key, a_in, a_in_size, *a_out, a_in_size);
}

size_t dap_enc_iaes256_cbc_decrypt_fast(struct dap_enc_key * a_key, const void * a_in,
                                        size_t a_in_size, void * buf_out, size_t buf_out_size)
{
    if (a_in_size % IAES_BLOCK_SIZE) {
        log_it(L_ERROR, "Bad in size");
        return 0;
    } else if(buf_out_size < a_in_size) {
        log_it(L_ERROR, "buf_out_size < a_in_size");
        return 0;
    }

    size_t block_in32_size = IAES_BLOCK_SIZE/sizeof(uint32_t);
    uint32_t round_decrypt_key[60];
    uint32_t feedback[block_in32_size];
    uint8_t priv_key_swapped_endian[IAES_KEYSIZE];

    memcpy(&feedback[0], DAP_ENC_AES_KEY(a_key)->ivec, IAES_BLOCK_SIZE);
    memcpy(priv_key_swapped_endian, a_key->priv_key_data, sizeof(priv_key_swapped_endian));

    swap_endian((uint32_t*)priv_key_swapped_endian, sizeof(priv_key_swapped_endian)/sizeof(uint32_t));
    Key_Shedule_for_decrypT((uint32_t*)priv_key_swapped_endian, round_decrypt_key);

    void *data = buf_out;
    const void *cdata = a_in;
    size_t count_block, count32_word;
    for(count_block = 0; count_block < (a_in_size/IAES_BLOCK_SIZE); count_block++){

        AES256_dec_cernelT((uint32_t *)cdata + count_block*block_in32_size,
                           (uint32_t *)data + count_block*block_in32_size, round_decrypt_key);

        for (count32_word = 0; count32_word < block_in32_size; count32_word++)
            *((uint32_t *)data + count_block * block_in32_size + count32_word) ^= feedback[count32_word];
        memcpy(&feedback[0], (uint32_t *)cdata + count_block*block_in32_size, IAES_BLOCK_SIZE);
    }
//    for(int i = 0; i < 16; ++i)
//    {printf("%.2x ", ((uint8_t*)data)[i]);}
//    printf("\n");fflush(stdout);

    size_t l_padding_size = ((uint8_t *)data)[a_in_size - 1];
    if(l_padding_size > a_in_size){
        log_it(L_WARNING, "%s: padding size is %zu while whole message is just %zu", __PRETTY_FUNCTION__, l_padding_size, a_in_size);
        return 0;
    }else{
        return a_in_size - l_padding_size;
    }
}

size_t dap_enc_iaes256_cbc_encrypt(struct dap_enc_key * a_key, const void * a_in, size_t a_in_size, void ** a_out)
{
    size_t length_data_new;

    length_data_new = dap_enc_iaes256_calc_encode_size(a_in_size);

     *a_out = DAP_NEW_SIZE(uint8_t, length_data_new);

    dap_enc_iaes256_cbc_encrypt_fast(a_key, a_in, a_in_size, *a_out, length_data_new);
    return length_data_new;
}

size_t dap_enc_iaes256_calc_encode_size(const size_t size_in)
{
    return size_in + 1 + (IAES_BLOCK_SIZE - (size_in + 1)%IAES_BLOCK_SIZE)%IAES_BLOCK_SIZE;
}

size_t dap_enc_iaes256_calc_decode_max_size(const size_t size_in)
{
    return size_in;
}

size_t dap_enc_iaes256_cbc_encrypt_fast(struct dap_enc_key * a_key, const void * a_in,
                                        size_t a_in_size, void * buf_out, size_t buf_out_size)
{
    size_t out_size = dap_enc_iaes256_calc_encode_size(a_in_size);
    if(buf_out_size < out_size) {
        log_it(L_ERROR, "buf_out_size less than expected encrypt out size data");
        return 0;
    }

    int last_block_from_in = a_in_size%IAES_BLOCK_SIZE;

    size_t block_in32_size = IAES_BLOCK_SIZE/sizeof(uint32_t);
    uint32_t feedback[block_in32_size];
    uint8_t priv_key_swapped_endian[IAES_KEYSIZE];
    memcpy(priv_key_swapped_endian, a_key->priv_key_data, sizeof(priv_key_swapped_endian));

    memcpy(&feedback[0], DAP_ENC_AES_KEY(a_key)->ivec, IAES_BLOCK_SIZE);
    swap_endian((uint32_t *)priv_key_swapped_endian, IAES_KEYSIZE/sizeof(uint32_t));

    size_t count_block, count32_word;
    const void *data = a_in;
    void *cdata = buf_out;
    for(count_block = 0; count_block < (a_in_size - last_block_from_in)/IAES_BLOCK_SIZE; count_block++)
    {
        for (count32_word = 0; count32_word < block_in32_size; count32_word++)
           *((uint32_t *)cdata + count_block * block_in32_size + count32_word) =
                *((uint32_t *)data + count_block * block_in32_size + count32_word) ^ feedback[count32_word];

        AES256_enc_cernelT(((uint32_t *)cdata + count_block * block_in32_size), feedback, (uint32_t *)priv_key_swapped_endian);

        memcpy ((uint32_t *)cdata + count_block * block_in32_size, &feedback[0], IAES_BLOCK_SIZE);
    }
    uint8_t tmp_in[IAES_BLOCK_SIZE];
    memcpy(tmp_in, a_in + a_in_size/IAES_BLOCK_SIZE*IAES_BLOCK_SIZE, last_block_from_in);
    int padd_size = IAES_BLOCK_SIZE - last_block_from_in;
    for(int padd_num = 0; padd_num < padd_size - 1; ++padd_num)
        tmp_in[last_block_from_in + padd_num] = 16;

    tmp_in[IAES_BLOCK_SIZE - 1] = padd_size;

    for (count32_word = 0; count32_word < block_in32_size; count32_word++)
       *((uint32_t *)cdata + count_block * block_in32_size + count32_word) =
            *((uint32_t *)tmp_in + count32_word) ^ feedback[count32_word];

    AES256_enc_cernelT(((uint32_t *)cdata + count_block * block_in32_size), feedback, (uint32_t *)priv_key_swapped_endian);

    memcpy ((uint32_t *)cdata + count_block * block_in32_size, &feedback[0], IAES_BLOCK_SIZE);


//    IAES_256_CBC_encrypt(a_in, buf_out, DAP_ENC_AES_KEY(a_key)->ivec, a_in_size - last_block_from_in, a_key->priv_key_data);
//    uint8_t tmp_in[IAES_BLOCK_SIZE];
//    memcpy(tmp_in, a_in + a_in_size/IAES_BLOCK_SIZE*IAES_BLOCK_SIZE, last_block_from_in);
//    int padd_size = IAES_BLOCK_SIZE - last_block_from_in;
//    for(int padd_num = 0; padd_num < padd_size; ++padd_num)
//        tmp_in[last_block_from_in + padd_num] = 16;

//    tmp_in[last_block_from_in + IAES_BLOCK_SIZE - 1] = padd_size;
//    IAES_256_CBC_encrypt(tmp_in, buf_out + a_in_size - last_block_from_in, buf_out + a_in_size - last_block_from_in - IAES_BLOCK_SIZE, IAES_BLOCK_SIZE, a_key->priv_key_data);

    return out_size;
}
