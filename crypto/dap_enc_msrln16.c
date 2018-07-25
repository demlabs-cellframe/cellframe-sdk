#include "dap_common.h"
#include "dap_enc_msrln16.h"
#include "dap_enc_aes.h"

#include "liboqs/crypto/rand/rand.h"
#include "liboqs/kex_rlwe_msrln16/kex_rlwe_msrln16.h"
#include "liboqs/kex/kex.h"
#include <string.h>

#define LOG_TAG "dap_enc_msrln16"


OQS_KEX *kex = NULL;

void *alignce_priv = NULL;
uint8_t *alice_msg = NULL;
size_t alice_msg_len;
uint8_t *alice_key = NULL;
size_t alice_key_len;

uint8_t *bob_msg = NULL;
size_t bob_msg_len;
uint8_t *bob_key = NULL;
size_t bob_key_len;


#define PRINT_HEX_STRING(label, str, len)                        \
    {   size_t i;                                                \
        printf("%-20s (%4zu bytes):  ", (label), (size_t)(len)); \
        for (i = 0; i < (len); i++) {                            \
         printf("%02X", ((unsigned char *) (str))[i]);           \
        }                                                        \
        printf("\n");                                            \
    }


/**
 * @brief dap_enc_msrln16_key_new_generate
 * @param a_key Struct for new key
 * @param a_size Not used
 */

void dap_enc_msrln16_key_new_generate(struct dap_enc_key* a_key, size_t a_size)//(OQS_RAND* rand)
{
    (void)a_size;
    if (a_key == NULL) {
        return;
    }
    
    a_key->_inheritor = (dap_enc_msrln16_key_t*)malloc(sizeof(dap_enc_msrln16_key_t));

    a_key->type = DAP_ENC_KEY_TYPE_RLWE_MSRLN16;
    a_key->dec=dap_enc_aes_decode;
    a_key->enc=dap_enc_aes_encode;
    dap_enc_msrln16_key_t *msrln16_a_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(a_key);
    msrln16_a_key->private_key = NULL;
}

/**
 * @brief dap_enc_msrln16_key_new_from_data
 * @param k
 * @param alice_priv
 * @param bob_msg
 * @param bob_msg_len
 * @param key
 * @param key_len
 */

void dap_enc_msrln16_key_new_from_data(struct dap_enc_key *a_key, const void *a_in, size_t a_in_size)
{
    (void)a_key;
    (void)a_in;
    (void)a_in_size;
}

/**
 * @brief dap_enc_msrln16_key_new_from_data_public
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_msrln16_key_new_from_data_public(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size)
{
    (void)a_key;
    (void)a_in;
    (void)a_in_size;
}

/**
 * @brief dap_kex_rlwe_msrln16_new
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
OQS_KEX *dap_kex_rlwe_msrln16_new(OQS_RAND *rand){
    return OQS_KEX_rlwe_msrln16_new(rand);
}

/**
 * @brief dap_rlwe_msrln16_alice_0
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
int dap_rlwe_msrln16_alice_0(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len){
    return OQS_KEX_rlwe_msrln16_alice_0(k, alice_priv, alice_msg, alice_msg_len);
}

/**
 * @brief dap_rlwe_msrln16_alice_1
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
int dap_rlwe_msrln16_alice_1(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len){
    return OQS_KEX_rlwe_msrln16_alice_1(k,alice_priv,bob_msg,bob_msg_len,key,key_len);
}

/**
 * @brief dap_enc_msrln16_key_delete
 * @param a_key
 */
void dap_enc_msrln16_key_delete(struct dap_enc_key* a_key)
{
    (void) a_key;
    if(!a_key){
        return;
    }
    DAP_DELETE(a_key);
}

/**
 * @brief dap_enc_msrln16_key_public_base64
 * @param a_key
 * @return
 */
char* dap_enc_msrln16_key_public_base64(dap_enc_key_t *a_key)
{
    (void)a_key;
    return NULL;
}

/**
 * @brief dap_enc_msrln16_key_public_raw
 * @param a_key
 * @param a_key_public
 * @return
 */
size_t dap_enc_msrln16_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public)
{
    (void)a_key;
    (void)a_key_public;
    return 0;
}

/**
 * @brief dap_enc_msrln16_decode
 * @param k
 * @param alice_msg
 * @param alice_msg_len
 * @param bob_msg
 * @param bob_msg_len
 * @param key
 * @param key_len
 * @return
 */
size_t dap_enc_msrln16_decode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
    return dap_enc_aes_decode(a_key,a_in,a_in_size,a_out);
}

/**
 * @brief dap_enc_msrln16_encode
 * @param k
 * @param alice_priv
 * @param alice_msg
 * @param alice_msg_len
 * @return
 */
size_t dap_enc_msrln16_encode(struct dap_enc_key* a_key, const void * a_in, size_t a_in_size,void * a_out)
{
    return dap_enc_aes_encode(a_key,a_in,a_in_size,a_out);
}

/**
 * @brief aes_key_from_msrln_pub
 * @param key Key for conversion
 */
void aes_key_from_msrln_pub(dap_enc_key_t* key){
    dap_enc_msrln16_key_t* msrln_key = DAP_ENC_KEY_TYPE_RLWE_MSRLN16(key);
    key->data = (unsigned char *)malloc(16);
    memcpy(key->data,msrln_key->public_key,16);
    key->data_size = 16;
}


