#include <string.h>
#include "dap_common.h"
#include "dap_enc_msrln.h"
#include "msrln/msrln.h"


#define LOG_TAG "dap_enc_msrln"

void dap_enc_msrln_key_new(struct dap_enc_key* a_key)
{
    a_key->type = DAP_ENC_KEY_TYPE_MSRLN;
    a_key->dec = NULL;
    a_key->enc = NULL;
    a_key->gen_bob_shared_key = (dap_enc_gen_bob_shared_key)dap_enc_msrln_gen_bob_shared_key;
    a_key->gen_alice_shared_key = (dap_enc_gen_alice_shared_key)dap_enc_msrln_gen_alice_shared_key;
    a_key->priv_key_data_size = 0;
    a_key->pub_key_data_size = 0;
}

///**
// * @brief dap_enc_msrln_key_new_generate
// * @param a_key Struct for new key
// * @param a_size Not used
// */
//void dap_enc_msrln_key_new_generate(struct dap_enc_key* a_key, size_t a_size)
//{
//    (void)a_size;
//    a_key = DAP_NEW(dap_enc_key_t);
//    if(a_key == NULL) {
//        log_it(L_ERROR, "Can't allocate memory for key");
//        return;
//    }

//    a_key->type = DAP_ENC_KEY_TYPE_MSRLN;
//    a_key->dec = dap_enc_msrln_decode;
//    a_key->enc = dap_enc_msrln_encode;
//    a_key->_inheritor = DAP_NEW_Z(dap_enc_msrln_key_t);
//    //a_key->delete_callback = dap_enc_msrln_key_delete;
//}

/**
 * @brief dap_enc_msrln_key_generate
 * @param a_key
 * @param kex_buf
 * @param kex_size
 * @param seed
 * @param seed_size
 * @param key_size
 * @details allocate memory and generate private and public key
 */
void dap_enc_msrln_key_generate(struct dap_enc_key * a_key, const void *kex_buf,
                                size_t kex_size, const void * seed, size_t seed_size,
                                size_t key_size)
{
    (void)kex_buf; (void)kex_size;
    (void)seed; (void)seed_size; (void)key_size;

    /* alice_msg is alice's public key */
    a_key->pub_key_data = NULL;
    a_key->pub_key_data = malloc(MSRLN_PKA_BYTES);
    a_key->pub_key_data_size = MSRLN_PKA_BYTES;
    if(a_key->pub_key_data == NULL) {
        abort();
    }

    a_key->priv_key_data = malloc(MSRLN_PKA_BYTES * sizeof(uint32_t));
    if(a_key->priv_key_data == NULL){
        abort();
    }

    PLatticeCryptoStruct PLCS = LatticeCrypto_allocate();
    LatticeCrypto_initialize(PLCS, (RandomBytes)randombytes, MSRLN_generate_a, MSRLN_get_error);

    if (MSRLN_KeyGeneration_A((int32_t *) a_key->priv_key_data,
                              (unsigned char *) a_key->pub_key_data, PLCS) != CRYPTO_MSRLN_SUCCESS) {
        abort();
    }
    free(PLCS);
    a_key->priv_key_data_size = MSRLN_SHAREDKEY_BYTES;

    return;
}


/**
 * @brief dap_enc_msrln16_encode
 * @param k
 * @param alice_priv
 * @param alice_msg
 * @param alice_msg_len
 * @return
 */
size_t dap_enc_msrln_gen_bob_shared_key(struct dap_enc_key* b_key, const void* a_pub, size_t a_pub_size, void ** b_pub)
{
    size_t ret;

    uint8_t *bob_tmp_pub = NULL;

    *b_pub = NULL;
    if(b_key->priv_key_data_size == 0) { // need allocate mamory for priv key
        b_key->priv_key_data = malloc(MSRLN_SHAREDKEY_BYTES);
        b_key->priv_key_data_size = MSRLN_SHAREDKEY_BYTES;
    }
 //   b_key->priv_key_data = NULL;

    if(a_pub_size != MSRLN_PKA_BYTES) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->priv_key_data);
        b_key->priv_key_data = NULL;
        return ret;
    }

    *b_pub = malloc(MSRLN_PKB_BYTES);
    if(b_pub == NULL) {
        ret = 0;
        DAP_DELETE(b_key->priv_key_data);
        b_key->priv_key_data = NULL;
        return ret;
    }
    bob_tmp_pub = *b_pub;

//    b_key->priv_key_data = malloc(MSRLN_SHAREDKEY_BYTES);
    if(b_key->priv_key_data == NULL) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        return ret;
    }

    PLatticeCryptoStruct PLCS = LatticeCrypto_allocate();
    LatticeCrypto_initialize(PLCS, (RandomBytes)randombytes, MSRLN_generate_a, MSRLN_get_error);
    if (MSRLN_SecretAgreement_B((unsigned char *) a_pub, (unsigned char *) b_key->priv_key_data, (unsigned char *) bob_tmp_pub, PLCS) != CRYPTO_MSRLN_SUCCESS) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->priv_key_data);
        b_key->priv_key_data = NULL;
        return ret;
    }
    free(PLCS);

    b_key->priv_key_data_size = MSRLN_SHAREDKEY_BYTES;
    b_key->pub_key_data_size = MSRLN_PKB_BYTES;
 //   *a_pub_size = MSRLN_PKB_BYTES;

    ret = 1;
    return ret;
}

/**
 * @brief dap_enc_msrln_decode
 * @param k
 * @param alice_msg
 * @param alice_msg_len
 * @param bob_msg
 * @param bob_msg_len
 * @param key
 * @param key_len
 * @return
 */
size_t dap_enc_msrln_gen_alice_shared_key(struct dap_enc_key* a_key, const void* a_priv, const size_t b_key_len, unsigned char * b_pub)
{
    size_t ret = 1;

    if(a_key->priv_key_data_size == 0) { // need allocate mamory for priv key
        a_key->priv_key_data = malloc(MSRLN_SHAREDKEY_BYTES);
        a_key->priv_key_data_size = MSRLN_SHAREDKEY_BYTES;
    }


    if(a_key->priv_key_data == NULL || b_key_len != MSRLN_PKB_BYTES) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        a_priv = NULL;
        DAP_DELETE(a_key->priv_key_data);
        a_key->priv_key_data = NULL;
    }

    if (MSRLN_SecretAgreement_A((unsigned char *) b_pub, (int32_t *) a_priv, (unsigned char *) a_key->priv_key_data) != CRYPTO_MSRLN_SUCCESS) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        a_priv = NULL;
        DAP_DELETE(a_key->priv_key_data);
        a_key->priv_key_data = NULL;
    }

    a_key->priv_key_data_size = MSRLN_SHAREDKEY_BYTES;

    return ret;
}

/**
 * @brief dap_enc_msrln_key_new_from_data_public
 * @param a_key
 * @param a_in
 * @param a_in_size
 */
void dap_enc_msrln_key_new_from_data_public(dap_enc_key_t * a_key, const void * a_in, size_t a_in_size)
{
    (void)a_key;
    (void)a_in;
    (void)a_in_size;
}

/**
 * @brief dap_enc_msrln_key_delete
 * @param a_key
 */
void dap_enc_msrln_key_delete(struct dap_enc_key* a_key)
{
    (void) a_key;
    if(!a_key){
        return;
    }
//    DAP_DELETE(a_key);
}

/**
 * @brief dap_enc_msrln_key_public_base64
 * @param a_key
 * @return
 */
char* dap_enc_msrln_key_public_base64(dap_enc_key_t *a_key)
{
    (void)a_key;
    return NULL;
}

/**
 * @brief dap_enc_msrln_key_public_raw
 * @param a_key
 * @param a_key_public
 * @return
 */
size_t dap_enc_msrln_key_public_raw(dap_enc_key_t *a_key, void ** a_key_public)
{
    (void)a_key;
    (void)a_key_public;
    return 0;
}
