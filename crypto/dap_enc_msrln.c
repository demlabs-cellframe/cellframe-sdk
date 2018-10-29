#include <string.h>
#include "dap_common.h"
#include "dap_enc_msrln.h"
#include "MSRLN/MSRLN.h"


#define LOG_TAG "dap_enc_msrln"

/**
 * @brief dap_enc_msrln_key_new_generate
 * @param a_key Struct for new key
 * @param a_size Not used
 */

void dap_enc_msrln_key_new_generate(struct dap_enc_key* a_key, size_t a_size)
{
    (void)a_size;
    a_key = DAP_NEW(dap_enc_key_t);
    if(a_key == NULL) {
        log_it(L_ERROR, "Can't allocate memory for key");
        return;
    }

    a_key->type = DAP_ENC_KEY_TYPE_MSRLN;
    a_key->dec = dap_enc_msrln_decode;
    a_key->enc = dap_enc_msrln_encode;
    a_key->delete_callback = dap_enc_msrln_key_delete;
}

/**
 * @brief dap_enc_msrln_key_new_from_data
 * @param k
 * @param alice_priv
 * @param bob_msg
 * @param bob_msg_len
 * @param key
 * @param key_len
 */
void dap_enc_msrln_key_new_from_data(struct dap_enc_key *a_key, void **alice_priv, size_t *alice_msg_len)
{    
    uint8_t *key_a_tmp_pub = NULL;

    /* alice_msg is alice's public key */
    a_key->priv_key_data = NULL;
    a_key->priv_key_data = malloc(MSRLN_PKA_BYTES);
    if(a_key->priv_key_data == NULL) {
        DAP_DELETE(a_key->priv_key_data = NULL);
        a_key->priv_key_data = NULL;
        *alice_priv = NULL;
        return;
    }
    key_a_tmp_pub = a_key->priv_key_data;

    *alice_priv = NULL;
    *alice_priv = malloc(1024 * sizeof(uint32_t));
    if (*alice_priv == NULL) {
        DAP_DELETE(a_key->priv_key_data = NULL);
        a_key->priv_key_data = NULL;
        *alice_priv = NULL;
        return;
    }

    PLatticeCryptoStruct PLCS = LatticeCrypto_allocate();
    LatticeCrypto_initialize(PLCS, randombytes, MSRLN_generate_a, MSRLN_get_error);

    if (MSRLN_KeyGeneration_A((int32_t *) *alice_priv, (unsigned char *) key_a_tmp_pub, PLCS) != CRYPTO_MSRLN_SUCCESS) {
        DAP_DELETE(a_key->priv_key_data = NULL);
        a_key->priv_key_data = NULL;
        *alice_priv = NULL;
        return;
    }
    *alice_msg_len = MSRLN_PKA_BYTES;
    a_key->priv_key_data_size = MSRLN_PKA_BYTES;

    key_a_tmp_pub = NULL;
    DAP_DELETE(key_a_tmp_pub);
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
size_t dap_enc_msrln_encode(struct dap_enc_key* b_key, unsigned char *a_pub, size_t *a_pub_size, unsigned char **b_pub)
{
    size_t ret;

    dap_enc_msrln_key_t *test_k_inh = DAP_ENC_KEY_TYPE_MSRLN(b_key);

    uint8_t *bob_priv = NULL;
    uint8_t *bob_tmp_pub = NULL;

    *b_pub = NULL;
    b_key->priv_key_data = NULL;

    if(*a_pub_size != MSRLN_PKA_BYTES) {
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
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->priv_key_data);
        b_key->priv_key_data = NULL;
        return ret;
    }
    bob_tmp_pub = *b_pub;

    b_key->priv_key_data = malloc(MSRLN_SHAREDKEY_BYTES);
    if(b_key->priv_key_data == NULL) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->priv_key_data);
        b_key->priv_key_data = NULL;
        return ret;
    }

    PLatticeCryptoStruct PLCS = LatticeCrypto_allocate();
    LatticeCrypto_initialize(PLCS, randombytes, MSRLN_generate_a, MSRLN_get_error);
    if (MSRLN_SecretAgreement_B((unsigned char *) a_pub, (unsigned char *) b_key->priv_key_data, (unsigned char *) bob_tmp_pub, PLCS) != CRYPTO_MSRLN_SUCCESS) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->priv_key_data);
        b_key->priv_key_data = NULL;
        return ret;
    }

    b_key->priv_key_data_size = MSRLN_SHAREDKEY_BYTES;
    *a_pub_size = MSRLN_PKB_BYTES;

    ret = 1;
    return ret;
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
size_t dap_enc_msrln_decode(struct dap_enc_key* a_key, const void* a_priv, size_t *a_key_len, unsigned char * b_pub)
{
    size_t ret = 1;

    a_key->priv_key_data = NULL;
    a_key->priv_key_data = malloc(MSRLN_SHAREDKEY_BYTES);
    if(a_key->priv_key_data == NULL || *a_key_len != MSRLN_PKB_BYTES) {
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
    DAP_DELETE(a_key);
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
