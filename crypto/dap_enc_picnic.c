#include "dap_common.h"
#include "dap_enc_picnic.h"
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "picnic.h"
#include "picnic_impl.h"

/**
 * Set the mark that valid keys are present
 */
static void set_picnic_params_t(struct dap_enc_key *key)
{
    picnic_params_t *param = (key) ? (picnic_params_t*) key->_inheritor : NULL;
    if(param && key->_inheritor_size == sizeof(picnic_params_t))
        *param = ((picnic_privatekey_t*) key->priv_key_data)->params;
}

/**
 * Check present of valid keys
 */
static bool check_picnic_params_t(struct dap_enc_key *key)
{
    picnic_params_t *param = (key) ? (picnic_params_t*) key->_inheritor : NULL;
    if(param && *param > PARAMETER_SET_INVALID && *param < PARAMETER_SET_MAX_INDEX)
        return true;
    return false;
}

size_t dap_enc_picnic_calc_signature_size(struct dap_enc_key *key)
{
    picnic_params_t *param = (picnic_params_t*) key->_inheritor;
    size_t max_signature_size = picnic_signature_size(*param);
    return max_signature_size;
}

void dap_enc_sig_picnic_key_new(struct dap_enc_key *key) {

    key->type = DAP_ENC_KEY_TYPE_SIG_PICNIC;
    key->_inheritor = calloc(sizeof(picnic_params_t), 1);
    key->_inheritor_size = sizeof(picnic_params_t);
    key->enc = NULL;
    key->enc = NULL;
    key->gen_bob_shared_key = NULL; //(dap_enc_gen_bob_shared_key) dap_enc_sig_picnic_get_sign;
    key->gen_alice_shared_key = NULL; //(dap_enc_gen_alice_shared_key) dap_enc_sig_picnic_verify_sign;
    key->enc_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_picnic_get_sign;
    key->dec_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_picnic_verify_sign;
    key->priv_key_data = NULL;
    key->pub_key_data = NULL;
}

void dap_enc_sig_picnic_key_delete(struct dap_enc_key *key)
{
    if(key->_inheritor_size > 0)
        free(key->_inheritor);
    key->_inheritor = NULL;
    key->_inheritor_size = 0;
    // free memory will be in dap_enc_key_delete()
    //picnic_keypair_delete((picnic_privatekey_t*) key->priv_key_data, (picnic_publickey_t *) key->pub_key_data);
    key->priv_key_data_size = 0;
    key->pub_key_data_size = 0;
}

void dap_enc_sig_picnic_key_new_generate(struct dap_enc_key * key, const void *kex_buf, size_t kex_size,
        const void * seed, size_t seed_size, size_t key_size)
{
    (void) kex_buf;
    (void) kex_size;
    (void) key_size;
    picnic_params_t parameters;
    // Parameter name from Picnic_L1_FS = 1 to PARAMETER_SET_MAX_INDEX
    if(seed_size >= sizeof(unsigned char) && seed)
        parameters = (((unsigned char*) seed)[0] % (PARAMETER_SET_MAX_INDEX - 1)) + 1;
    else
        parameters = DAP_PICNIC_SIGN_PARAMETR

    key->priv_key_data_size = sizeof(picnic_privatekey_t);
    key->pub_key_data_size = sizeof(picnic_publickey_t);
    key->priv_key_data = malloc(key->priv_key_data_size);
    key->pub_key_data = malloc(key->pub_key_data_size);

    picnic_keys_gen((picnic_privatekey_t *) key->priv_key_data, (picnic_publickey_t *) key->pub_key_data, parameters);
    if(!picnic_validate_keypair((picnic_privatekey_t *) key->priv_key_data, (picnic_publickey_t *) key->pub_key_data))
        set_picnic_params_t(key);
}

size_t dap_enc_sig_picnic_get_sign(struct dap_enc_key * key, const void* message, size_t message_len,
        void* signature, size_t signature_len)
{
    int ret;
    if(!check_picnic_params_t(key))
        return -1;
    picnic_privatekey_t* sk = key->priv_key_data;
    signature_t* sig = (signature_t*) malloc(sizeof(signature_t));
    paramset_t paramset;

    ret = get_param_set(sk->params, &paramset);
    if(ret != EXIT_SUCCESS) {
        free(sig);
        return -1;
    }

    allocateSignature(sig, &paramset);
    if(sig == NULL) {
        return -1;
    }

    ret = sign((uint32_t*) sk->data, (uint32_t*) sk->pk.ciphertext, (uint32_t*) sk->pk.plaintext, (const uint8_t*)message,
            message_len, sig, &paramset);
    if(ret != EXIT_SUCCESS) {
        freeSignature(sig, &paramset);
        free(sig);
        return -1;
    }
    ret = serializeSignature(sig, (uint8_t*)signature, signature_len, &paramset);
    if(ret == -1) {
        freeSignature(sig, &paramset);
        free(sig);
        return -1;
    }
//    *signature_len = ret;
    freeSignature(sig, &paramset);
    free(sig);
    return ret;
}

size_t dap_enc_sig_picnic_verify_sign(struct dap_enc_key * key, const void* message, size_t message_len,
        void* signature, size_t signature_len)
{
    int ret;
    if(!check_picnic_params_t(key))
        return -1;
    picnic_publickey_t* pk = key->pub_key_data;
    paramset_t paramset;

    ret = get_param_set(pk->params, &paramset);
    if(ret != EXIT_SUCCESS)
        return -1;

    signature_t* sig = (signature_t*) malloc(sizeof(signature_t));
    allocateSignature(sig, &paramset);
    if(sig == NULL) {
        return -1;
    }

    ret = deserializeSignature(sig, (const uint8_t*)signature, signature_len, &paramset);
    if(ret != EXIT_SUCCESS) {
        freeSignature(sig, &paramset);
        free(sig);
        return -1;
    }

    ret = verify(sig, (uint32_t*) pk->ciphertext,
            (uint32_t*) pk->plaintext, (const uint8_t*)message, message_len, &paramset);
    if(ret != EXIT_SUCCESS) {
        /* Signature is invalid, or verify function failed */
        freeSignature(sig, &paramset);
        free(sig);
        return -1;
    }

    freeSignature(sig, &paramset);
    free(sig);
    return 0;
}

