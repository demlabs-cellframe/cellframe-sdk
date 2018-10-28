
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "dap_enc_defeo.h"
#include "dap_enc_key.h"

#include "dap_common.h"
#include "DeFeo_Scheme/config.h"
#include "DeFeo_Scheme/P768_internal.h"

void dap_enc_defeo_key_new(struct dap_enc_key* a_key)
{
    a_key = DAP_NEW(dap_enc_key_t);
    if(a_key == NULL)
        return;

    //a_key->_inheritor = (dap_enc_defeo_key_t*)malloc(sizeof(dap_enc_defeo_key_t));
    a_key->type = DAP_ENC_KEY_TYPE_DEFEO;
    a_key->enc = &dap_enc_defeo_encode;
    a_key->dec = &dap_enc_defeo_decode;
    a_key->delete_callback = &dap_enc_defeo_key_delete;
}

// key pair generation of Alice
// OUTPUT:
// a_key->data  --- Alice's public key
// alice_priv  ---  Alice's private key
// alice_msg_len --- Alice's private key length
void dap_enc_defeo_key_new_from_data(struct dap_enc_key *a_key, void **alice_priv, size_t *alice_msg_len) {

    //dap_enc_defeo_key_t *defeo_a_key = DAP_ENC_DEFEO_KEY(a_key);

    uint8_t *key_a_tmp_pub = NULL;
    uint8_t *key_a_tmp_priv = NULL;
    //if(!a_key || !a_in)
    //    return;

    a_key->data = malloc(DEFEO_PUBLICKEYBYTES);
    if(a_key->data == NULL) {
        DAP_DELETE(a_key->data = NULL);
        a_key->data = NULL;
        *alice_priv = NULL;
    }
    key_a_tmp_pub = a_key->data;

    *alice_priv = NULL;
    *alice_priv = malloc(DEFEO_SECRETKEYBYTES);
    if (*alice_priv == NULL) {
        DAP_DELETE(a_key->data = NULL);
        a_key->data = NULL;
        *alice_priv = NULL;
    }
    //key_a_tmp_priv = a_in;

    // generate A key pair
    random_mod_order_A((unsigned char *) *alice_priv);
    if(EphemeralKeyGeneration_A((unsigned char *) *alice_priv, (unsigned char *) key_a_tmp_pub) != 0) {
        DAP_DELETE(a_key->data = NULL);
        a_key->data = NULL;
        *alice_priv = NULL;
    }

    //defeo_a_key->alice_msg_len = DEFEO_PUBLICKEYBYTES;
    a_key->data_size = DEFEO_PUBLICKEYBYTES;
    *alice_msg_len = DEFEO_PUBLICKEYBYTES;
    key_a_tmp_pub = NULL;
    key_a_tmp_priv = NULL;

    DAP_DELETE(key_a_tmp_pub);
    DAP_DELETE(key_a_tmp_priv);
}

void dap_enc_defeo_key_delete(struct dap_enc_key *a_key) {
    dap_enc_defeo_key_t *defeo_a_key = DAP_ENC_DEFEO_KEY(a_key);
    (void) a_key;
    if(!a_key){
        return;
    }
    DAP_DELETE(a_key);
}


// key pair generation and generation of shared key at Bob's side
// INPUT:
// a_pub  ---  Alice's public key
// a_pub_size --- Alice's public key length
// OUTPUT:
// b_pub  --- Bob's public key
// b_key->data  --- shared key
// a_pub_size --- shared key length
size_t dap_enc_defeo_encode(struct dap_enc_key *b_key, unsigned char *a_pub, size_t *a_pub_size, unsigned char **b_pub) {

    size_t ret;
    //dap_enc_defeo_key_t *defeo_a_key = DAP_ENC_DEFEO_KEY(b_key);
    //dap_enc_defeo_key_t *defeo_a_key = b_key->_inheritor;
    uint8_t *bob_priv = NULL;
    uint8_t *bob_tmp_pub = NULL;

    //if(!a_key || !a_in || !a_out){
    //    return 0;
    //}

    *b_pub = NULL;
    b_key->data = NULL;

    if(*a_pub_size != DEFEO_PUBLICKEYBYTES) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->data);
        b_key->data = NULL;
    }
    *b_pub = malloc(DEFEO_PUBLICKEYBYTES);
    if(b_pub == NULL) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->data);
        b_key->data = NULL;
    }
    bob_tmp_pub = *b_pub;

    bob_priv = malloc(DEFEO_SECRETKEYBYTES);
    if(bob_priv == NULL){
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->data);
        b_key->data = NULL;
    }
    b_key->data = malloc(DEFEO_BYTES);
    if(b_key->data == NULL) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->data);
        b_key->data = NULL;
    }

    // generate Bob's key pair
    random_mod_order_B((unsigned char *)bob_priv);
    if(EphemeralKeyGeneration_B((unsigned char *) bob_priv, (unsigned char *) bob_tmp_pub) != 0) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->data);
        b_key->data = NULL;
    }

    //defeo_a_key->bob_msg_len = DEFEO_PUBLICKEYBYTES;
    bob_tmp_pub = NULL;  // we do not want to double-free it
    // compute Bob's shared secret
    if(EphemeralSecretAgreement_B((unsigned char *) bob_priv, (unsigned char *) a_pub, (unsigned char *) b_key->data) != 0) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(b_key->data);
        b_key->data = NULL;
    }

    //defeo_a_key->key_len = DEFEO_BYTES;
    b_key->data_size = DEFEO_BYTES;
    *a_pub_size = DEFEO_BYTES;
    ret = 1;
    DAP_DELETE(bob_tmp_pub);
    DAP_DELETE(bob_priv);

    return ret;

}


// generation of shared key at Alice's side
// INPUT:
// a_priv  --- Alice's private key
// b_pub  ---  Bob's public key
// OUTPUT:
// a_key->data  --- shared key
// a_key_len --- shared key length
size_t dap_enc_defeo_decode(struct dap_enc_key *a_key, const void *a_priv, size_t *a_key_len, unsigned char *b_pub)
{

    size_t ret = 1;
    //dap_enc_defeo_key_t *defeo_a_key = DAP_ENC_DEFEO_KEY(a_key);

   // if(!a_key || !a_in || !a_out){
     //   return 0;
    //}

    a_key->data = NULL;
    a_key->data = malloc(DEFEO_BYTES);
    if(a_key->data == NULL) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(a_priv);
        a_priv = NULL;
        DAP_DELETE(a_key->data);
        a_key->data = NULL;
    }

    if(EphemeralSecretAgreement_A((unsigned char *) a_priv, (unsigned char *) b_pub, (unsigned char *) a_key->data) != 0) {
        ret = 0;
        DAP_DELETE(b_pub);
        b_pub = NULL;
        DAP_DELETE(a_priv);
        a_priv = NULL;
        DAP_DELETE(a_key->data);
        a_key->data = NULL;
    }

    //defeo_a_key->key_len = DEFEO_BYTES;
    *a_key_len = DEFEO_BYTES;
    ret = 1;

    return ret;
}



