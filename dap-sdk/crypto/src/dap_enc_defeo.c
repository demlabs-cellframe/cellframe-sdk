
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "dap_enc_defeo.h"
#include "dap_enc_key.h"

#include "dap_common.h"
#include "defeo_config.h"
#include "defeo_scheme/defeo_P768_internal.h"


void dap_enc_defeo_key_new(struct dap_enc_key *a_key) {

    a_key->type = DAP_ENC_KEY_TYPE_DEFEO;
    a_key->enc = NULL;
    a_key->gen_bob_shared_key = (dap_enc_gen_bob_shared_key) dap_enc_defeo_gen_bob_shared_key;
    a_key->gen_alice_shared_key = (dap_enc_gen_alice_shared_key) dap_enc_defeo_gen_alice_shared_key;
}

// key pair generation of Alice
// OUTPUT:
// a_key->data  --- Alice's public key
// alice_priv  ---  Alice's private key
// alice_msg_len --- Alice's private key length
void dap_enc_defeo_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size)
{
    (void) kex_buf; (void) kex_size;
    (void) seed; (void) seed_size;
    (void)key_size;

    dap_enc_defeo_key_new(a_key);

    a_key->pub_key_data = malloc(DEFEO_PUBLICK_KEY_LEN);
    a_key->pub_key_data_size = DEFEO_PUBLICK_KEY_LEN;
    if(a_key->pub_key_data == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        return;
    }

    a_key->priv_key_data = malloc(DEFEO_SECRET_KEY_LEN);
    a_key->priv_key_data_size = DEFEO_SECRET_KEY_LEN;

    // generate A key pair
    random_mod_order_A((unsigned char *) a_key->priv_key_data);
    if(EphemeralKeyGeneration_A((unsigned char *) a_key->priv_key_data, (unsigned char *) a_key->pub_key_data) != 0) {
        log_it(L_CRITICAL, "Error malloc");
    }

}

void dap_enc_defeo_key_delete(struct dap_enc_key *a_key)
{
    (void)a_key;
}


// key pair generation and generation of shared key at Bob's side
// INPUT:
// a_pub  ---  Alice's public key
// a_pub_size --- Alice's public key length
// OUTPUT:
// b_pub  --- Bob's public key
// b_key->data  --- shared key
// a_pub_size --- shared key length
size_t dap_enc_defeo_gen_bob_shared_key(struct dap_enc_key *b_key, const void *a_pub,
                            size_t a_pub_size, void ** b_pub)
{
    *b_pub = NULL;

    if(a_pub_size != DEFEO_PUBLICK_KEY_LEN) {
        return 1;
    }

    *b_pub = malloc(DEFEO_PUBLICK_KEY_LEN);
    if(b_pub == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        return 2;
    }

    b_key->priv_key_data = malloc(DEFEO_SHARED_KEY_LEN);
    if(b_key->priv_key_data == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        return 3;
    }

    uint8_t *bob_priv = malloc(DEFEO_SECRET_KEY_LEN);

    // generate Bob's key pair
    random_mod_order_B((unsigned char *)bob_priv);
    if(EphemeralKeyGeneration_B((unsigned char *) bob_priv, (unsigned char *) b_key->pub_key_data) != 0) {
        log_it(L_CRITICAL, "Error malloc");
        return 1;
    }

    // compute Bob's shared secret
    if(EphemeralSecretAgreement_B((unsigned char *) bob_priv, (unsigned char *) a_pub,
                                  (unsigned char *) b_key->priv_key_data) != 0) {
        log_it(L_CRITICAL, "Error malloc");
        return 2;
    }

    free(bob_priv);
    b_key->priv_key_data_size = DEFEO_SHARED_KEY_LEN;
    b_key->pub_key_data_size = DEFEO_PUBLICK_KEY_LEN;

    return 0;
}


// generation of shared key at Alice's side
// INPUT:
// a_priv  --- Alice's private key
// b_pub  ---  Bob's public key
// OUTPUT:
// a_key->priv_key_data  --- shared key
// a_key_len --- shared key length
size_t dap_enc_defeo_gen_alice_shared_key(struct dap_enc_key *a_key, const void *a_priv, size_t b_pub_size, unsigned char *b_pub)
{
    size_t ret_val = 0;
    if(b_pub_size != DEFEO_PUBLICK_KEY_LEN) {
        log_it(L_ERROR, "public key size not equal DEFEO_PUBLICKEYBYTES");
        return 1;
    }
    void *oldkey = NULL;
    if(a_key->priv_key_data && a_key->priv_key_data_size > 0)
        oldkey = a_key->priv_key_data;
    a_key->priv_key_data = malloc(DEFEO_SHARED_KEY_LEN);

    if(a_key->priv_key_data == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        ret_val = 2;
    }

    if(EphemeralSecretAgreement_A((unsigned char *) a_priv, (unsigned char *) b_pub,
                                  (unsigned char *) a_key->priv_key_data) != 0) {
        log_it(L_ERROR, "Error EphemeralSecretAgreement_A");
        ret_val = 3;
    }

    if(oldkey)
        free(oldkey);
    if(!ret_val)
        a_key->priv_key_data_size = DEFEO_SHARED_KEY_LEN;
    return ret_val;
}
