
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


void dap_enc_defeo_key_new(struct dap_enc_key *a_key) {
    a_key = DAP_NEW(dap_enc_key_t);
    if(a_key == NULL)
        return;

    a_key->type = DAP_ENC_KEY_TYPE_DEFEO;
    a_key->enc = dap_enc_defeo_encode;
    a_key->dec = dap_enc_defeo_decode;
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

    a_key->pub_key_data = malloc(DEFEO_PUBLICKEYBYTES);
    a_key->pub_key_data_size = DEFEO_PUBLICKEYBYTES;
    if(a_key->pub_key_data == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        return;
    }

    a_key->priv_key_data = malloc(DEFEO_SECRETKEYBYTES);
    a_key->priv_key_data_size = DEFEO_SECRETKEYBYTES;

    // generate A key pair
    random_mod_order_A((unsigned char *) a_key->priv_key_data);
    if(EphemeralKeyGeneration_A((unsigned char *) a_key->priv_key_data, (unsigned char *) a_key->pub_key_data) != 0) {
        log_it(L_CRITICAL, "Error malloc");
    }

}

void dap_enc_defeo_key_delete(struct dap_enc_key *a_key) {
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
size_t dap_enc_defeo_encode(struct dap_enc_key *b_key, const void *a_pub,
                            size_t a_pub_size, void **b_pub)
{

    size_t ret;

    *b_pub = NULL;

    if(a_pub_size != DEFEO_PUBLICKEYBYTES) {
        return 1;
    }

    *b_pub = malloc(DEFEO_PUBLICKEYBYTES);
    if(b_pub == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        return 2;
    }

    b_key->priv_key_data = malloc(DEFEO_BYTES);
    if(b_key->priv_key_data == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        return 3;
    }

    uint8_t *bob_priv = malloc(DEFEO_SECRETKEYBYTES);

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
    b_key->priv_key_data_size = DEFEO_BYTES;
    b_key->pub_key_data_size = DEFEO_PUBLICKEYBYTES;

    return 0;
}


// generation of shared key at Alice's side
// INPUT:
// a_priv  --- Alice's private key
// b_pub  ---  Bob's public key
// OUTPUT:
// a_key->data  --- shared key
// a_key_len --- shared key length
size_t dap_enc_defeo_decode(struct dap_enc_key *a_key, const void *a_priv, size_t b_pub_size, unsigned char *b_pub)
{
    if(b_pub_size != DEFEO_PUBLICKEYBYTES) {
        log_it(L_ERROR, "public key size not equal DEFEO_PUBLICKEYBYTES");
        return 1;
    }

    a_key->priv_key_data = malloc(DEFEO_BYTES);
    if(a_key->priv_key_data == NULL) {
        log_it(L_CRITICAL, "Error malloc");
        return 2;
    }

    if(EphemeralSecretAgreement_A((unsigned char *) a_priv, (unsigned char *) b_pub,
                                  (unsigned char *) a_key->priv_key_data) != 0) {
        log_it(L_ERROR, "Error EphemeralSecretAgreement_A");
        return 3;
    }

    a_key->priv_key_data_size = DEFEO_BYTES;

    return 0;
}
