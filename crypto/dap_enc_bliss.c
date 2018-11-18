#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "dap_enc_bliss.h"
#include "dap_common.h"
#include "dap_rand.h"

static enum DAP_BLISS_SIGN_SECURITY _bliss_type = MAX_SECURITY; // by default

void dap_enc_sig_bliss_set_type(enum DAP_BLISS_SIGN_SECURITY type)
{
    _bliss_type = type;
}

void dap_enc_sig_bliss_key_new(struct dap_enc_key *key) {

    key->type = DAP_ENC_KEY_TYPE_SIG_BLISS;
    key->enc = NULL;
    key->gen_bob_shared_key = (dap_enc_gen_bob_shared_key) dap_enc_sig_bliss_get_sign;
    key->gen_alice_shared_key = (dap_enc_gen_alice_shared_key) dap_enc_sig_bliss_verify_sign;
}


// generation key pair for sign Alice
// OUTPUT:
// a_key->data  --- Alice's public key
// alice_priv  ---  Alice's private key
// alice_msg_len --- Alice's private key length
void dap_enc_sig_bliss_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
                                    size_t kex_size, const void * seed, size_t seed_size,
                                    size_t key_size)
{
    (void) kex_buf; (void) kex_size;
    (void) seed; (void) seed_size;
    (void)key_size;

    int32_t retcode;

    dap_enc_sig_bliss_key_new(key);

    uint8_t seed_tmp[SHA3_512_DIGEST_LENGTH];
    entropy_t entropy;
    randombytes( &seed_tmp, 64);
    entropy_init( &entropy, seed_tmp);

    /* type is a param of sign-security
     * type = 0 - "toy" version                (< 60 bits)
     * type = 1 - max speed                    (128 bits)
     * type = 2 - min size                     (128 bits)
     * type = 3 - good speed and good security (160 bits)
     * type = 4 - max securiry                 (192 bits)
    */
    //int32_t type = 4;
    key->priv_key_data = malloc(sizeof(bliss_private_key_t));
    retcode = bliss_b_private_key_gen((bliss_private_key_t *) key->priv_key_data, _bliss_type, &entropy);
    if (retcode != BLISS_B_NO_ERROR) {
        bliss_b_private_key_delete(key->priv_key_data);
        log_it(L_CRITICAL, "Error");
        return;
    }

    key->pub_key_data = malloc(sizeof(bliss_public_key_t));
    retcode = bliss_b_public_key_extract( (bliss_public_key_t *) key->pub_key_data, (const bliss_private_key_t *) key->priv_key_data);
    if (retcode != BLISS_B_NO_ERROR) {
        bliss_b_private_key_delete(key->priv_key_data);
        bliss_b_public_key_delete(key->pub_key_data);
        log_it(L_CRITICAL, "Error");
        return;
    }
}


size_t dap_enc_sig_bliss_get_sign(struct dap_enc_key * key,const void * msg,
                                  const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof (bliss_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    uint8_t seed_tmp[SHA3_512_DIGEST_LENGTH];
    entropy_t entropy;
    randombytes(&seed_tmp, 64);
    entropy_init(&entropy, seed_tmp);

    return bliss_b_sign((bliss_signature_t *)signature,
                        (const bliss_private_key_t *)key->priv_key_data,
                        (const uint8_t *)msg,
                        msg_size,
                        &entropy);
}

size_t dap_enc_sig_bliss_verify_sign(struct dap_enc_key * key,const void * msg,
                                     const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof (bliss_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    return bliss_b_verify(signature, key->pub_key_data, msg, msg_size);
}

void dap_enc_sig_bliss_key_delete(struct dap_enc_key *key)
{
    bliss_b_private_key_delete(key->priv_key_data);
    bliss_b_public_key_delete(key->pub_key_data);
}


