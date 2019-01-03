#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "dap_enc_tesla.h"
#include "dap_common.h"
#include "dap_rand.h"

static enum DAP_TESLA_SIGN_SECURITY _tesla_type = HEURISTIC_MAX_SECURITY_AND_MAX_SPEED; // by default

void dap_enc_sig_tesla_set_type(enum DAP_TESLA_SIGN_SECURITY type)
{
    _tesla_type = type;
}

void dap_enc_sig_tesla_key_new(struct dap_enc_key *key) {

    key->type = DAP_ENC_KEY_TYPE_SIG_TESLA;
    key->enc = NULL;
    key->enc_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_tesla_get_sign;
    key->dec_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_tesla_verify_sign;
//    key->gen_bob_shared_key = (dap_enc_gen_bob_shared_key) dap_enc_sig_tesla_get_sign;
//    key->gen_alice_shared_key = (dap_enc_gen_alice_shared_key) dap_enc_sig_tesla_verify_sign;
}

// generation key pair for sign Alice
// OUTPUT:
// a_key->data  --- Alice's public key
// alice_priv  ---  Alice's private key
// alice_msg_len --- Alice's private key length
void dap_enc_sig_tesla_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size,
        size_t key_size)
{
    (void) kex_buf;
    (void) kex_size;
    (void) key_size;

    int32_t retcode;

    int tesla_type = (seed && seed_size >= sizeof(uint8_t)) ? ((uint8_t*)seed)[0] % (PROVABLY_MAX_SECURITY + 1) :
                                                              HEURISTIC_MAX_SECURITY_AND_MAX_SPEED;
    dap_enc_sig_tesla_set_type(tesla_type);

    /* type is a param of sign-security
     * type = 0 - Heuristic qTESLA, NIST's security category 1
     * type = 1 - Heuristic qTESLA, NIST's security category 3 (option for size)
     * type = 2 - Heuristic qTESLA, NIST's security category 3 (option for speed)
     * type = 3 - Provably-secure qTESLA, NIST's security category 1
     * type = 4 - Provably-secure qTESLA, NIST's security category 3 (max security)
     */
    //int32_t type = 2;
    key->priv_key_data_size = sizeof(tesla_private_key_t);
    key->pub_key_data_size = sizeof(tesla_public_key_t);
    key->priv_key_data = malloc(key->priv_key_data_size);
    key->pub_key_data = malloc(key->pub_key_data_size);

    retcode = tesla_crypto_sign_keypair((tesla_public_key_t *) key->pub_key_data,
            (tesla_private_key_t *) key->priv_key_data, _tesla_type);
    if(retcode != 0) {
        tesla_private_and_public_keys_delete((tesla_private_key_t *) key->pub_key_data,
                (tesla_public_key_t *) key->pub_key_data);
        log_it(L_CRITICAL, "Error");
        return;
    }
}

size_t dap_enc_sig_tesla_get_sign(struct dap_enc_key * key, const void * msg,
        const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof(tesla_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }

    if(!tesla_crypto_sign((tesla_signature_t *) signature, (const unsigned char *) msg, msg_size, key->priv_key_data))
        return signature_size;
    else
        return 0;
}

size_t dap_enc_sig_tesla_verify_sign(struct dap_enc_key * key, const void * msg,
        const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof(tesla_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }

    return (tesla_crypto_sign_open((tesla_signature_t *) signature, (unsigned char *) msg, msg_size, key->pub_key_data));
}

void dap_enc_sig_tesla_key_delete(struct dap_enc_key * key)
{
    tesla_private_and_public_keys_delete((tesla_private_key_t *) key->priv_key_data,
            (tesla_public_key_t *) key->pub_key_data);
}

size_t dap_enc_tesla_calc_signature_size(void)
{
    return sizeof(tesla_signature_t);
}

