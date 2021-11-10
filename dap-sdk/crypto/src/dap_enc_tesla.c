#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "dap_enc_tesla.h"
#include "dap_common.h"
#include "rand/dap_rand.h"

#define LOG_TAG "dap_enc_sig_tesla"

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
/**
 * @brief dap_enc_sig_tesla_key_new_generate
 * 
 * @param key 
 * @param kex_buf 
 * @param kex_size 
 * @param seed 
 * @param seed_size 
 * @param key_size 
 */
void dap_enc_sig_tesla_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size,
        size_t key_size)
{
    (void) kex_buf;
    (void) kex_size;
    (void) key_size;

    int32_t retcode;

    dap_enc_sig_tesla_set_type(HEURISTIC_MAX_SECURITY_AND_MAX_SPEED);

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
            (tesla_private_key_t *) key->priv_key_data, _tesla_type, seed, seed_size);
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

size_t dap_enc_tesla_calc_signature_serialized_size(tesla_signature_t* a_sign)
{
    return sizeof(size_t) + sizeof(tesla_kind_t) + a_sign->sig_len + sizeof(unsigned long long);
}

/* Serialize a signature */
uint8_t* dap_enc_tesla_write_signature(tesla_signature_t* a_sign, size_t *a_sign_out)
{
    if(!a_sign || *a_sign_out!=sizeof(tesla_signature_t)) {
        return NULL ;
    }
    size_t l_shift_mem = 0;
    size_t l_buflen = dap_enc_tesla_calc_signature_serialized_size(a_sign);

    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    l_shift_mem += sizeof(size_t);
    memcpy(l_buf + l_shift_mem, &a_sign->kind, sizeof(tesla_kind_t));
    l_shift_mem += sizeof(tesla_kind_t);
    memcpy(l_buf + l_shift_mem, &a_sign->sig_len, sizeof(unsigned long long));
    l_shift_mem += sizeof(unsigned long long);
    memcpy(l_buf + l_shift_mem, a_sign->sig_data, a_sign->sig_len );
    l_shift_mem += a_sign->sig_len ;

    if(a_sign_out)
        *a_sign_out = l_buflen;
    return l_buf;
}

/* Deserialize a signature */
tesla_signature_t* dap_enc_tesla_read_signature(uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(tesla_kind_t)))
        return NULL ;
    tesla_kind_t kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(tesla_kind_t));
    if(l_buflen != a_buflen)
        return NULL ;
    tesla_param_t p;
    if(!tesla_params_init(&p, kind))
        return NULL ;

    tesla_signature_t* l_sign = DAP_NEW(tesla_signature_t);
    l_sign->kind = kind;
    size_t l_shift_mem = sizeof(size_t) + sizeof(tesla_kind_t);
    memcpy(&l_sign->sig_len, a_buf + l_shift_mem, sizeof(unsigned long long));
    l_shift_mem += sizeof(unsigned long long);
    l_sign->sig_data = DAP_NEW_SIZE(unsigned char, l_sign->sig_len);
    memcpy(l_sign->sig_data, a_buf + l_shift_mem, l_sign->sig_len);
    l_shift_mem += l_sign->sig_len;
    return l_sign;
}

/* Serialize a private key. */
uint8_t* dap_enc_tesla_write_private_key(const tesla_private_key_t* a_private_key, size_t *a_buflen_out)
{
    tesla_param_t p;// = malloc(sizeof(tesla_param_t));
    if(!tesla_params_init(&p, a_private_key->kind))
        return NULL;

    size_t l_buflen = sizeof(size_t) + sizeof(tesla_kind_t) + p.CRYPTO_SECRETKEYBYTES; //CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    memcpy(l_buf + sizeof(size_t), &a_private_key->kind, sizeof(tesla_kind_t));
    memcpy(l_buf + sizeof(size_t) + sizeof(tesla_kind_t), a_private_key->data, p.CRYPTO_SECRETKEYBYTES);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    return l_buf;
}

/* Serialize a public key. */
uint8_t* dap_enc_tesla_write_public_key(const tesla_public_key_t* a_public_key, size_t *a_buflen_out)
{
    tesla_param_t p;
    if(!tesla_params_init(&p, a_public_key->kind))
        return NULL;

    size_t l_buflen = sizeof(size_t) + sizeof(tesla_kind_t) + p.CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    memcpy(l_buf + sizeof(size_t), &a_public_key->kind, sizeof(tesla_kind_t));
    memcpy(l_buf + sizeof(size_t) + sizeof(tesla_kind_t), a_public_key->data, p.CRYPTO_PUBLICKEYBYTES);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    return l_buf;
}

/* Deserialize a private key. */
tesla_private_key_t* dap_enc_tesla_read_private_key(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(tesla_kind_t)))
        return NULL;
    tesla_kind_t kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(tesla_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    tesla_param_t p;
    if(!tesla_params_init(&p, kind))
        return NULL;
    tesla_private_key_t* l_private_key = DAP_NEW(tesla_private_key_t);
    l_private_key->kind = kind;

    l_private_key->data = DAP_NEW_SIZE(unsigned char, p.CRYPTO_SECRETKEYBYTES);
    memcpy(l_private_key->data, a_buf + sizeof(size_t) + sizeof(tesla_kind_t), p.CRYPTO_SECRETKEYBYTES);
    return l_private_key;
}

/* Deserialize a public key. */
tesla_public_key_t* dap_enc_tesla_read_public_key(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(size_t) + sizeof(tesla_kind_t)))
        return NULL;
    tesla_kind_t kind;
    size_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(size_t));
    memcpy(&kind, a_buf + sizeof(size_t), sizeof(tesla_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    tesla_param_t p;
    if(!tesla_params_init(&p, kind))
        return NULL;
    tesla_public_key_t* l_public_key = DAP_NEW(tesla_public_key_t);
    l_public_key->kind = kind;

    l_public_key->data = DAP_NEW_SIZE(unsigned char, p.CRYPTO_PUBLICKEYBYTES);
    memcpy(l_public_key->data, a_buf + sizeof(size_t) + sizeof(tesla_kind_t), p.CRYPTO_PUBLICKEYBYTES);
    return l_public_key;
}
