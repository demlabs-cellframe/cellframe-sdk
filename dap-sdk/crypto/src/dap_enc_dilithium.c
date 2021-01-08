#include <assert.h>
#include <inttypes.h>
#include <string.h>

#include "dap_enc_dilithium.h"
#include "dap_common.h"
#include "rand/dap_rand.h"

#define LOG_TAG "dap_enc_sig_dilithium"

static enum DAP_DILITHIUM_SIGN_SECURITY _dilithium_type = DILITHIUM_MIN_SIZE; // by default

//// WARNING! Its because of accident with wrong sizes on mobile 32bit platforms
//// Remove it after you'll update all mobile keys


void dap_enc_sig_dilithium_set_type(enum DAP_DILITHIUM_SIGN_SECURITY type)
{
    _dilithium_type = type;
}

void dap_enc_sig_dilithium_key_new(struct dap_enc_key *key) {

    key->type = DAP_ENC_KEY_TYPE_SIG_DILITHIUM;
    key->enc = NULL;
    key->enc_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_dilithium_get_sign;
    key->dec_na = (dap_enc_callback_dataop_na_t) dap_enc_sig_dilithium_verify_sign;
//    key->gen_bob_shared_key = (dap_enc_gen_bob_shared_key) dap_enc_sig_dilithium_get_sign;
//    key->gen_alice_shared_key = (dap_enc_gen_alice_shared_key) dap_enc_sig_dilithium_verify_sign;
}

// generation key pair for sign Alice
// OUTPUT:
// a_key->data  --- Alice's public key
// alice_priv  ---  Alice's private key
// alice_msg_len --- Alice's private key length
void dap_enc_sig_dilithium_key_new_generate(struct dap_enc_key * key, const void *kex_buf,
        size_t kex_size, const void * seed, size_t seed_size,
        size_t key_size)
{
    (void) kex_buf;
    (void) kex_size;
    (void) key_size;

    int32_t retcode;

    dap_enc_sig_dilithium_set_type(DILITHIUM_MAX_SPEED);


    //int32_t type = 2;
    key->priv_key_data_size = sizeof(dilithium_private_key_t);
    key->pub_key_data_size = sizeof(dilithium_public_key_t);
    key->priv_key_data = malloc(key->priv_key_data_size);
    key->pub_key_data = malloc(key->pub_key_data_size);

    retcode = dilithium_crypto_sign_keypair((dilithium_public_key_t *) key->pub_key_data,
            (dilithium_private_key_t *) key->priv_key_data, _dilithium_type, seed, seed_size);
    if(retcode != 0) {
        dilithium_private_and_public_keys_delete((dilithium_private_key_t *) key->pub_key_data,
                (dilithium_public_key_t *) key->pub_key_data);
        log_it(L_CRITICAL, "Error");
        return;
    }
}

size_t dap_enc_sig_dilithium_get_sign(struct dap_enc_key * key, const void * msg,
        const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof(dilithium_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }

    if(!dilithium_crypto_sign((dilithium_signature_t *) signature, (const unsigned char *) msg, msg_size, key->priv_key_data))
        return signature_size;
    else
        return 0;
}

size_t dap_enc_sig_dilithium_verify_sign(struct dap_enc_key * key, const void * msg,
        const size_t msg_size, void * signature, const size_t signature_size)
{
    if(signature_size < sizeof(dilithium_signature_t)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }

    return (dilithium_crypto_sign_open( (unsigned char *) msg, msg_size, (dilithium_signature_t *) signature, key->pub_key_data));
}

void dap_enc_sig_dilithium_key_delete(struct dap_enc_key * key)
{
    if( key->priv_key_data && key->pub_key_data)
        dilithium_private_and_public_keys_delete((dilithium_private_key_t *) key->priv_key_data,
            (dilithium_public_key_t *) key->pub_key_data);
    else if ( key->pub_key_data )
        dilithium_public_key_delete((dilithium_public_key_t *) key->pub_key_data);
    else if ( key->priv_key_data )
        dilithium_public_key_delete((dilithium_public_key_t *) key->priv_key_data);

}

size_t dap_enc_dilithium_calc_signature_unserialized_size(void)
{
    return sizeof(dilithium_signature_t);
}




/* Serialize a signature */
uint8_t* dap_enc_dilithium_write_signature(dilithium_signature_t* a_sign, size_t *a_sign_out)
{
    if(!a_sign ) {
        return NULL ;
    }
    size_t l_shift_mem = 0;
    size_t l_buflen = dap_enc_dilithium_calc_signagture_size(a_sign);

    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(uint64_t));
    l_shift_mem += sizeof(uint64_t);
    memcpy(l_buf + l_shift_mem, &a_sign->kind, sizeof(dilithium_kind_t));
    l_shift_mem += sizeof(dilithium_kind_t);
    memcpy(l_buf + l_shift_mem, &a_sign->sig_len, sizeof(unsigned long long));
    l_shift_mem += sizeof(uint64_t);
    memcpy(l_buf + l_shift_mem, a_sign->sig_data, a_sign->sig_len );
    l_shift_mem += a_sign->sig_len ;

    if(a_sign_out)
        *a_sign_out = l_buflen;
    return l_buf;
}

/* Deserialize a signature */
dilithium_signature_t* dap_enc_dilithium_read_signature(uint8_t *a_buf, size_t a_buflen)
{
    if( !a_buf || (a_buflen < (sizeof(uint64_t) + sizeof(dilithium_kind_t)) )  )
        return NULL ;
    dilithium_kind_t kind;
    uint64_t l_buflen_internal = 0;
    memcpy(&l_buflen_internal, a_buf, sizeof(uint64_t));
    memcpy(&kind, a_buf + sizeof(uint64_t), sizeof(dilithium_kind_t));
    if(l_buflen_internal != a_buflen)
        return NULL ;
    dilithium_param_t p;
    if(!dilithium_params_init(&p, kind))
        return NULL ;

    dilithium_signature_t* l_sign = DAP_NEW(dilithium_signature_t);
    l_sign->kind = kind;
    uint64_t l_shift_mem = sizeof(uint64_t) + sizeof(dilithium_kind_t);
    memcpy(&l_sign->sig_len, a_buf + l_shift_mem, sizeof(uint64_t));
    l_shift_mem += sizeof(uint64_t);
    l_sign->sig_data = DAP_NEW_SIZE(unsigned char, l_sign->sig_len);
    memcpy(l_sign->sig_data, a_buf + l_shift_mem, l_sign->sig_len);
    l_shift_mem += l_sign->sig_len;
    return l_sign;
}

/**
 * @brief dap_enc_dilithium_read_signature
 * @param a_buf
 * @param a_buflen
 * @return
 */
dilithium_signature_t* dap_enc_dilithium_read_signature_old(uint8_t *a_buf, size_t a_buflen)
{
    if( !a_buf || (a_buflen < (sizeof(uint32_t) + sizeof(dilithium_kind_t)) )  )
        return NULL ;
    dilithium_kind_t kind;
    uint32_t l_buflen_internal = 0;
    memcpy(&l_buflen_internal, a_buf, sizeof(uint32_t));
    memcpy(&kind, a_buf + sizeof(uint32_t), sizeof(dilithium_kind_t));
    if(l_buflen_internal != a_buflen)
        return NULL ;
    dilithium_param_t p;
    if(!dilithium_params_init(&p, kind))
        return NULL ;

    dilithium_signature_t* l_sign = DAP_NEW(dilithium_signature_t);
    l_sign->kind = kind;
    size_t l_shift_mem = sizeof(size_t) + sizeof(dilithium_kind_t);
    memcpy(&l_sign->sig_len, a_buf + l_shift_mem, sizeof(unsigned long long));
    l_shift_mem += sizeof(unsigned long long);
    l_sign->sig_data = DAP_NEW_SIZE(unsigned char, l_sign->sig_len);
    memcpy(l_sign->sig_data, a_buf + l_shift_mem, l_sign->sig_len);
    l_shift_mem += l_sign->sig_len;
    return l_sign;
}


/* Serialize a private key. */
uint8_t* dap_enc_dilithium_write_private_key(const dilithium_private_key_t* a_private_key, size_t *a_buflen_out)
{
    dilithium_param_t p;// = malloc(sizeof(dilithium_param_t));
    if(!dilithium_params_init(&p, a_private_key->kind))
        return NULL;

    size_t l_buflen = sizeof(size_t) + sizeof(dilithium_kind_t) + p.CRYPTO_SECRETKEYBYTES; //CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(size_t));
    memcpy(l_buf + sizeof(size_t), &a_private_key->kind, sizeof(dilithium_kind_t));
    memcpy(l_buf + sizeof(size_t) + sizeof(dilithium_kind_t), a_private_key->data, p.CRYPTO_SECRETKEYBYTES);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    return l_buf;
}

/* Serialize a public key. */
uint8_t* dap_enc_dilithium_write_public_key(const dilithium_public_key_t* a_public_key, size_t *a_buflen_out)
{
    dilithium_param_t p;
    if(!dilithium_params_init(&p, a_public_key->kind))
        return NULL;

    uint64_t l_buflen = sizeof(uint64_t) + sizeof(dilithium_kind_t) + p.CRYPTO_PUBLICKEYBYTES;
    uint8_t *l_buf = DAP_NEW_SIZE(uint8_t, l_buflen);
    memcpy(l_buf, &l_buflen, sizeof(uint64_t));
    memcpy(l_buf + sizeof(uint64_t), &a_public_key->kind, sizeof(dilithium_kind_t));
    memcpy(l_buf + sizeof(uint64_t) + sizeof(dilithium_kind_t), a_public_key->data, p.CRYPTO_PUBLICKEYBYTES);
    if(a_buflen_out)
        *a_buflen_out = l_buflen;
    return l_buf;
}

/* Deserialize a private key. */
dilithium_private_key_t* dap_enc_dilithium_read_private_key(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(uint64_t) + sizeof(dilithium_kind_t)))
        return NULL;
    dilithium_kind_t kind;
    uint64_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(uint64_t));
    memcpy(&kind, a_buf + sizeof(uint64_t), sizeof(dilithium_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    dilithium_param_t p;
    if(!dilithium_params_init(&p, kind))
        return NULL;
    dilithium_private_key_t* l_private_key = DAP_NEW(dilithium_private_key_t);
    l_private_key->kind = kind;

    l_private_key->data = DAP_NEW_SIZE(unsigned char, p.CRYPTO_SECRETKEYBYTES);
    memcpy(l_private_key->data, a_buf + sizeof(uint64_t) + sizeof(dilithium_kind_t), p.CRYPTO_SECRETKEYBYTES);
    return l_private_key;
}

/* Deserialize a private key. */
dilithium_private_key_t* dap_enc_dilithium_read_private_key_old(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(uint32_t) + sizeof(dilithium_kind_t)))
        return NULL;
    dilithium_kind_t kind;
    uint32_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(uint32_t));
    memcpy(&kind, a_buf + sizeof(uint32_t), sizeof(dilithium_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    dilithium_param_t p;
    if(!dilithium_params_init(&p, kind))
        return NULL;
    dilithium_private_key_t* l_private_key = DAP_NEW(dilithium_private_key_t);
    l_private_key->kind = kind;

    l_private_key->data = DAP_NEW_SIZE(unsigned char, p.CRYPTO_SECRETKEYBYTES);
    memcpy(l_private_key->data, a_buf + sizeof(uint32_t) + sizeof(dilithium_kind_t), p.CRYPTO_SECRETKEYBYTES);
    return l_private_key;
}

/* Deserialize a public key. */
dilithium_public_key_t* dap_enc_dilithium_read_public_key(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(uint64_t) + sizeof(dilithium_kind_t)))
        return NULL;
    dilithium_kind_t kind;
    uint64_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(uint64_t));
    memcpy(&kind, a_buf + sizeof(uint64_t), sizeof(dilithium_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    dilithium_param_t p;
    if(!dilithium_params_init(&p, kind))
        return NULL;
    dilithium_public_key_t* l_public_key = DAP_NEW_Z(dilithium_public_key_t);
    l_public_key->kind = kind;

    l_public_key->data = DAP_NEW_Z_SIZE(unsigned char, p.CRYPTO_PUBLICKEYBYTES);
    memcpy(l_public_key->data, a_buf + sizeof(uint64_t) + sizeof(dilithium_kind_t), p.CRYPTO_PUBLICKEYBYTES);
    return l_public_key;
}

/**
 * @brief dap_enc_dilithium_read_public_key_old
 * @param a_buf
 * @param a_buflen
 * @return
 */
dilithium_public_key_t* dap_enc_dilithium_read_public_key_old(const uint8_t *a_buf, size_t a_buflen)
{
    if(!a_buf || a_buflen < (sizeof(uint32_t) + sizeof(dilithium_kind_t)))
        return NULL;
    dilithium_kind_t kind;
    uint32_t l_buflen = 0;
    memcpy(&l_buflen, a_buf, sizeof(uint32_t));
    memcpy(&kind, a_buf + sizeof(uint32_t), sizeof(dilithium_kind_t));
    if(l_buflen != a_buflen)
        return NULL;
    dilithium_param_t p;
    if(!dilithium_params_init(&p, kind))
        return NULL;
    dilithium_public_key_t* l_public_key = DAP_NEW_Z(dilithium_public_key_t);
    l_public_key->kind = kind;

    l_public_key->data = DAP_NEW_Z_SIZE(unsigned char, p.CRYPTO_PUBLICKEYBYTES);
    memcpy(l_public_key->data, a_buf + sizeof(uint32_t) + sizeof(dilithium_kind_t), p.CRYPTO_PUBLICKEYBYTES);
    return l_public_key;
}
