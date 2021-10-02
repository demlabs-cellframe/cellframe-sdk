#include "dap_enc_sign_ecdsa.h"
#include "dap_rand.h"

#define LOG_TAG "dap_enc_sign_ecdsa"

void dap_enc_sign_ecdsa_gen_priv_key(struct dap_enc_key * a_key){

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_ECDSA_BTC:
        a_key->priv_key_data_size=BTC_PRIV_KEY_SIZE;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_ETH:
        a_key->priv_key_data_size=ETH_PRIV_KEY_SIZE;
        break;
    default:
        log_it(L_ERROR, "Key have type ");
        return;
}
    int output_randombytes=0;
    output_randombytes=randombytes(&a_key->priv_key_data, a_key->priv_key_data_size)
    //first of all, second argument randombytes should be int and not size_t, and secondly 
    //the output is not handled in an appropriate way here
}

void dap_enc_sign_ecdsa_set_curve(struct dap_enc_key * a_key){

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_ECDSA_BTC:
        a_key->_inheritor->dap_ecdsa_curve=DAP_ENC_CURVE_TYPE_SECP256K1;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_ETH:
        a_key->_inheritor->dap_ecdsa_curve=DAP_ENC_CURVE_TYPE_SECP256K1;
        break;
    default:
        log_it(L_ERROR, "Key have type ");
        return;
    }
}

void dap_enc_sign_ecdsa_alloc_mem_pub_key(struct dap_enc_key * a_key){

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_ECDSA_BTC:
        a_key->pub_key_data = DAP_NEW_SIZE(void,BTC_PUBLIC_KEY_SIZE);
        a_key->pub_key_data_size =BTC_PUBLIC_KEY_SIZE;
        a_key->_inheritor->pub_key_compr_data = DAP_NEW_SIZE(void,BTC_PUBLIC_KEY_COMPR_SIZE);
        a_key->_inheritor->pub_key_compr_data_size = BTC_PUBLIC_KEY_COMPR_SIZE;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_ETH:
        a_key->pub_key_data = DAP_NEW_SIZE(void,ETH_PUBLIC_KEY_SIZE);
        a_key->pub_key_data_size =ETH_PUBLIC_KEY_SIZE;
        a_key->_inheritor->pub_key_compr_data = DAP_NEW_SIZE(void,ETH_PUBLIC_KEY_COMPR_SIZE);
        a_key->_inheritor->pub_key_compr_data_size = ETH_PUBLIC_KEY_COMPR_SIZE;
        break;
    default:
        log_it(L_ERROR, "Key have type ");
        return;
}

void dap_enc_sign_ecdsa_gen_pub_key(struct dap_enc_key* a_key){

    bool gen_public_key = false;

    if (curve != NULL){
            ecdsa_get_public_key33(curve,(uint8_t*) a_key->priv_key_data,(uint8_t*)a_key->_inheritor->pub_key_compr_data);
            gen_public_key = true;

            ecdsa_get_public_key65(curve,(uint8_t*) a_key->priv_key_data,(uint8_t*)a_key->pub_key_data);
            gen_public_key = true;
    } else {
           log_it(L_ERROR, "Curve was not set"); ;
        }

    if(!gen_public_key){
        log_it(L_ERROR, "Can't generate public key");
        dap_enc_sign_ecdsa_key_delete(a_key);
        return;
    }
}

void dap_enc_sign_ecdsa_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                         const void *seed, size_t seed_size, size_t key_size) {
    (void)kex_buf;
    (void)kex_size;
    (void)key_size;
    //now using dap_random /dev/urandom generator called in dap_enc_sign_ecdsa_gen_priv_key
    (void) seed;
    (void) seed_size;

    dap_enc_sign_ecdsa_gen_priv_key(a_key);
    dap_enc_sign_ecdsa_alloc_mem_pub_key(a_key);
    dap_enc_sign_ecdsa_set_curve(a_key);
    dap_enc_sign_ecdsa_gen_pub_key(a_key);
}

size_t dap_enc_sign_ecdsa_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){   
 
    if(signature_size < dap_enc_sign_ecdsa_calc_signature_size()){
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    if (ecdsa_sign(a_key->_inheritor->dap_ecdsa_curve, HASHER_SHA2, a_key->priv_key_data, msg, msg_len, sig, NULL,
                   NULL) != 0) {
      log_it(L_ERROR,"trezor-crypto signing call failed\n");
      return;
    }
}

size_t dap_enc_sign_ecdsa_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                 void *signature, const size_t signature_size){
    if (signature_size < dap_enc_sign_ecdsa_calc_signature_size()){
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    return ecdsa_verify(a_key->_inheritor->dap_ecdsa_curve, HASHER_SHA2, a_key->pub_key_data, signature, msg, (uint32_t)msg_size) == 0?1:0;
}

void dap_enc_sign_ecdsa_key_delete(struct dap_enc_key * a_key){

        DAP_FREE(a_key->priv_key_data);
        a_key->priv_key_data_size = 0;
        DAP_FREE(a_key->pub_key_data);
        a_key->pub_key_data_size = 0;
        DAP_FREE(a_key->_inheritor->pub_key_compr_data);
        a_key->_inheritor->pub_key_compr_data_size = 0;
        return ;
}

static inline size_t dap_enc_sign_ecdsa_calc_signature_size(void){
    return sizeof(ecdsa_signature_t);
}

static inline size_t dap_enc_sign_ecdsa_calc_signature_serialized_size(void){
    return sizeof(ecdsa_signature_t);
}

/* Serialize a signature */
static inline uint8_t* dap_enc_sign_ecdsa_write_signature(ecdsa_signature_t *a_sign){
    if (!a_sign)
        return NULL;
    else
       return (uint8_t*) a_buf;
}

/* Deserialize a signature */
static inline ecdsa_signature_t* dap_enc_sign_ecdsa_read_signature(uint8_t* a_buf, size_t a_buflen){
    if (!a_buflen || a_buflen <  sizeof(ecdsa_signature_t)  )
        return NULL;
    else
       return (ecdsa_signature_t*) a_buf;
}


/* Serialize a private key */
static inline uint8_t* dap_enc_sign_ecdsa_write_private_key(dap_enc_key * a_key){
    if (a_key == NULL) {
        return NULL;
    }
    if (a_key->priv_key_data_size == 0){
        return NULL;
    }
    if (!a_key->priv_key_data){
        return (uint8_t*) (a_key->priv_key_data);
    }
    }

/* Deserialize a private key */
static inline void* dap_enc_sign_ecdsa_write_private_key(dap_enc_key * a_key){
    if (a_key == NULL) {
        return NULL;
    }
    if (a_key->priv_key_data_size == 0){
        return NULL;
    }
    if (!a_key->priv_key_data){
        return (void*) (a_key->priv_key_data);
    }
    }

/* Serialize a public key */
static inline uint8_t* dap_enc_sign_ecdsa_write_public_key(dap_enc_key *a_key){
    if (a_key == NULL) {
        return NULL;
    }
    if (a_key->pub_key_data_size == 0){
        return NULL;
    }
    if (!a_key->priv_key_data){
        return (uint8_t*) (a_key->pub_key_data);
    }
    }

/* Deserialize a public key */
static inline void* dap_enc_sign_ecdsa_write_public_key(dap_enc_key *a_key){
    if (a_key == NULL) {
        return NULL;
    }
    if (a_key->pub_key_data_size == 0){
        return NULL;
    }
    if (!a_key->priv_key_data){
        return (void*) (a_key->pub_key_data);
    }
    }


