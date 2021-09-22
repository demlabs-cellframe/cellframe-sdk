#include "dap_enc_sign_ecdsa.h"
#include "dap_rand.h"

#define LOG_TAG "dap_enc_sign_ecdsa"

typedef struct ecdsa_pvt_serialize{
    dap_enc_curve_types_t curve_type:32;
    uint64_t size_key;
    byte_t data[];
}DAP_ALIGN_PACKED ecdsa_pvt_serialize_t;


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
    }

    if(!gen_public_key){
        log_it(L_ERROR, "Can't generate public key");
        DAP_FREE(a_key->priv_key_data);
        a_key->priv_key_data_size = 0;
        DAP_FREE(a_key->pub_key_data);
        a_key->pub_key_data_size = 0;
        DAP_FREE(a_key->_inheritor->pub_key_compr_data);
        a_key->_inheritor->pub_key_compr_data_size = 0;
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
    /*ecdsa_curve *curve;
    return (size_t)ecdsa_sign(curve, HASHER_SHA3, a_key->priv_key_data, msg, (uint32_t)msg_size, signature, NULL, NULL);*/
}

size_t dap_enc_sign_ecdsa_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                 void *signature, const size_t signature_size){
    if (signature_size < dap_enc_sign_ecdsa_calc_signature_size()){
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    ecdsa_curve *curve;
    return ecdsa_verify(curve, HASHER_SHA3, a_key->pub_key_data, signature, msg, (uint32_t)msg_size) == 0?1:0;
}

size_t dap_enc_sign_ecdsa_calc_signature_size(void){
    return sizeof(uint64_t);
}

size_t dap_enc_sign_ecdsa_calc_signature_serialized_size(void){
    return sizeof(uint64_t);
}

/* Serialize a signature */
uint8_t* dap_enc_sign_ecdsa_write_signature(uint8_t *a_sign, size_t *a_sign_out){
    if (!a_sign || *a_sign_out != dap_enc_sign_ecdsa_calc_signature_size()){
        return NULL;
    }
    size_t l_shift_mem = 0;
    size_t l_buff_len = dap_enc_sign_ecdsa_calc_signature_serialized_size();
    uint8_t *l_out = DAP_NEW_SIZE(uint8_t, l_buff_len);
    memcpy(l_out, a_sign, sizeof(uint64_t));
    l_shift_mem += sizeof(uint64_t);

    if (a_sign_out)
        *a_sign_out = l_buff_len;
    return l_out;
}

/* Deserialize a signature */
uint8_t* dap_enc_sign_ecdsa_read_signature(uint8_t *a_buff, size_t a_buff_size){
    if(!a_buff || a_buff_size != dap_enc_sign_ecdsa_calc_signature_serialized_size()){
        return NULL;
    }
    uint8_t *l_out = DAP_NEW_SIZE(uint8_t, sizeof(uint64_t));
    memcpy(l_out, a_buff, sizeof(uint64_t));
    return l_out;
}

/* Serialize a private key */
uint8_t *dap_enc_sign_ecdsa_write_private_key(const dap_enc_key_private_ecdsa_t *a_private_key, size_t *a_buflen_out){
    if (a_private_key == NULL) {
        return NULL;
    }
    if (a_private_key->size_key == 0){
        return NULL;
    }
    ecdsa_pvt_serialize_t *pvt = DAP_NEW_Z_SIZE(ecdsa_pvt_serialize_t, sizeof(*pvt) + a_private_key->size_key);
    pvt->curve_type = a_private_key->curve_type;
    pvt->size_key = a_private_key->size_key;
    memcpy(pvt->data, a_private_key->data, sizeof(byte_t) * a_private_key->size_key);
    if (a_buflen_out)
        *a_buflen_out = sizeof(*pvt) + a_private_key->size_key;
    return (uint8_t*)pvt;
}

/* Serialize a public key */
uint8_t *dap_enc_sign_ecdsa_write_public_key(const dap_enc_key_public_ecdsa_t *a_public_key, size_t *a_buflen_out){
    if (a_public_key == NULL){
        return NULL;
    }
    if (a_public_key->size_key == 0){
        return  NULL;
    }
    ecdsa_pvt_serialize_t *pvt = DAP_NEW_Z_SIZE(ecdsa_pvt_serialize_t, sizeof (*pvt) + a_public_key->size_key);
    pvt->curve_type = a_public_key->curve_type;
    pvt->size_key = a_public_key->size_key;
    memcpy(pvt->data, a_public_key->data, sizeof(byte_t) * a_public_key->size_key);
    if (a_buflen_out)
        *a_buflen_out = sizeof(*pvt) + a_public_key->size_key;
    return (uint8_t*)pvt;
}

/* Deserialize a private key. */
dap_enc_key_private_ecdsa_t *dap_enc_sign_ecdsa_read_private_key(const uint8_t *a_buf, size_t a_buflen){
    if (!a_buf || a_buflen  == 0){
        return NULL;
    }
    const ecdsa_pvt_serialize_t *pvt = (const ecdsa_pvt_serialize_t*)a_buf;
    dap_enc_key_private_ecdsa_t *l_private_key = DAP_NEW(dap_enc_key_private_ecdsa_t);
    l_private_key->curve_type = pvt->curve_type;
    l_private_key->size_key = pvt->size_key;
    l_private_key->data = DAP_NEW_Z_SIZE(uint8_t, l_private_key->size_key);
    memcpy(l_private_key->data, pvt->data, sizeof(byte_t) * l_private_key->size_key);
    return  l_private_key;
}

/* Deserialize a public key. */
dap_enc_key_public_ecdsa_t *dap_enc_sign_ecdsa_read_public_key(const uint8_t *a_buf, size_t a_buflen){
    if (!a_buf || a_buflen == 0){
        return NULL;
    }
    const ecdsa_pvt_serialize_t *pvt = (const ecdsa_pvt_serialize_t*)a_buf;
    dap_enc_key_public_ecdsa_t *l_public_key = DAP_NEW(dap_enc_key_public_ecdsa_t);
    l_public_key->curve_type = pvt->curve_type;
    l_public_key->size_key = pvt->size_key;
    l_public_key->data = DAP_NEW_Z_SIZE(uint8_t, l_public_key->size_key);
    memcpy(l_public_key->data, pvt->data, sizeof(byte_t) * pvt->size_key);
    return l_public_key;
}
