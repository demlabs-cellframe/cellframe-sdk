#include "dap_enc_sign_ecdsa.h"

#define LOG_TAG "dap_enc_sign_ecdsa"

void dap_enc_sign_ecdsa_key_new(struct dap_enc_key *a_key){
    //a_key->type = DAP_ENC_KEY_TYPE_ECDSA_0;
    a_key->enc = NULL;
    a_key->dec = NULL;
    a_key->enc_na = dap_enc_sign_ecdsa_get;
    a_key->dec_na = dap_enc_sign_ecdsa_verify;
    //1a_key->
}
//void _dap_enc_sign_ecdsa_key
void dap_enc_sign_ecdsa_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                         const void *seed, size_t seed_size, size_t key_size) {
    (void)kex_size;
    (void)seed;
    (void)seed_size;
    a_key->pub_key_data = DAP_NEW(dap_enc_key_public_ecdsa_t);
    a_key->pub_key_data_size = sizeof (dap_enc_key_public_ecdsa_t);
    a_key->priv_key_data = DAP_NEW(dap_enc_key_private_ecdsa_t);
    a_key->priv_key_data_size = sizeof(dap_enc_key_private_ecdsa_t);
    const ecdsa_curve *curve;
    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_ECDSA_ED25519:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
//        curve = &ed25519
        //random_buffer(data)
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_NIST256P1:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_SECP256K1:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_ED25519_EX:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_extended_size;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_ED25519;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_NIST256P1_EX:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_extended_size;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_NIST256p1;
        break;
    case DAP_ENC_KEY_TYPE_ECDSA_SECP256K1_EX:
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561;
        ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_extended_size;
        ((dap_enc_key_public_ecdsa_t*)a_key->pub_key_data)->curve_type = DAP_ENC_CURVE_TYPE_SECP2561;
        break;
    default:
        log_it(L_ERROR, "Key have type ");
        return;
    }
    //((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key = c_dap_enc_key_private_size;
    random_buffer(((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->data,
                  ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->size_key);
//    const ecdsa_curve *curve;
    /*switch ( ((dap_enc_key_private_ecdsa_t*)a_key->priv_key_data)->curve_type ) {
    case DAP_ENC_CURVE_TYPE_ED25519:
        break;
    case DAP_ENC_CURVE_TYPE_NIST256p1:
        break;
    case DAP_ENC_CYRVE_TYPE_SECP256k1:
        break;
    case DAP_ENC_CURVE_TYPE_CURVE25519:
        break;
    case DAP_ENC_CURVE_TYPE_ED25519Blake2b:
        break;
    }*/
}
size_t dap_enc_sign_ecdsa_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){    
    if(signature_size < dap_enc_sign_ecdsa_calc_signature_size()){
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    ecdsa_curve *curve;
    return (size_t)ecdsa_sign(curve, HASHER_SHA3, a_key->priv_key_data, msg, (uint32_t)msg_size, signature, NULL, NULL);
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
