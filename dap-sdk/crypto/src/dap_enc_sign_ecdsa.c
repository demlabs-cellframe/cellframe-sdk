#include "dap_enc_sign_ecdsa.h"

#define LOG_TAG "dap_enc_sign_ecdsa"

void dap_enc_sign_ecdsa_key_new(struct dap_enc_key *a_key){
    a_key->type = DAP_ENC_KEY_TYPE_ECDSA_0;
    a_key->enc = NULL;
    a_key->dec = NULL;
    a_key->enc_na = dap_enc_sign_ecdsa_get;
    a_key->dec_na = dap_enc_sign_ecdsa_verify;
    //1a_key->
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
size_t dap_enc_sign_ecdsa_calc_signature_serialized_size(){
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
