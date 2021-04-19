#include "dap_enc_sign_schnorr.h"

#define LOG_TAG "dap_enc_sign_schnorr"


void dap_enc_sign_schnorr_key_new(struct dap_enc_key * a_key){
    a_key->type = DAP_ENC_KEY_TYPE_SCHNORR_0;
    a_key->enc = NULL;
    a_key->dec = NULL;
    a_key->enc_na = dap_enc_sign_schnorr_get;
    a_key->dec_na = dap_enc_sign_schnorr_verify;
    //a_key->sign_get = dap_enc_sign_schnorr_get;
    //a_key->sign_verify = dap_enc_sign_schnorr_verify;
}

void dap_enc_sign_schnorr_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                            const void *seed, size_t seed_size, size_t key_size){
    if (a_key == NULL)
        return;
    (void)kex_buf;
    (void)kex_size;
    (void)seed;
    (void)seed_size;
    a_key->priv_key_data = DAP_NEW_SIZE(uint8_t, key_size);
}
size_t dap_enc_sign_schnorr_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){
    if(signature_size < sizeof(schnorr_sign_pair)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    bignum256 *k;
    ecdsa_curve *curve;
    schnorr_sign_pair *sign = DAP_NEW(schnorr_sign_pair);
    int result = schnorr_sign(curve, a_key->priv_key_data, k, msg, msg_size, sign);
    if (result == 0 ){
        signature = sign;
        return sizeof(schnorr_sign_pair);
    } else {
        log_it(L_ERROR, "Can't get sign for message.");
        return 0;
    }
}
size_t dap_enc_sign_schnorr_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){
    if(signature_size < sizeof(schnorr_sign_pair)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    ecdsa_curve *curve;
    return schnorr_verify(curve, a_key->pub_key_data, msg, msg_size, (schnorr_sign_pair*)signature);
}
void dap_enc_sign_schnorr_key_delete(struct dap_enc_key *a_key){}

size_t dap_enc_sign_schnorr_calc_signature_size(void){
    return sizeof(schnorr_sign_pair);
}
size_t dap_enc_sign_schnorr_calc_signature_serialized_size(void){
    return ((sizeof (uint8_t) * 32) +(sizeof (uint8_t) * 32));
}

/* Serialize a signature */
uint8_t* dap_enc_sign_schnorr_write_signature(schnorr_sign_pair *a_sign, size_t *a_sign_out){
    if(!a_sign || *a_sign_out!=sizeof(schnorr_sign_pair)) {
        return NULL ;
    }
    size_t l_shift_mem = 0;
    size_t l_buff_len = dap_enc_sign_schnorr_calc_signature_serialized_size();
    uint8_t *l_out = DAP_NEW_SIZE(uint8_t, l_buff_len);
    memcpy(l_out, a_sign->r, sizeof(uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;
    memcpy(l_out + l_shift_mem, a_sign->s, sizeof (uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;

    if (a_sign_out)
        *a_sign_out = l_buff_len;
    return l_out;
}

/* Deserialize a signature */
schnorr_sign_pair* dap_enc_sign_schnorr_read_signature(uint8_t *a_buff, size_t a_buff_size){
    if (a_buff_size != dap_enc_sign_schnorr_calc_signature_serialized_size()){
        return NULL;
    }
    schnorr_sign_pair *l_sign = DAP_NEW(schnorr_sign_pair);
    size_t l_shift_mem = 0;
    memcpy(&l_sign->r, a_buff, sizeof(uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;
    memcpy(&l_sign->s, a_buff + l_shift_mem, sizeof(uint8_t) * 32);
    l_shift_mem += sizeof (uint8_t) * 32;
    return  l_sign;
}
