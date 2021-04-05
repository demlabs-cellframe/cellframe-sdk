#include "dap_enc_sign_schnorr.h"

void dap_enc_sign_schnorr_key_new(struct dap_enc_key * a_key){
    a_key->type = DAP_ENC_KEY_TYPE_SCHNORR_0;
    a_key->enc = NULL;
    a_key->enc_na = NULL;
    a_key->dec = NULL;
    a_key->dec_na = NULL;
    a_key->sign_get = dap_enc_sign_schnorr_get;
    a_key->sign_verify = dap_enc_sign_schnorr_verify;
}

void dap_enc_sign_schnorr_key_new_generate(struct dap_enc_key * a_key, const void *kex_buf, size_t kex_size,
                                            const void *seed, size_t seed_size, size_t key_size){}
size_t dap_enc_sign_schnorr_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){
    return 0;
}
size_t dap_enc_sign_schnorr_verify(struct dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){
    return 0;

}
void dap_enc_sign_schnorr_key_delete(struct dap_enc_key *a_key){}

size_t dap_enc_sign_schnorr_calc_signature_size(void){
    return 0;
}