#include "dap_enc_sign_ecdsa.h"

#define LOG_TAG "dap_enc_sign_ecdsa"

void dap_enc_sign_ecdsa_key_new(struct dap_enc_key *a_key){
    a_key->type = DAP_ENC_KEY_TYPE_ESCDA;
    a_key->enc = NULL;
    a_key->dec = NULL;
    a_key->enc_na = dap_enc_sign_ecdsa_get;
    a_key->dec_na = dap_enc_sign_ecdsa_verify;
    //1a_key->
}
size_t dap_enc_sign_ecdsa_get(struct  dap_enc_key *a_key, const void *msg, const size_t msg_size,
                                void *signature, const size_t signature_size){    
    //KEY
    if(signature_size < sizeof(schnorr_sign_pair)) {
        log_it(L_ERROR, "bad signature size");
        return 0;
    }
    return 0;
}