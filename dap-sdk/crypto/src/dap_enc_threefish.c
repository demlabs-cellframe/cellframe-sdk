#include "dap_enc_threefish.h"


void dap_enc_threefish_key_new(struct dap_enc_key *a_key){
    a_key->type = DAP_ENC_KEY_TYPE_THREEFISH;
    a_key->priv_key_data = NULL;
    a_key->priv_key_data_size = 0;
    a_key->enc = dap_enc_threefish_encrypt;
    a_key->dec = dap_enc_threefish_decrypt;
}

void dap_enc_threefish_generate(struct dap_enc_key *a_key){
    a_key->priv_key_data_size = THREEFISH_KEY_SIZE + THREEFISH_TWEEK_SIZE;
    a_key->priv_key_data = (uint8_t *)malloc(a_key->priv_key_data_size);
    randombytes(a_key->priv_key_data, (unsigned int)a_key->priv_key_data_size);
}
