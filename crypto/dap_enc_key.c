/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <stdlib.h>
#include <string.h>
#include "dap_common.h"

#include "dap_enc_iaes.h"
#include "dap_enc_oaes.h"
#include "dap_enc_msrln.h"
#include "dap_enc_defeo.h"
#include "dap_enc_picnic.h"
#include "dap_enc_bliss.h"

#include "dap_enc_key.h"

#undef LOG_TAG
#define LOG_TAG "dap_enc_key"

struct dap_enc_key_callbacks{
    const char * name;
    dap_enc_callback_dataop_t enc;
    dap_enc_callback_dataop_t dec;
    dap_enc_callback_dataop_na_t enc_na;
    dap_enc_callback_dataop_na_t dec_na;
    dap_enc_callback_calc_out_size enc_out_size;
    dap_enc_callback_calc_out_size dec_out_size;

    dap_enc_gen_bob_shared_key gen_bob_shared_key;
    dap_enc_gen_alice_shared_key gen_alice_shared_key;

    dap_enc_callback_new new_callback;
    dap_enc_callback_data_t new_from_data_public_callback;
    dap_enc_callback_new_generate new_generate_callback;

    dap_enc_callback_delete delete_callback;
} s_callbacks[]={
    // AES
    [DAP_ENC_KEY_TYPE_IAES]={
        .name = "IAES",
        .enc = dap_enc_iaes256_cbc_encrypt,
        .enc_na = dap_enc_iaes256_cbc_encrypt_fast ,
        .dec = dap_enc_iaes256_cbc_decrypt,
        .dec_na = dap_enc_iaes256_cbc_decrypt_fast ,
        .new_callback = dap_enc_aes_key_new,
        .delete_callback = dap_enc_aes_key_delete,
        .new_generate_callback = dap_enc_aes_key_generate,
        .enc_out_size = dap_enc_iaes256_calc_encode_size,
        .dec_out_size = dap_enc_iaes256_calc_decode_size,
    },
    // OAES
    [DAP_ENC_KEY_TYPE_OAES]={
        .name = "OAES",
        .enc = dap_enc_oaes_encrypt,
        .enc_na = dap_enc_oaes_encrypt_fast ,
        .dec = dap_enc_oaes_decrypt,
        .dec_na = dap_enc_oaes_decrypt_fast ,
        .new_callback = dap_enc_oaes_key_new,
        .delete_callback = dap_enc_oaes_key_delete,
        .new_generate_callback = dap_enc_oaes_key_generate,
        .enc_out_size = dap_enc_oaes_calc_encode_size,
        .dec_out_size = dap_enc_oaes_calc_decode_size,
    },
    [DAP_ENC_KEY_TYPE_MSRLN] = {
        .name = "MSRLN",
        .enc = NULL,
        .dec = NULL,
        .new_callback = dap_enc_msrln_key_new,
        .delete_callback = dap_enc_msrln_key_delete,
        .new_generate_callback = dap_enc_msrln_key_generate,
        .gen_bob_shared_key = dap_enc_msrln_gen_bob_shared_key,
        .gen_alice_shared_key = dap_enc_msrln_gen_alice_shared_key,
        .new_from_data_public_callback = dap_enc_msrln_key_new_from_data_public,
        .enc_out_size = NULL,
        .dec_out_size = NULL
    },
    [DAP_ENC_KEY_TYPE_DEFEO]={
        .name = "DEFEO",
        .enc = NULL,
        .dec = NULL,
        .gen_bob_shared_key = dap_enc_defeo_gen_bob_shared_key,
        .gen_alice_shared_key = dap_enc_defeo_gen_alice_shared_key,
        .new_callback = dap_enc_defeo_key_new,
        .delete_callback = dap_enc_defeo_key_delete,
        .new_generate_callback = dap_enc_defeo_key_new_generate,
        .enc_out_size = NULL,
        .dec_out_size = NULL
    },
    [DAP_ENC_KEY_TYPE_SIG_PICNIC]={
        .name = "PICNIC",
        .enc_na = dap_enc_picnic_enc_na,
        .dec_na = dap_enc_picnic_dec_na,
        .gen_bob_shared_key = NULL,
        .gen_alice_shared_key = NULL,
        .new_callback = dap_enc_defeo_key_new,
        .delete_callback = dap_enc_defeo_key_delete,
        .new_generate_callback = dap_enc_defeo_key_new_generate,
        .enc_out_size = NULL,
        .dec_out_size = NULL

    },
    [DAP_ENC_KEY_TYPE_SIG_BLISS]={
        .name = "SIG_BLISS",
        .enc = NULL,
        .dec = NULL,
        .enc_na = dap_enc_sig_bliss_get_sign,
        .dec_na = dap_enc_sig_bliss_verify_sign,
        .gen_bob_shared_key = NULL,
        .gen_alice_shared_key = NULL,
        .new_callback = dap_enc_sig_bliss_key_new,
        .delete_callback = dap_enc_sig_bliss_key_delete,
        .new_generate_callback = dap_enc_sig_bliss_key_new_generate,
        .enc_out_size = NULL,
        .dec_out_size = NULL
    }
};

const size_t c_callbacks_size = sizeof(s_callbacks) / sizeof(s_callbacks[0]);

/**
 * @brief dap_enc_key_init
 * @return
 */
int dap_enc_key_init()
{
    return 0;
}

/**
 * @brief dap_enc_key_deinit
 */
void dap_enc_key_deinit()
{

}

/**
 * @brief dap_enc_key_serealize
 * @param key
 * @return allocates dap_enc_key_serealize_t* dont remember use free()
 */
dap_enc_key_serealize_t* dap_enc_key_serealize(dap_enc_key_t * key)
{
    dap_enc_key_serealize_t *result = DAP_NEW_Z(dap_enc_key_serealize_t);
    result->priv_key_data_size = key->priv_key_data_size;
    result->pub_key_data_size = key->pub_key_data_size;
    result->last_used_timestamp = key->last_used_timestamp;
    result->inheritor_size = key->_inheritor_size;
    result->type = key->type;
    memcpy(result->priv_key_data, key->priv_key_data, key->priv_key_data_size);
    memcpy(result->pub_key_data, key->pub_key_data, key->pub_key_data_size);
    memcpy(result->inheritor, key->_inheritor, key->_inheritor_size);
    return result;
}

/**
 * @brief dap_enc_key_deserealize
 * @param buf
 * @param buf_size
 * @return allocates dap_enc_key_t*. Use dap_enc_key_delete for free memory
 */
dap_enc_key_t* dap_enc_key_deserealize(void *buf, size_t buf_size)
{
    if(buf_size != sizeof (dap_enc_key_serealize_t)) {
        log_it(L_ERROR, "Key can't be deserealize. buf_size != sizeof (dap_enc_key_serealize_t)");
        return NULL;
    }
    dap_enc_key_serealize_t *in_key = (dap_enc_key_serealize_t *)buf;
    dap_enc_key_t *result = dap_enc_key_new(in_key->type);
    result->last_used_timestamp = in_key->last_used_timestamp;
    result->priv_key_data_size = in_key->priv_key_data_size;
    result->pub_key_data_size = in_key->pub_key_data_size;
    result->_inheritor_size = in_key->inheritor_size;
    memcpy(result->priv_key_data, in_key->priv_key_data, result->priv_key_data_size);
    memcpy(result->pub_key_data, in_key->pub_key_data, result->pub_key_data_size);

    if(in_key->inheritor_size)
        memcpy(result->_inheritor, in_key->inheritor, in_key->inheritor_size);
    else
        result->_inheritor = NULL;

    return result;
}

/**
 * @brief dap_enc_key_new
 * @param a_key_type
 * @return
 */
dap_enc_key_t *dap_enc_key_new(dap_enc_key_type_t a_key_type)
{
    dap_enc_key_t * ret = NULL;
    if(a_key_type < c_callbacks_size ){
        ret = DAP_NEW_Z(dap_enc_key_t);
        if(s_callbacks[a_key_type].new_callback){
            s_callbacks[a_key_type].new_callback(ret);
        }
    }
    ret->type = a_key_type;
    return ret;
}

/**
 * @brief dap_enc_key_new_generate
 * @param a_key_type
 * @param kex_buf
 * @param kex_size
 * @param seed
 * @param seed_size
 * @param key_size - can be NULL ( generate size by default )
 * @return
 */
dap_enc_key_t *dap_enc_key_new_generate(dap_enc_key_type_t a_key_type, const void *kex_buf,
                                        size_t kex_size, const void* seed,
                                        size_t seed_size, size_t key_size)
{
    dap_enc_key_t * ret = NULL;
    if(a_key_type< c_callbacks_size ) {
        ret = dap_enc_key_new(a_key_type);
        if(s_callbacks[a_key_type].new_generate_callback) {
            s_callbacks[a_key_type].new_generate_callback( ret, kex_buf, kex_size, seed, seed_size, key_size);
        }
    }
    return ret;
}


/**
 * @brief dap_enc_key_delete
 * @param a_key
 */
void dap_enc_key_delete(dap_enc_key_t * a_key)
{
    if(s_callbacks[a_key->type].delete_callback) {
        s_callbacks[a_key->type].delete_callback(a_key);
    } else {
        log_it(L_ERROR, "delete callback is null. Can be leak memory!");
    }
    /* a_key->_inheritor must be cleaned in delete_callback func */

    free(a_key->pub_key_data);
    free(a_key->priv_key_data);
    free(a_key);
}

size_t dap_enc_key_get_enc_size(dap_enc_key_t * a_key, const size_t buf_in_size)
{
    if(s_callbacks[a_key->type].enc_out_size) {
        return s_callbacks[a_key->type].enc_out_size(buf_in_size);
    }
    log_it(L_ERROR, "enc_out_size not realize for current key type");
    return 0;
}

size_t dap_enc_key_get_dec_size(dap_enc_key_t * a_key, const size_t buf_in_size)
{
    if(s_callbacks[a_key->type].dec_out_size) {
        return s_callbacks[a_key->type].dec_out_size(buf_in_size);
    }
    log_it(L_ERROR, "dec_out_size not realize for current key type");
    return 0;
}
