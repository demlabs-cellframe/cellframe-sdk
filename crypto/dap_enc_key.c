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

#include "dap_enc_aes.h"
#include "dap_enc_newhope.h"
#include "dap_enc_sidh16.h"
#include "dap_enc_msrln16.h"

#include "dap_enc_key.h"

#define LOG_TAG "dap_enc_key"

struct dap_enc_key_callbacks{
    const char * name;
    size_t size_max;
    dap_enc_callback_dataop_t enc;
    dap_enc_callback_dataop_t dec;
    dap_enc_callback_pptr_r_size_t key_public_raw_callback;

    dap_enc_callback_t new_callback;
    dap_enc_callback_size_t new_calllback_size;
    dap_enc_callback_data_t new_from_data_callback;
    dap_enc_callback_data_t new_from_data_public_callback;
    dap_enc_callback_str_t new_from_str_callback;

    dap_enc_callback_t delete_callback;
} s_callbacks[]={
    // AES
    [DAP_ENC_KEY_TYPE_AES]={
                            .name = "AES",
                            .size_max = 8,
                            .enc = dap_enc_aes_encode,
                            .dec = dap_enc_aes_decode,
                            .new_callback = dap_enc_aes_key_new,
                            .delete_callback = NULL,
                            .new_calllback_size = dap_enc_aes_key_new_size,
                            .new_from_data_callback = dap_enc_aes_key_new_from_data,
                            .new_from_str_callback = dap_enc_aes_key_new_from_str
                           },
    // NEW HOPE
    [DAP_ENC_KEY_TYPE_RLWE_NEWHOPE]={
                            .name = "NEWHOPE",
                            .size_max = 64,
                            .enc = dap_enc_newhope_encode,
                            .dec = dap_enc_newhope_decode,
                            .new_callback = dap_enc_newhope_key_new,
                            .delete_callback = NULL,
                            .new_calllback_size = dap_enc_newhope_key_new_size,
                            .new_from_data_callback = dap_enc_newhope_key_new_from_data,
                            .key_public_raw_callback = dap_enc_newhope_key_public_raw,
                            .new_from_data_public_callback = dap_enc_newhope_key_new_from_data_public
                           },
    [DAP_ENC_KEY_TYPE_SIDH_CLN16]={
                            .name = "SIDHCLN16",
                            .size_max = 64,
                            .enc = dap_enc_sidh16_encode,
                            .dec = dap_enc_sidh16_decode,
                            .new_callback = dap_enc_sidh16_key_new,
                            .delete_callback = NULL,
                            .new_calllback_size = dap_enc_sidh16_key_new_size,
                            .new_from_data_callback = dap_enc_sidh16_key_new_from_data
                           },
    [DAP_ENC_KEY_TYPE_RLWE_MSRLN16] = {
                            .name = "MSRLN16",
                            .size_max = 64,
                            .enc = dap_enc_msrln16_encode,
                            .dec = dap_enc_msrln16_decode,
                            .new_callback = dap_enc_msrln16_key_new,
                            .delete_callback =NULL,
                            .new_calllback_size = dap_enc_msrln16_key_new_size,
                            .new_from_data_callback = dap_enc_msrln16_key_new_from_data,
                            .key_public_raw_callback = dap_enc_msrln16_key_public_raw,
                            .new_from_data_public_callback = dap_enc_msrln16_key_new_from_data_public
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
 * @brief dap_enc_key_new
 * @param a_key_type
 * @return
 */
dap_enc_key_t *dap_enc_key_new(dap_enc_key_type_t a_key_type)
{
    dap_enc_key_t * ret = NULL;
    if(a_key_type< c_callbacks_size ){
        ret = DAP_NEW_Z(dap_enc_key_t);
        if(s_callbacks[a_key_type].new_callback){
            s_callbacks[a_key_type].new_callback(ret);
        }
    }
    return ret;
}

/**
 * @brief dap_enc_key_new_generate
 * @param a_key_type
 * @param a_key_size
 * @return
 */
dap_enc_key_t *dap_enc_key_new_generate(dap_enc_key_type_t a_key_type, size_t a_key_size)
{
    dap_enc_key_t * ret = NULL;

    if(a_key_type< c_callbacks_size ){
        ret = dap_enc_key_new (a_key_type);
        if( s_callbacks[a_key_type].new_calllback_size) {
            s_callbacks[a_key_type].new_calllback_size(ret,a_key_size);
        }
    }
    return ret;
}

/**
 * @brief dap_enc_key_new_from_str
 * @param a_keyt_type
 * @param a_key_str
 * @return
 */
dap_enc_key_t *dap_enc_key_new_from_str(dap_enc_key_type_t a_key_type, const char *a_key_str)
{
    dap_enc_key_t * ret = NULL;

    if(a_key_type< c_callbacks_size ){
        ret = DAP_NEW_Z(dap_enc_key_t);
        if(s_callbacks[a_key_type].new_from_str_callback){
            s_callbacks[a_key_type].new_from_str_callback(ret,a_key_str);
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
    if( a_key->delete_callback )
        a_key->delete_callback( a_key );

    if( a_key->data )
        free( a_key->data );

    if( a_key->_inheritor )
        free( a_key->_inheritor );

    free(a_key);
}

/**
 * @brief dap_enc_key_new_from_data
 * @param a_key_type
 * @param a_key_input
 * @param a_key_input_size
 * @return
 */
dap_enc_key_t *dap_enc_key_new_from_data(dap_enc_key_type_t a_key_type, void * a_key_input, size_t a_key_input_size)
{
    dap_enc_key_t * ret = NULL;

    if(a_key_type< c_callbacks_size ){
        ret = DAP_NEW_Z(dap_enc_key_t);
        s_callbacks[a_key_type].new_from_data_callback(ret,a_key_input, a_key_input_size);
    }
    return ret;
}



