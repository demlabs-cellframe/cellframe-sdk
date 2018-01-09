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

#include "dap_enc_aes.h"

#include "dap_enc_key.h"

#define LOG_TAG "dap_enc_key"

struct dap_enc_key_callbacks{
    const char * name;
    dap_enc_callback_dataop_t enc;
    dap_enc_callback_dataop_t dec;
    dap_enc_callback_data_t new_from_callback;
    dap_enc_callback_t new_generate_callback;
    dap_enc_callback_t delete_callback;
} s_callbacks[]={
    [DAP_ENC_KEY_TYPE_AES]={
                            .name = "AES",
                            .enc = dap_enc_aes_encode,
                            .dec = dap_enc_aes_decode,
                            .new_generate_callback = dap_enc_aes_key_new_generate,
                            .new_from_callback = dap_enc_aes_key_new_from
                           }
};

/**
 * @brief dap_enc_key_init
 * @return
 */
int dap_enc_key_init()
{
    size_t i;
    for( i = 0; i< sizeof(s_callbacks)/sizeof(s_callbacks[0]); i++ ){
        switch ((dap_enc_key_type_t) i) {
        case DAP_ENC_KEY_CODE_MCBITS:
        case DAP_ENC_KEY_LWE_FRODO:
        case DAP_ENC_KEY_MLWE_KYBER:
        case DAP_ENC_KEY_NTRU:
        case DAP_ENC_KEY_RLWE_BCNS15:
        case DAP_ENC_KEY_RLWE_MSRLN16:
        case DAP_ENC_KEY_RLWE_NEWHOPE:
        case DAP_ENC_KEY_SIDH_CLN16:
        case DAP_ENC_KEY_SIDH_IQC_REF:
        case DAP_ENC_KEY_SIG_PICNIC:
        case DAP_ENC_KEY_TYPE_AES:
            continue;
        default:
            memset(&s_callbacks[i],0,sizeof(s_callbacks[0]));
        }
    }
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
 * @param key_type
 * @return
 */
dap_enc_key_t *dap_enc_key_new(dap_enc_key_type_t key_type)
{

}

/**
 * @brief dap_enc_key_new_generate
 * @param key_type
 * @param key_size
 * @return
 */
dap_enc_key_t *dap_enc_key_new_generate(dap_enc_key_type_t key_type, size_t key_size)
{
    if(s_callbacks[key_type].name ){
        dap_enc_key_t * ret = dap_enc_ke_n
        s_callbacks[key_type].new_generate_callback()
    }
    return NULL;
}

dap_enc_key_t *dap_enc_key_new_from_str(dap_enc_key_type_t a_type, const char *a_key_str)
{
   enc_key_t * ret= (enc_key_t *) calloc(1,sizeof(enc_key_t) );
   size_t input_size=strlen(key_input);
   switch(v_type){
        case ENC_KEY_TYPE_AES:{
            enc_aes_key_create(ret,key_input);
        }break;
        case ENC_KEY_TYPE_FNAM2:{
           ret->data = (unsigned char*) calloc(1,input_size*2);
           ret->data_size= enc_base64_decode(key_input,input_size,ret->data);
        }break;
   }
   ret->type=v_type;
   return ret;
}

/**
 * @brief dap_enc_key_new_from_data
 * @param a_type
 * @param a_key_input
 * @param a_key_input_size
 * @return
 */
dap_enc_key_t *dap_enc_key_new_from_data(dap_enc_key_type_t a_type, void * a_key_input, size_t a_key_input_size)
{

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

