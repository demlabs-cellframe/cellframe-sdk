/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_common.h"
#include "dap_chain_sign.h"
#include "dap_enc_bliss.h"
#include "dap_enc_tesla.h"
#include "dap_enc_picnic.h"

#define LOG_TAG "dap_chain_sign"

dap_chain_sign_t * s_sign_null = NULL;
bliss_signature_t s_sign_bliss_null = {0};
size_t dap_chain_sign_create_output_cals_size(dap_enc_key_t * a_key, size_t a_output_wish_size )
{
    size_t l_sign_size = 0;
    switch (a_key->type){
        case DAP_ENC_KEY_TYPE_SIG_BLISS: l_sign_size = sizeof(s_sign_bliss_null); break;
        case DAP_ENC_KEY_TYPE_SIG_PICNIC: dap_enc_picnic_calc_signature_size(a_key); break;
        default : return 0;

    }
    return sizeof(s_sign_null->header)+ a_key->pub_key_data_size + l_sign_size;
}

/**
 * @brief dap_chain_sign_type_from_key_type
 * @param a_key_type
 * @return
 */
dap_chain_sign_type_t dap_chain_sign_type_from_key_type( dap_enc_key_type_t a_key_type)
{
    dap_chain_sign_type_t l_sign_type={0};
    switch (a_key_type){
        case DAP_ENC_KEY_TYPE_SIG_BLISS: l_sign_type.type = SIG_TYPE_BLISS; break;
        case DAP_ENC_KEY_TYPE_SIG_PICNIC: l_sign_type.type = SIG_TYPE_PICNIC; break;
        case DAP_ENC_KEY_TYPE_SIG_TESLA: l_sign_type.type = SIG_TYPE_TESLA; break;
    }
    return l_sign_type;

}

/**
 * @brief dap_chain_sign_type_to_key_type
 * @param a_chain_sign_type
 * @return
 */
dap_enc_key_type_t  dap_chain_sign_type_to_key_type(dap_chain_sign_type_t  a_chain_sign_type)
{
    switch (a_chain_sign_type.type) {
        case SIG_TYPE_BLISS: return DAP_ENC_KEY_TYPE_SIG_BLISS;
        case SIG_TYPE_TESLA: return DAP_ENC_KEY_TYPE_SIG_TESLA;
        case SIG_TYPE_PICNIC: return DAP_ENC_KEY_TYPE_SIG_PICNIC;
        default: return DAP_ENC_KEY_TYPE_NULL;
    }
}

/**
 * @brief dap_chain_sign_create
 * @param a_key
 * @param a_data
 * @param a_data_size
 * @param a_output_wish_size
 * @return
 */
dap_chain_sign_t * dap_chain_sign_create(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size,
                                      size_t a_output_wish_size )
{
    size_t l_ret_size = dap_chain_sign_create_output_cals_size(a_key,a_output_wish_size);
    if (l_ret_size > 0 ) {
        dap_chain_sign_t * l_ret = DAP_NEW_Z_SIZE(dap_chain_sign_t,
                                                  l_ret_size );
        if (l_ret){
            if ( dap_chain_sign_create_output(a_key,a_data,a_data_size,l_ret,l_ret_size) !=0 ){
                DAP_DELETE(l_ret);
                return NULL;
            }else
                return l_ret;
        }
    }else
        return NULL;

}

/**
 * @brief dap_chain_sign_create_output
 * @param a_key
 * @param a_data
 * @param a_data_size
 * @param a_output
 * @return
 */
int dap_chain_sign_create_output(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size, void * a_output
                                 ,size_t a_output_size)
{
    switch (a_key->type){
        default: return -1;
    }
    return 0;
}

/**
 * @brief dap_chain_sign_to_enc_key
 * @param a_chain_sign
 * @return
 */
dap_enc_key_t *dap_chain_sign_to_enc_key(dap_chain_sign_t * a_chain_sign)
{

}

/**
 * @brief dap_chain_sign_verify
 * @param a_chain_sign
 * @return
 */
int dap_chain_sign_verify (dap_chain_sign_t * a_chain_sign)
{

}
