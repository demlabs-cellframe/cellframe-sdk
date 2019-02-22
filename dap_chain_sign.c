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

#include <string.h>

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
        case DAP_ENC_KEY_TYPE_SIG_TESLA: dap_enc_tesla_calc_signature_size(); break;
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
 * @brief dap_chain_sign_type_to_str
 * @param a_chain_sign_type
 * @return
 */
const char * dap_chain_sign_type_to_str(dap_chain_sign_type_t a_chain_sign_type)
{
    switch (a_chain_sign_type.type) {
        case DAP_ENC_KEY_TYPE_SIG_BLISS: return "sig_bliss";
        case DAP_ENC_KEY_TYPE_SIG_TESLA: return "sig_tesla";
        case DAP_ENC_KEY_TYPE_SIG_PICNIC: return "sig_picnic";
        default: return DAP_ENC_KEY_TYPE_NULL;
    }

}

/**
 * @brief dap_chain_sign_type_from_str
 * @param a_type_str
 * @return
 */
dap_chain_sign_type_t dap_chain_sign_type_from_str(const char * a_type_str)
{
    dap_chain_sign_type_t l_sign_type = {0};
    if ( strcmp (a_type_str,"sig_bliss") == 0 ){
        l_sign_type.type = SIG_TYPE_BLISS;
    } else if ( strcmp (a_type_str,"sig_tesla") == 0){
        l_sign_type.type = SIG_TYPE_TESLA;
    } else if ( strcmp (a_type_str,"sig_picnic") == 0){
        l_sign_type.type = SIG_TYPE_PICNIC;
    }else{
       log_it (L_WARNING, "Wrong sign type string \"%s\"",a_type_str);
    }
    return l_sign_type;
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
    size_t l_sign_size = dap_chain_sign_create_output_cals_size(a_key,a_output_wish_size);
    if (l_sign_size > 0 ) {
        size_t l_ret_size = sizeof(dap_chain_sign_t) + a_key->pub_key_data_size + l_sign_size;
        dap_chain_sign_t * l_ret = DAP_NEW_Z_SIZE(dap_chain_sign_t, l_ret_size );
        if (l_ret){
            l_ret->header.sign_pkey_size = a_key->pub_key_data_size;
            l_ret->header.sign_size = ( l_ret_size - sizeof(l_ret->header) - a_key->pub_key_data_size );
            if ( dap_chain_sign_create_output(a_key,a_data,a_data_size,l_ret->pkey_n_sign + a_key->pub_key_data_size ,
                                              l_ret->header.sign_size ) !=0 ){
                DAP_DELETE(l_ret);
                return NULL;
            }else{
                memcpy(l_ret->pkey_n_sign, a_key->pub_key_data, a_key->pub_key_data_size);
                switch (a_key->type)
                {
                case DAP_ENC_KEY_TYPE_SIG_BLISS:
                    l_ret->header.type.raw = SIG_TYPE_BLISS;
                    break;
                case DAP_ENC_KEY_TYPE_SIG_TESLA:
                    l_ret->header.type.raw = SIG_TYPE_TESLA;
                    break;
                case DAP_ENC_KEY_TYPE_SIG_PICNIC:
                    l_ret->header.type.raw = SIG_TYPE_PICNIC;
                    break;
                case DAP_ENC_KEY_TYPE_DEFEO:
                    l_ret->header.type.raw = SIG_TYPE_DEFO;
                    break;
                default:
                    l_ret->header.type.raw = SIG_TYPE_NULL;
                }
                return l_ret;
            }
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
        case DAP_ENC_KEY_TYPE_SIG_TESLA:
        case DAP_ENC_KEY_TYPE_SIG_PICNIC:
            return (a_key->enc_na(a_key, a_data, a_data_size, a_output, a_output_size) > 0 )
                    ? 0 : -1;
        case DAP_ENC_KEY_TYPE_SIG_BLISS:
            return dap_enc_sig_bliss_get_sign( a_key, a_data, a_data_size, a_output, a_output_size) == BLISS_B_NO_ERROR
                    ? 0: -1;
        default: return -1;
    }
}

/**
 * @brief dap_chain_sign_to_enc_key
 * @param a_chain_sign
 * @return
 */
dap_enc_key_t *dap_chain_sign_to_enc_key(dap_chain_sign_t * a_chain_sign)
{
    dap_enc_key_t * l_ret =  dap_enc_key_new( dap_chain_sign_type_to_key_type( a_chain_sign->header.type  ) );
    l_ret->pub_key_data_size = a_chain_sign->header.sign_pkey_size;
    l_ret->pub_key_data = a_chain_sign->pkey_n_sign;
    return l_ret;
}

/**
 * @brief dap_chain_sign_verify
 * @param a_chain_sign
 * @param a_data
 * @param a_data_size
 * @return 1 valid signature, 0 invalid signature, -1 unsupported sign type
 */
int dap_chain_sign_verify (dap_chain_sign_t * a_chain_sign, const void * a_data, const size_t a_data_size)
{
    dap_enc_key_t * l_key = dap_chain_sign_to_enc_key (a_chain_sign);
    uint8_t * l_sign = a_chain_sign->pkey_n_sign + a_chain_sign->header.sign_pkey_size;
    size_t l_sign_size = a_chain_sign->header.sign_size;
    switch (l_key->type){
        case DAP_ENC_KEY_TYPE_SIG_TESLA:
        case DAP_ENC_KEY_TYPE_SIG_PICNIC:
            return (l_key->dec_na ( l_key, a_data, a_data_size, l_sign, l_sign_size) > 0 )
                    ? 0 : 1;
        case DAP_ENC_KEY_TYPE_SIG_BLISS:
            return dap_enc_sig_bliss_verify_sign( l_key, a_data, a_data_size, l_sign, l_sign_size );
        default: return -1;
    }
}

/**
 * Get size of struct dap_chain_sign_t
 */
size_t dap_chain_sign_get_size(dap_chain_sign_t * a_chain_sign)
{
    if(!a_chain_sign)
        return 0;
    return (sizeof(dap_chain_sign_t) + a_chain_sign->header.sign_size + a_chain_sign->header.sign_pkey_size);
}
