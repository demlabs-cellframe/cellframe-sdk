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
#include "dap_hash.h"
#include "dap_sign.h"
#include "dap_enc_bliss.h"
#include "dap_enc_tesla.h"
#include "dap_enc_picnic.h"
#include "dap_enc_dilithium.h"

#define LOG_TAG "dap_sign"

static dap_sign_t * s_sign_null = NULL;
static bliss_signature_t s_sign_bliss_null = {0};

// calc signature size
size_t dap_sign_create_output_unserialized_calc_size(dap_enc_key_t * a_key, size_t a_output_wish_size )
{
    if(!a_key)
        return 0;
    size_t l_sign_size = 0;
    switch (a_key->type){
        case DAP_ENC_KEY_TYPE_SIG_BLISS: l_sign_size = sizeof(s_sign_bliss_null); break;
        case DAP_ENC_KEY_TYPE_SIG_PICNIC: l_sign_size = dap_enc_picnic_calc_signature_size(a_key); break;
        case DAP_ENC_KEY_TYPE_SIG_TESLA: l_sign_size = dap_enc_tesla_calc_signature_size(); break;
        case DAP_ENC_KEY_TYPE_SIG_DILITHIUM: l_sign_size = dap_enc_dilithium_calc_signature_unserialized_size(); break;
        default : return 0;

    }
    return l_sign_size;
    //return sizeof(s_sign_null->header)+ a_key->pub_key_data_size + l_sign_size;
}


/**
 * @brief dap_sign_type_from_key_type
 * @param a_key_type
 * @return
 */
dap_sign_type_t dap_sign_type_from_key_type( dap_enc_key_type_t a_key_type)
{
    dap_sign_type_t l_sign_type;
    switch (a_key_type){
        case DAP_ENC_KEY_TYPE_SIG_BLISS: l_sign_type.type = SIG_TYPE_BLISS; break;
        case DAP_ENC_KEY_TYPE_SIG_PICNIC: l_sign_type.type = SIG_TYPE_PICNIC; break;
        case DAP_ENC_KEY_TYPE_SIG_TESLA: l_sign_type.type = SIG_TYPE_TESLA; break;
        case DAP_ENC_KEY_TYPE_SIG_DILITHIUM: l_sign_type.type = SIG_TYPE_DILITHIUM; break;
        default: l_sign_type.raw = 0;
    }
    return l_sign_type;
}

/**
 * @brief dap_sign_type_to_key_type
 * @param a_chain_sign_type
 * @return
 */
dap_enc_key_type_t  dap_sign_type_to_key_type(dap_sign_type_t  a_chain_sign_type)
{
    switch (a_chain_sign_type.type) {
        case SIG_TYPE_BLISS: return DAP_ENC_KEY_TYPE_SIG_BLISS;
        case SIG_TYPE_TESLA: return DAP_ENC_KEY_TYPE_SIG_TESLA;
        case SIG_TYPE_PICNIC: return DAP_ENC_KEY_TYPE_SIG_PICNIC;
        case SIG_TYPE_DILITHIUM: return DAP_ENC_KEY_TYPE_SIG_DILITHIUM;
        default: return DAP_ENC_KEY_TYPE_NULL;
    }
}



/**
 * @brief dap_sign_type_to_str
 * @param a_chain_sign_type
 * @return
 */
const char * dap_sign_type_to_str(dap_sign_type_t a_chain_sign_type)
{
    switch (a_chain_sign_type.type) {
        case SIG_TYPE_BLISS: return "sig_bliss";
        case SIG_TYPE_TESLA: return "sig_tesla";
        case SIG_TYPE_PICNIC: return "sig_picnic";
        case SIG_TYPE_DILITHIUM: return "sig_dil";
        default: return "UNDEFINED";//DAP_ENC_KEY_TYPE_NULL;
    }

}

/**
 * @brief dap_pkey_type_from_sign
 * @param a_pkey_type
 * @return
 */
dap_sign_type_t dap_pkey_type_from_sign( dap_pkey_type_t a_pkey_type)
{
    dap_sign_type_t l_sign_type={0};
    switch (a_pkey_type.type){
        case PKEY_TYPE_SIGN_BLISS: l_sign_type.type = SIG_TYPE_BLISS; break;
        case PKEY_TYPE_SIGN_PICNIC: l_sign_type.type = SIG_TYPE_PICNIC; break;
        case PKEY_TYPE_SIGN_TESLA: l_sign_type.type = SIG_TYPE_TESLA; break;
        case PKEY_TYPE_SIGN_DILITHIUM : l_sign_type.type = SIG_TYPE_DILITHIUM; break;
        case PKEY_TYPE_MULTI: l_sign_type.type = SIG_TYPE_MULTI; break;
        case PKEY_TYPE_NULL: l_sign_type.type = SIG_TYPE_NULL; break;
    }
    return l_sign_type;
}


/**
 * @brief dap_sign_type_from_str
 * @param a_type_str
 * @return
 */
dap_sign_type_t dap_sign_type_from_str(const char * a_type_str)
{
    dap_sign_type_t l_sign_type = {0};
    if ( dap_strcmp (a_type_str,"sig_bliss") == 0 ){
        l_sign_type.type = SIG_TYPE_BLISS;
    } else if ( dap_strcmp (a_type_str,"sig_tesla") == 0){
        l_sign_type.type = SIG_TYPE_TESLA;
    } else if ( dap_strcmp (a_type_str,"sig_picnic") == 0){
        l_sign_type.type = SIG_TYPE_PICNIC;
    }else if ( dap_strcmp (a_type_str,"sig_dil") == 0){
        l_sign_type.type = SIG_TYPE_DILITHIUM;
    }else{
        log_it(L_WARNING, "Wrong sign type string \"%s\"", a_type_str ? a_type_str : "(null)");
    }
    return l_sign_type;
}

/**
 * @brief dap_sign_create_output
 * @param a_key
 * @param a_data
 * @param a_data_size
 * @param a_output [in/out]
 * @return
 */
static int dap_sign_create_output(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size,
        void * a_output, size_t *a_output_size)
{
    if(!a_key || !a_key->priv_key_data || !a_key->priv_key_data_size){
        log_it (L_ERROR, "Can't find the private key to create signature");
        return -1;
    }
    switch (a_key->type) {
        case DAP_ENC_KEY_TYPE_SIG_TESLA:
        case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
                // For PICNIC a_output_size should decrease
            *a_output_size = dap_enc_sig_dilithium_get_sign(a_key,a_data,a_data_size,a_output,sizeof(dilithium_signature_t));
             //       a_key->enc_na(a_key, a_data, a_data_size, a_output, *a_output_size);
            return (*a_output_size > 0) ? 0 : -1;


        case DAP_ENC_KEY_TYPE_SIG_BLISS:
            return (dap_enc_sig_bliss_get_sign(a_key, a_data, a_data_size, a_output, *a_output_size) == BLISS_B_NO_ERROR)
                   ? 0 : -1;
        default:
            return -1;
    }
}

/**
 * @brief dap_sign_create
 * @param a_key
 * @param a_data
 * @param a_data_size
 * @param a_output_wish_size
 * @return
 */
dap_sign_t * dap_sign_create(dap_enc_key_t *a_key, const void * a_data,
        const size_t a_data_size, size_t a_output_wish_size)
{
    // calculate max signature size
    size_t l_sign_unserialized_size = dap_sign_create_output_unserialized_calc_size(a_key, a_output_wish_size);
    if(l_sign_unserialized_size > 0) {
        size_t l_pub_key_size = 0;
        uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_key, &l_pub_key_size);
        if(!l_pub_key)
            return NULL;
        uint8_t* l_sign_unserialized = DAP_NEW_Z_SIZE(uint8_t, l_sign_unserialized_size);
        // calc signature [sign_size may decrease slightly]
        if( dap_sign_create_output(a_key, a_data, a_data_size,
                                         l_sign_unserialized, &l_sign_unserialized_size) != 0) {
            dap_enc_key_signature_delete(a_key->type, l_sign_unserialized);
            DAP_DELETE(l_pub_key);
            return NULL;
        } else {
            size_t l_sign_ser_size = l_sign_unserialized_size;
            uint8_t *l_sign_ser = dap_enc_key_serealize_sign(a_key->type, l_sign_unserialized, &l_sign_ser_size);
            if ( l_sign_ser ){
                dap_sign_t * l_ret = DAP_NEW_Z_SIZE(dap_sign_t,
                        sizeof(dap_sign_hdr_t) + l_sign_ser_size + l_pub_key_size);
                // write serialized public key to dap_sign_t
                memcpy(l_ret->pkey_n_sign, l_pub_key, l_pub_key_size);
                l_ret->header.type = dap_sign_type_from_key_type(a_key->type);
                // write serialized signature to dap_sign_t
                memcpy(l_ret->pkey_n_sign + l_pub_key_size, l_sign_ser, l_sign_ser_size);
                l_ret->header.sign_pkey_size =(uint32_t) l_pub_key_size;
                l_ret->header.sign_size = (uint32_t) l_sign_ser_size;
                DAP_DELETE(l_sign_ser);
                dap_enc_key_signature_delete(a_key->type, l_sign_unserialized);
                DAP_DELETE(l_pub_key);
                return l_ret;
            }else {
                log_it(L_WARNING,"Can't serialize signature: NULL returned");
                return NULL;
            }
        }
    }
    return NULL;
}

/**
 * @brief dap_sign_get_sign
 * @param a_sign
 * @param a_sign_out
 * @return
 */
uint8_t* dap_sign_get_sign(dap_sign_t *a_sign, size_t *a_sign_out)
{
    if(!a_sign)
        return NULL;
    if(a_sign_out)
    *a_sign_out = a_sign->header.sign_size;
    return a_sign->pkey_n_sign + a_sign->header.sign_pkey_size;
}

/**
 * @brief dap_sign_get_pkey
 * @param a_sign
 * @param a_pub_key_out
 * @return
 */
uint8_t* dap_sign_get_pkey(dap_sign_t *a_sign, size_t *a_pub_key_out)
{
    if(!a_sign)
        return NULL;
    if(a_pub_key_out)
        *a_pub_key_out = a_sign->header.sign_pkey_size;
    return a_sign->pkey_n_sign;
}

/**
 * @brief dap_sign_get_pkey_hash
 * @param a_sign
 * @param a_sign_hash
 * @return
 */
bool dap_sign_get_pkey_hash(dap_sign_t *a_sign, dap_chain_hash_fast_t * a_sign_hash)
{
    if(!a_sign){
        log_it( L_WARNING, "Sign is NULL on enter");
        return false;
    }
    if( ! a_sign->header.sign_pkey_size ){
        log_it( L_WARNING, "Sign public key's size is 0");
        return false;
    }
    return dap_hash_fast( a_sign->pkey_n_sign,a_sign->header.sign_pkey_size,a_sign_hash );
}


/**
 * @brief dap_sign_to_enc_key
 * @param a_chain_sign
 * @return
 */
dap_enc_key_t *dap_sign_to_enc_key(dap_sign_t * a_chain_sign)
{
    dap_enc_key_t * l_ret =  dap_enc_key_new( dap_sign_type_to_key_type( a_chain_sign->header.type  ) );
    size_t l_pkey_size = 0;
    uint8_t *l_pkey = dap_sign_get_pkey(a_chain_sign, &l_pkey_size);
    // deserialize public key
    dap_enc_key_deserealize_pub_key(l_ret, l_pkey, l_pkey_size);
    return l_ret;
}

/**
 * @brief dap_sign_verify
 * @param a_chain_sign
 * @param a_data
 * @param a_data_size
 * @return 1 valid signature, 0 invalid signature, -1 unsupported sign type
 */
int dap_sign_verify(dap_sign_t * a_chain_sign, const void * a_data, const size_t a_data_size)
{
    int l_ret;
    dap_enc_key_t * l_key = dap_sign_to_enc_key(a_chain_sign);
    size_t l_sign_size = a_chain_sign->header.sign_size;
    size_t l_sign_ser_size;
    uint8_t *l_sign_ser = dap_sign_get_sign(a_chain_sign, &l_sign_ser_size);
    // deserialize signature
    uint8_t * l_sign = dap_enc_key_deserealize_sign(l_key->type, l_sign_ser, &l_sign_size);

    //uint8_t * l_sign = a_chain_sign->pkey_n_sign + a_chain_sign->header.sign_pkey_size;
    switch (l_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        if(l_key->dec_na(l_key, a_data, a_data_size, l_sign, l_sign_size) > 0)
            l_ret = 0;
        else
            l_ret = 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        if(dap_enc_sig_bliss_verify_sign(l_key, a_data, a_data_size, l_sign, l_sign_size) != BLISS_B_NO_ERROR)
            l_ret = 0;
        else
            l_ret = 1;
        break;
    default:
        l_ret = -1;
    }
    dap_enc_key_signature_delete(l_key->type, l_sign);
    dap_enc_key_delete(l_key);
    return l_ret;
}

/**
 * Get size of struct dap_sign_t
 */
size_t dap_sign_get_size(dap_sign_t * a_chain_sign)
{
    if(!a_chain_sign)
        return 0;
    return (sizeof(dap_sign_t) + a_chain_sign->header.sign_size + a_chain_sign->header.sign_pkey_size);
}
