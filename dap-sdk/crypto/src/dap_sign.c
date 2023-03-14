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
#include "dap_strfuncs.h"
#include "dap_hash.h"
#include "dap_sign.h"
#include "dap_enc_base58.h"
#include "dap_enc_bliss.h"
#include "dap_enc_tesla.h"
#include "dap_enc_picnic.h"
#include "dap_enc_dilithium.h"
#include "dap_enc_falcon.h"

#ifdef DAP_PQLR
#include "dap_pqlr_dilithium.h"
#include "dap_pqlr_falcon.h"
#include "dap_pqlr_sphincs.h"
#endif

#include "dap_list.h"

#define LOG_TAG "dap_sign"

//static dap_sign_t * s_sign_null = NULL;
static bliss_signature_t s_sign_bliss_null = {0};
static uint8_t s_sign_hash_type_default = DAP_SIGN_HASH_TYPE_SHA3;

/**
 * @brief get signature size (different for specific crypto algorithm)
 * 
 * @param a_key dap_enc_key_t * encryption key object
 * @param a_output_wish_size size_t output size
 * @return size_t 
 */
size_t dap_sign_create_output_unserialized_calc_size(dap_enc_key_t * a_key, size_t a_output_wish_size)
{
    UNUSED(a_output_wish_size);

    if (!a_key)
        return 0;

    switch (a_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        return sizeof(s_sign_bliss_null);
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
        return dap_enc_picnic_calc_signature_size(a_key);
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
        return dap_enc_tesla_calc_signature_size();
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
        return dap_enc_dilithium_calc_signature_unserialized_size();
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
        return dap_enc_falcon_calc_signature_unserialized_size(a_key);
#ifdef DAP_PQLR
    case DAP_ENC_KEY_TYPE_PQLR_SIG_DILITHIUM:
        return dap_pqlr_dilithium_calc_signature_size(a_key);
    case DAP_ENC_KEY_TYPE_PQLR_SIG_FALCON:
        return dap_pqlr_falcon_calc_signature_size(a_key);
    case DAP_ENC_KEY_TYPE_PQLR_SIG_SPHINCS:
        return dap_pqlr_sphincs_calc_signature_size(a_key);

#endif
    default:
        return 0;
    }
}


/**
 * @brief get sign type (dap_sign_type_t) type from key type (dap_enc_key_type_t)
 * @param a_key_type dap_enc_key_type_t key type
 * @return
 */
dap_sign_type_t dap_sign_type_from_key_type( dap_enc_key_type_t a_key_type)
{
    switch (a_key_type) {
    case DAP_ENC_KEY_TYPE_SIG_BLISS:    return (dap_sign_type_t){ .type = SIG_TYPE_BLISS };
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:   return (dap_sign_type_t){ .type = SIG_TYPE_PICNIC };
    case DAP_ENC_KEY_TYPE_SIG_TESLA:    return (dap_sign_type_t){ .type = SIG_TYPE_TESLA };
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:return (dap_sign_type_t){ .type = SIG_TYPE_DILITHIUM };
    case DAP_ENC_KEY_TYPE_SIG_FALCON:   return (dap_sign_type_t){ .type = SIG_TYPE_FALCON };
#ifdef DAP_PQLR
    case DAP_ENC_KEY_TYPE_PQLR_SIG_DILITHIUM:   return (dap_sign_type_t){ .type = SIG_TYPE_PQLR_DILITHIUM };
    case DAP_ENC_KEY_TYPE_PQLR_SIG_FALCON:      return (dap_sign_type_t){ .type = SIG_TYPE_PQLR_FALCON };
    case DAP_ENC_KEY_TYPE_PQLR_SIG_SPHINCS:     return (dap_sign_type_t){ .type = SIG_TYPE_PQLR_SPHINCS };

#endif
    default: return (dap_sign_type_t){ .raw = 0 };
    }
}

/**
 * @brief convert chain sign type (dap_sign_type_t) to encryption key type (dap_enc_key_type_t)
 * @param a_chain_sign_type dap_enc_key_type_t signature type
 * @return dap_enc_key_type_t
 */
dap_enc_key_type_t  dap_sign_type_to_key_type(dap_sign_type_t  a_chain_sign_type)
{
    switch (a_chain_sign_type.type) {
    case SIG_TYPE_BLISS:    return DAP_ENC_KEY_TYPE_SIG_BLISS;
    case SIG_TYPE_TESLA:    return DAP_ENC_KEY_TYPE_SIG_TESLA;
    case SIG_TYPE_PICNIC:   return DAP_ENC_KEY_TYPE_SIG_PICNIC;
    case SIG_TYPE_DILITHIUM:return DAP_ENC_KEY_TYPE_SIG_DILITHIUM;
    case SIG_TYPE_FALCON:   return DAP_ENC_KEY_TYPE_SIG_FALCON;
#ifdef DAP_PQLR
    case SIG_TYPE_PQLR_DILITHIUM:   return DAP_ENC_KEY_TYPE_PQLR_SIG_DILITHIUM;
    case SIG_TYPE_PQLR_FALCON:      return DAP_ENC_KEY_TYPE_PQLR_SIG_FALCON;
    case SIG_TYPE_PQLR_SPHINCS:     return DAP_ENC_KEY_TYPE_PQLR_SIG_SPHINCS;
#endif
    default: return DAP_ENC_KEY_TYPE_INVALID;
    }
}



/**
 * @brief convert sign type (dap_sign_type_t) to string format
 * [sig_bliss,sig_tesla,sig_picnic,sig_dil,sig_multi2,sig_multi]
 * @param a_chain_sign_type sign type dap_sign_type_t
 * @return const char* 
 */
const char * dap_sign_type_to_str(dap_sign_type_t a_chain_sign_type)
{
    switch (a_chain_sign_type.type) {
    case SIG_TYPE_BLISS:    return "sig_bliss";
    case SIG_TYPE_TESLA:    return "sig_tesla";
    case SIG_TYPE_PICNIC:   return "sig_picnic";
    case SIG_TYPE_DILITHIUM:return "sig_dil";
    case SIG_TYPE_FALCON:   return "sig_falcon";
    case SIG_TYPE_MULTI_COMBINED:   return "sig_multi2";
    case SIG_TYPE_MULTI_CHAINED:    return "sig_multi";
#ifdef DAP_PQLR
    case SIG_TYPE_PQLR_DILITHIUM:   return "sig_pqlr_dil";
    case SIG_TYPE_PQLR_FALCON:      return "sig_pqlr_falcon";
    case SIG_TYPE_PQLR_SPHINCS:     return "sig_pqrl_sphincs";
#endif
    default: return "UNDEFINED";
    }

}

/**
 * @brief convert public key type (dap_pkey_type_t) to dap_sign_type_t type
 * 
 * @param a_pkey_type dap_pkey_type_t key type
 * @return dap_sign_type_t 
 */
dap_sign_type_t dap_sign_type_from_pkey_type( dap_pkey_type_t a_pkey_type)
{
    switch (a_pkey_type.type){
    case PKEY_TYPE_SIGN_BLISS:  return (dap_sign_type_t){ .type = SIG_TYPE_BLISS };
    case PKEY_TYPE_SIGN_PICNIC: return (dap_sign_type_t){ .type = SIG_TYPE_PICNIC };
    case PKEY_TYPE_SIGN_TESLA:  return (dap_sign_type_t){ .type = SIG_TYPE_TESLA };
    case PKEY_TYPE_SIGN_DILITHIUM: return (dap_sign_type_t){ .type =  SIG_TYPE_DILITHIUM };
    case PKEY_TYPE_MULTI: return (dap_sign_type_t){ .type = SIG_TYPE_MULTI_CHAINED };
    case PKEY_TYPE_NULL: return (dap_sign_type_t){ .type = SIG_TYPE_NULL };
#ifdef DAP_PQLR
    case PKEY_TYPE_SIGN_PQLR_DIL: return (dap_sign_type_t){ .type =  SIG_TYPE_PQLR_DILITHIUM };
    case PKEY_TYPE_SIGN_PQLR_FALCON: return (dap_sign_type_t){ .type =  SIG_TYPE_PQLR_FALCON };
    case PKEY_TYPE_SIGN_PQLR_SPHINCS: return (dap_sign_type_t){ .type =  SIG_TYPE_PQLR_SPHINCS };
#endif
    default: return (dap_sign_type_t){ .raw = 0 };
    }
}


/**
 * @brief convert string to dap_sign_type_t type
 * 
 * @param a_type_str const char * algorithm type [sig_bliss,sig_tesla,sig_picnic,sig_dil,sig_multi2,sig_multi]
 * @return dap_sign_type_t 
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
    } else if (dap_strcmp(a_type_str, "sig_falcon") == 0) {
        l_sign_type.type = SIG_TYPE_FALCON;
#ifdef DAP_PQLR
    } else if (dap_strcmp(a_type_str, "sig_pqlr_dil") == 0) {
        l_sign_type.type = SIG_TYPE_PQLR_DILITHIUM;
    } else if (dap_strcmp(a_type_str, "sig_pqlr_falcon") == 0) {
        l_sign_type.type = SIG_TYPE_PQLR_FALCON;
    } else if (dap_strcmp(a_type_str, "sig_pqlr_sphincs") == 0) {
        l_sign_type.type = SIG_TYPE_PQLR_SPHINCS;
#endif
    }else if ( dap_strcmp (a_type_str,"sig_multi") == 0){
        l_sign_type.type = SIG_TYPE_MULTI_CHAINED;
    }else if ( dap_strcmp (a_type_str,"sig_multi2") == 0){
        l_sign_type.type = SIG_TYPE_MULTI_COMBINED;
    }else{
        log_it(L_WARNING, "Wrong sign type string \"%s\"", a_type_str ? a_type_str : "(null)");
    }
    return l_sign_type;
}

/**
 * @brief encrypt data
 * call a_key->enc_na or dap_enc_sig_bliss_get_sign
 * @param a_key dap_enc_key_t key object
 * @param a_data const void * data
 * @param a_data_size const size_t size of data
 * @param a_output void * output buffer
 * @param a_output_size size_t size of output buffer
 * @return int 
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
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
#ifdef DAP_PQLR
    case DAP_ENC_KEY_TYPE_PQLR_SIG_DILITHIUM:
    case DAP_ENC_KEY_TYPE_PQLR_SIG_FALCON:
    case DAP_ENC_KEY_TYPE_PQLR_SIG_SPHINCS:
#endif
            // For PICNIC a_output_size should decrease
        //*a_output_size = dap_enc_sig_dilithium_get_sign(a_key,a_data,a_data_size,a_output,sizeof(dilithium_signature_t));
        a_key->enc_na(a_key, a_data, a_data_size, a_output, *a_output_size);
        return (*a_output_size > 0) ? 0 : -1;
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        return (dap_enc_sig_bliss_get_sign(a_key, a_data, a_data_size, a_output, *a_output_size) == BLISS_B_NO_ERROR)
               ? 0 : -1;
    default:
        return -1;
    }
}

/**
 * @brief sign data with specified key
 * 
 * @param a_key dap_enc_key_t key object
 * @param a_data const void * buffer with data
 * @param a_data_size const size_t buffer size
 * @param a_output_wish_size size_t output buffer size
 * @return dap_sign_t* 
 */
dap_sign_t * dap_sign_create(dap_enc_key_t *a_key, const void * a_data,
        const size_t a_data_size, size_t a_output_wish_size)
{
    const void * l_sign_data;
    size_t l_sign_data_size;

    dap_chain_hash_fast_t l_sign_data_hash;

    if(s_sign_hash_type_default == DAP_SIGN_HASH_TYPE_NONE){
        l_sign_data = a_data;
        l_sign_data_size = a_data_size;
    }else{
        l_sign_data = &l_sign_data_hash;
        l_sign_data_size = sizeof(l_sign_data_hash);
        switch(s_sign_hash_type_default){
            case DAP_SIGN_HASH_TYPE_SHA3: dap_hash_fast(a_data,a_data_size,&l_sign_data_hash); break;
            default: log_it(L_CRITICAL, "We can't hash with hash type 0x%02x",s_sign_hash_type_default);
        }
    }

    // calculate max signature size
    size_t l_sign_unserialized_size = dap_sign_create_output_unserialized_calc_size(a_key, a_output_wish_size);
    if(l_sign_unserialized_size > 0) {
        size_t l_pub_key_size = 0;
        uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(a_key, &l_pub_key_size);
        if(!l_pub_key)
            return NULL;
        uint8_t* l_sign_unserialized = DAP_NEW_Z_SIZE(uint8_t, l_sign_unserialized_size);
        // calc signature [sign_size may decrease slightly]
        if( dap_sign_create_output(a_key, l_sign_data, l_sign_data_size,
                                         l_sign_unserialized, &l_sign_unserialized_size) != 0) {
            dap_enc_key_signature_delete(a_key->type, l_sign_unserialized);
            DAP_DELETE(l_pub_key);
            return NULL;
        } else {
            size_t l_sign_ser_size = l_sign_unserialized_size;
            uint8_t *l_sign_ser = dap_enc_key_serialize_sign(a_key->type, l_sign_unserialized, &l_sign_ser_size);
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
                l_ret->header.hash_type = s_sign_hash_type_default;
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
 * @brief create signed object header (dap_sign_t) from variables
 * 
 * @param a_key dap_enc_key_t key object
 * @param a_sign_ser signed data buffer
 * @param a_sign_ser_size buffer size
 * @param a_pkey public key
 * @param a_pub_key_size public key size
 * @return dap_sign_t* 
 */
dap_sign_t * dap_sign_pack(dap_enc_key_t *a_key, const void * a_sign_ser, const size_t a_sign_ser_size, const void * a_pkey, const size_t a_pub_key_size)
{
    dap_sign_t * l_ret = DAP_NEW_Z_SIZE(dap_sign_t, sizeof(dap_sign_hdr_t) + a_sign_ser_size + a_pub_key_size);
    // write serialized public key to dap_sign_t
    memcpy(l_ret->pkey_n_sign, a_pkey, a_pub_key_size);
    l_ret->header.type = dap_sign_type_from_key_type(a_key->type);
    // write serialized signature to dap_sign_t
    memcpy(l_ret->pkey_n_sign + a_pub_key_size, a_sign_ser, a_sign_ser_size);
    l_ret->header.sign_pkey_size = (uint32_t) a_pub_key_size;
    l_ret->header.sign_size = (uint32_t) a_sign_ser_size;
    return l_ret;
}

/**
 * @brief 
 * get a_sign->pkey_n_sign + a_sign->header.sign_pkey_size
 * @param a_sign dap_sign_t object (header + raw signature data)
 * @param a_sign_out  a_sign->header.sign_size
 * @return uint8_t* 
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
 * @brief get a_sign->pkey_n_sign and a_sign->header.sign_pkey_size (optionally)
 * 
 * @param a_sign dap_sign_t sign object
 * @param a_pub_key_out [option] output pointer to a_sign->header.sign_pkey_size
 * @return uint8_t* 
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
 * @brief get SHA3 hash of buffer (a_sign), storing in output buffer a_sign_hash
 * 
 * @param a_sign input buffer
 * @param a_sign_hash output buffer
 * @return true 
 * @return false 
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
 * @brief Compare two sign
 *
 * @param l_sign1
 * @param l_sign2
 * @return true or false
 */
bool dap_sign_match_pkey_signs(dap_sign_t *l_sign1, dap_sign_t *l_sign2)
{
    dap_chain_hash_fast_t l_hash_pkey;
    size_t l_pkey_ser_size1 = 0, l_pkey_ser_size2 = 0;
    // Get public key from sign
    const uint8_t *l_pkey_ser1 = dap_sign_get_pkey(l_sign1, &l_pkey_ser_size1);
    const uint8_t *l_pkey_ser2 = dap_sign_get_pkey(l_sign2, &l_pkey_ser_size2);
    if(l_pkey_ser_size1 == l_pkey_ser_size2) {
        if(!memcmp(l_pkey_ser1, l_pkey_ser2, l_pkey_ser_size1))
            return true;
    }
    return false;
}

dap_pkey_t *dap_sign_get_pkey_deserialization(dap_sign_t *a_sign){
    dap_pkey_t *l_pkey = DAP_NEW_SIZE(dap_pkey_t, sizeof(dap_pkey_t) + a_sign->header.sign_pkey_size);
    l_pkey->header.size = a_sign->header.sign_pkey_size;
    l_pkey->header.type = dap_pkey_type_from_sign_type(a_sign->header.type);
    memcpy(l_pkey->pkey, a_sign->pkey_n_sign, l_pkey->header.size);
    return l_pkey;
}

/**
 * @brief verify, if a_sign->header.sign_pkey_size and a_sign->header.sign_size bigger, then a_max_key_size
 * 
 * @param a_sign signed data object 
 * @param a_max_sign_size max size of signature
 * @return true 
 * @return false 
 */
bool dap_sign_verify_size(dap_sign_t *a_sign, size_t a_max_sign_size) {
    return (a_sign->header.sign_size) && (a_sign->header.sign_pkey_size) && (a_sign->header.type.type != SIG_TYPE_NULL)
        && (a_sign->header.sign_size + a_sign->header.sign_pkey_size + sizeof(*a_sign) <= a_max_sign_size);
}

/**
 * @brief get deserialized pub key from dap_sign_t
 * 
 * @param a_chain_sign dap_sign_t object
 * @return dap_enc_key_t* 
 */
dap_enc_key_t *dap_sign_to_enc_key(dap_sign_t * a_chain_sign)
{
    dap_enc_key_type_t l_type = dap_sign_type_to_key_type(a_chain_sign->header.type);
    if (l_type == DAP_ENC_KEY_TYPE_INVALID)
        return NULL;
    size_t l_pkey_size = 0;
    uint8_t *l_pkey = dap_sign_get_pkey(a_chain_sign, &l_pkey_size);
    dap_enc_key_t * l_ret =  dap_enc_key_new(l_type);
    // deserialize public key
    dap_enc_key_deserialize_pub_key(l_ret, l_pkey, l_pkey_size);
    return l_ret;
}

/**
 * @brief dap_sign_verify data signature
 * @param a_chain_sign dap_sign_t a_chain_sign object
 * @param a_data const void * buffer with data
 * @param a_data_size const size_t  buffer size
 * @return 1 valid signature, 0 invalid signature, -1 unsupported sign type
 */
int dap_sign_verify(dap_sign_t * a_chain_sign, const void * a_data, const size_t a_data_size)
{
    if (!a_chain_sign || !a_data)
        return -2;

    dap_enc_key_t * l_key = dap_sign_to_enc_key(a_chain_sign);
    if ( ! l_key ){
        log_it(L_WARNING,"Incorrect signature, can't extract key");
        return -3;
    }
    size_t l_sign_data_ser_size;
    uint8_t *l_sign_data_ser = dap_sign_get_sign(a_chain_sign, &l_sign_data_ser_size);

    if ( ! l_sign_data_ser ){
        dap_enc_key_delete(l_key);
        log_it(L_WARNING,"Incorrect signature, can't extract serialized signature's data ");
        return -4;
    }

    size_t l_sign_data_size = a_chain_sign->header.sign_size;
    // deserialize signature
    uint8_t * l_sign_data = dap_enc_key_deserialize_sign(l_key->type, l_sign_data_ser, &l_sign_data_size);

    if ( ! l_sign_data ){
        log_it(L_WARNING,"Incorrect signature, can't deserialize signature's data");
        dap_enc_key_delete(l_key);
        return -5;
    }

    int l_ret;
    //uint8_t * l_sign = a_chain_sign->pkey_n_sign + a_chain_sign->header.sign_pkey_size;
    const void * l_verify_data;
    size_t l_verify_data_size;
    dap_chain_hash_fast_t l_verify_data_hash;

    if(a_chain_sign->header.hash_type == DAP_SIGN_HASH_TYPE_NONE){
        l_verify_data = a_data;
        l_verify_data_size = a_data_size;
    }else{
        l_verify_data = &l_verify_data_hash;
        l_verify_data_size = sizeof(l_verify_data_hash);
        switch(s_sign_hash_type_default){
            case DAP_SIGN_HASH_TYPE_SHA3: dap_hash_fast(a_data,a_data_size,&l_verify_data_hash); break;
            default: log_it(L_CRITICAL, "Incorrect signature: we can't check hash with hash type 0x%02x",s_sign_hash_type_default);
            return -5;
        }
    }

    switch (l_key->type) {
    case DAP_ENC_KEY_TYPE_SIG_TESLA:
    case DAP_ENC_KEY_TYPE_SIG_PICNIC:
    case DAP_ENC_KEY_TYPE_SIG_DILITHIUM:
    case DAP_ENC_KEY_TYPE_SIG_FALCON:
#ifdef DAP_PQLR
    case DAP_ENC_KEY_TYPE_PQLR_SIG_DILITHIUM:
    case DAP_ENC_KEY_TYPE_PQLR_SIG_FALCON:
    case DAP_ENC_KEY_TYPE_PQLR_SIG_SPHINCS:
#endif
        l_ret = l_key->dec_na(l_key, l_verify_data, l_verify_data_size, l_sign_data, l_sign_data_size) < 0
                ? 0 : 1;
        break;
    case DAP_ENC_KEY_TYPE_SIG_BLISS:
        l_ret = dap_enc_sig_bliss_verify_sign(l_key, l_verify_data, l_verify_data_size, l_sign_data, l_sign_data_size) != BLISS_B_NO_ERROR
                ? 0 : 1;
        break;
    default:
        l_ret = -6;
        break;
    }
    dap_enc_key_signature_delete(l_key->type, l_sign_data);
    dap_enc_key_delete(l_key);
    return l_ret;
}


/**
 * @brief Get size of struct dap_sign_t
 * 
 * @param a_chain_sign dap_sign_t object
 * @return size_t 
 */
size_t dap_sign_get_size(dap_sign_t * a_chain_sign)
{
    if(!a_chain_sign || a_chain_sign->header.type.type == SIG_TYPE_NULL)
        return 0;
    return (sizeof(dap_sign_t) + a_chain_sign->header.sign_size + a_chain_sign->header.sign_pkey_size);
}


dap_sign_t **dap_sign_get_unique_signs(void *a_data, size_t a_data_size, size_t *a_signs_count)
{
    size_t l_offset = 0;
    dap_list_t *l_list_signs = NULL;
    while (l_offset < a_data_size) {
        dap_sign_t *l_sign = (dap_sign_t *)(a_data+l_offset);
        size_t l_sign_size = dap_sign_get_size(l_sign);
        if (!l_sign_size){
            break;
        }
        if (l_sign_size > a_data_size-l_offset ){
            break;
        }
        // Check duplicate signs
        bool l_sign_duplicate = false;
        if (l_list_signs) {
            dap_list_t *l_list = dap_list_first(l_list_signs);
            while (l_list) {
                if ( memcmp( ((dap_sign_t *)l_list->data)->pkey_n_sign,
                            l_sign->pkey_n_sign, l_sign->header.sign_pkey_size ) == 0 ) {
                    l_sign_duplicate = true;
                    break;
                }
                l_list = l_list->next;
            }
        }
        if (!l_sign_duplicate) {
            l_list_signs = dap_list_append(l_list_signs, l_sign);
        }
        l_offset += l_sign_size;
    }
    unsigned int l_list_length = dap_list_length(l_list_signs);
    *a_signs_count = (size_t)l_list_length;
    dap_sign_t **l_ret = DAP_NEW_Z_SIZE(dap_sign_t *, sizeof(dap_sign_t *)*l_list_length);
    unsigned int i = 0;
    dap_list_t *l_list = dap_list_first(l_list_signs);
    while(l_list) {
        l_ret[i] = l_list->data;
        i++;
        l_list = l_list->next;
    }
    dap_list_free(l_list_signs);
    return l_ret;
}


/**
 * @brief dap_multi_sign_calc_size Auxiliary function to calculate multi-signature strucrutre size
 * @param a_sign The multi-signature
 * @return Multi-signature size
 */
size_t dap_multi_sign_calc_size(dap_multi_sign_t *a_sign)
{
    if (!a_sign)
        return 0;
    size_t l_meta_data_size = sizeof(dap_sign_type_t) + 2 * sizeof(uint8_t) +
            a_sign->sign_count * (sizeof(dap_multi_sign_keys_t) + sizeof(dap_multi_sign_meta_t));
    size_t l_pkeys_hashes_size = a_sign->total_count * sizeof(dap_chain_hash_fast_t);
    size_t l_pkeys_size = 0, l_signes_size = 0;
    for (int i = 0; i < a_sign->sign_count; i++) {
        l_pkeys_size += a_sign->meta[i].pkey_size;
        l_signes_size += a_sign->meta[i].sign_size;
    }
    return l_meta_data_size + l_pkeys_hashes_size + l_pkeys_size + l_signes_size;
}

/**
 * @brief dap_multi_sign_serialize Makes a serialization for multi-signature structure
 * @param a_sign Pointer to multi-signature
 * @param a_out_len OUT Output data lenght
 * @return Pointer to serialized data
 */
uint8_t *dap_multi_sign_serialize(dap_multi_sign_t *a_sign, size_t *a_out_len)
{
    if (a_sign->type.type != SIG_TYPE_MULTI_CHAINED) {
        log_it(L_ERROR, "Unsupported multi-signature type");
        return NULL;
    }
    *a_out_len = dap_multi_sign_calc_size(a_sign) + sizeof(size_t);
    uint8_t *l_ret = DAP_NEW_SIZE(uint8_t, *a_out_len);
    size_t l_mem_shift = 0;
    memcpy(l_ret, a_out_len, sizeof(size_t));
    l_mem_shift += sizeof(size_t);
    memcpy(&l_ret[l_mem_shift], &a_sign->type, sizeof(dap_sign_type_t));
    l_mem_shift += sizeof(dap_sign_type_t);
    memcpy(&l_ret[l_mem_shift], &a_sign->total_count, 1);
    l_mem_shift++;
    memcpy(&l_ret[l_mem_shift], &a_sign->sign_count, 1);
    l_mem_shift++;
    for (int i = 0; i < a_sign->sign_count; i++) {
        memcpy(&l_ret[l_mem_shift], &a_sign->key_seq[i].num, 1);
        l_mem_shift++;
        memcpy(&l_ret[l_mem_shift], &a_sign->key_seq[i].type, sizeof(dap_sign_type_t));
        l_mem_shift += sizeof(dap_sign_type_t);
    }
    for (int i = 0; i < a_sign->sign_count; i++) {
        memcpy(&l_ret[l_mem_shift], &a_sign->meta[i].pkey_size, sizeof(uint32_t));
        l_mem_shift += sizeof(uint32_t);
        memcpy(&l_ret[l_mem_shift], &a_sign->meta[i].sign_size, sizeof(uint32_t));
        l_mem_shift += sizeof(uint32_t);
    }
    for (int i = 0; i < a_sign->total_count; i++) {
        memcpy(&l_ret[l_mem_shift], &a_sign->key_hashes[i], sizeof(dap_chain_hash_fast_t));
        l_mem_shift += sizeof(dap_chain_hash_fast_t);
    }
    uint32_t l_data_shift = 0, l_data_size = 0;
    for (int i = 0; i < a_sign->sign_count; i++) {
        l_data_size = a_sign->meta[i].pkey_size;
        memcpy(&l_ret[l_mem_shift], &a_sign->pub_keys[l_data_shift], l_data_size);
        l_mem_shift += l_data_size;
        l_data_shift += l_data_size;
    }
    l_data_shift = l_data_size = 0;
    for (int i = 0; i < a_sign->sign_count; i++) {
        l_data_size = a_sign->meta[i].sign_size;
        memcpy(&l_ret[l_mem_shift], &a_sign->sign_data[l_data_shift], l_data_size);
        l_mem_shift += l_data_size;
        l_data_shift += l_data_size;
    }
    return l_ret;
}

/**
 * @brief dap_multi_sign_deserialize Makes a deserialization for multi-signature structure
 * @param a_sign Pointer to serialized data
 * @param a_sign_len Input data lenght
 * @return Pointer to multi-signature
 */
dap_multi_sign_t *dap_multi_sign_deserialize(dap_sign_type_enum_t a_type, uint8_t *a_sign, size_t a_sign_len)
{
    if (a_type != SIG_TYPE_MULTI_CHAINED) {
        log_it(L_ERROR, "Unsupported multi-signature type");
        return NULL;
    }
    size_t l_sign_len = *(size_t *)a_sign;
    if (l_sign_len != a_sign_len) {
        return NULL;
    }
    dap_multi_sign_t *l_sign = DAP_NEW(dap_multi_sign_t);
    size_t l_mem_shift = sizeof(size_t);
    memcpy(&l_sign->type, &a_sign[l_mem_shift], sizeof(dap_sign_type_t));
    l_mem_shift += sizeof(dap_sign_type_t);
    memcpy(&l_sign->total_count, &a_sign[l_mem_shift], 1);
    l_mem_shift++;
    memcpy(&l_sign->sign_count, &a_sign[l_mem_shift], 1);
    l_mem_shift++;
    if(l_sign->sign_count)
        l_sign->key_seq = DAP_NEW_Z_SIZE(dap_multi_sign_keys_t, l_sign->sign_count * sizeof(dap_multi_sign_keys_t));
    for (int i = 0; i < l_sign->sign_count; i++) {
        memcpy(&l_sign->key_seq[i].num, &a_sign[l_mem_shift], 1);
        l_mem_shift++;
        memcpy(&l_sign->key_seq[i].type, &a_sign[l_mem_shift], sizeof(dap_sign_type_t));
        l_mem_shift += sizeof(dap_sign_type_t);
    }
    size_t l_pkeys_size = 0, l_signes_size = 0;
    if(l_sign->sign_count){
        l_sign->meta = DAP_NEW_Z_SIZE(dap_multi_sign_meta_t, l_sign->sign_count * sizeof(dap_multi_sign_meta_t));
        for (int i = 0; i < l_sign->sign_count; i++) {
            memcpy(&l_sign->meta[i].pkey_size, &a_sign[l_mem_shift], sizeof(uint32_t));
            l_mem_shift += sizeof(uint32_t);
            l_pkeys_size += l_sign->meta[i].pkey_size;
            memcpy(&l_sign->meta[i].sign_size, &a_sign[l_mem_shift], sizeof(uint32_t));
            l_mem_shift += sizeof(uint32_t);
            l_signes_size += l_sign->meta[i].sign_size;
        }
    }
    if(l_sign->total_count){
        l_sign->key_hashes = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, l_sign->total_count * sizeof(dap_chain_hash_fast_t));
        for (int i = 0; i < l_sign->total_count; i++) {
            memcpy(&l_sign->key_hashes[i], &a_sign[l_mem_shift], sizeof(dap_chain_hash_fast_t));
            l_mem_shift += sizeof(dap_chain_hash_fast_t);
        }
    }
    uint32_t l_data_shift = 0, l_data_size = 0;
    if(l_pkeys_size){
        l_sign->pub_keys = DAP_NEW_Z_SIZE(uint8_t, l_pkeys_size);
        for (int i = 0; i < l_sign->sign_count; i++) {
            l_data_size = l_sign->meta[i].pkey_size;
            memcpy( &l_sign->pub_keys[l_data_shift], &a_sign[l_mem_shift],l_data_size);
            l_mem_shift += l_data_size;
            l_data_shift += l_data_size;
        }
        l_data_shift = l_data_size = 0;
    }
    if(l_signes_size){
        l_sign->sign_data = DAP_NEW_Z_SIZE(uint8_t, l_signes_size);
        for (int i = 0; i < l_sign->sign_count; i++) {
            l_data_size = l_sign->meta[i].sign_size;
            memcpy(&l_sign->sign_data[l_data_shift], &a_sign[l_mem_shift], l_data_size);
            l_mem_shift += l_data_size;
            l_data_shift += l_data_size;
        }
    }
    return l_sign;
}

/**
 * @brief dap_multi_sign_params_make Auxiliary function which helps fill multi-signature params structure
 * @param a_type Type of multi-signature
 * @param a_total_count Number of total key count
 * @param a_sign_count Number of keys participating in multi-signing algorithm
 * @param a_key[1 .. total_count] Set of keys
 * @param a_num[1 .. sign_count] Signing keys sequence
 * @return Pointer to multi-signature params structure
 */
dap_multi_sign_params_t *dap_multi_sign_params_make(dap_sign_type_enum_t a_type, uint8_t a_total_count, uint8_t a_sign_count, dap_enc_key_t *a_key1, ...)
{
    dap_multi_sign_params_t *l_params = DAP_NEW(dap_multi_sign_params_t);
    l_params->type.type = a_type;
    l_params->total_count = a_total_count;
    l_params->keys = DAP_NEW_SIZE(dap_enc_key_t *, a_total_count * sizeof(dap_enc_key_t *));
    l_params->sign_count = a_sign_count;
    l_params->key_seq = DAP_NEW_SIZE(uint8_t, a_sign_count);
    l_params->keys[0] = a_key1;
    va_list list;
    va_start(list, a_key1);
    for (int i = 1; i < a_total_count; i++) {
        l_params->keys[i] = va_arg(list, dap_enc_key_t *);
    }
    for (int i = 0; i < a_sign_count; i++) {
        l_params->key_seq[i] = va_arg(list, int) - 1;
    }
    va_end(list);
    return l_params;
}

/**
 * @brief dap_multi_sign_delete Destroy multi-signature params structure
 * @param a_sign Pointer to multi-signature params structure to destroy
 * @return None
 */
void dap_multi_sign_params_delete(dap_multi_sign_params_t *a_params)
{
    if (!a_params)
        return;
    if (a_params->key_seq) {
        DAP_DELETE(a_params->key_seq);
    }
    if (a_params->keys) {
        DAP_DELETE(a_params->keys);
    }
    DAP_DELETE(a_params);
}

/**
 * @brief dap_multi_sign_hash_data Make multi-signature hash for specified message
 * @param a_sign Pointer to multi-signature structure
 * @param a_data Pointer to message to be signed with this multi-signature
 * @param a_data_size Message size
 * @param a_hash OUT Pointer to calculated hash
 * @return True if success, overwise return false
 */
bool dap_multi_sign_hash_data(dap_multi_sign_t *a_sign, const void *a_data, const size_t a_data_size, dap_chain_hash_fast_t *a_hash)
{
    //types missunderstanding?
    uint8_t *l_concatenated_hash = DAP_NEW_SIZE(uint8_t, 3 * sizeof(dap_chain_hash_fast_t));
    if (!dap_hash_fast(a_data, a_data_size, a_hash)) {
        DAP_DELETE(l_concatenated_hash);
        return false;
    }
    memcpy(l_concatenated_hash, a_hash, sizeof(dap_chain_hash_fast_t));
    uint32_t l_meta_data_size = sizeof(dap_sign_type_t) + 2 * sizeof(uint8_t) + a_sign->sign_count * sizeof(dap_multi_sign_keys_t);
    uint8_t *l_meta_data = DAP_NEW_SIZE(uint8_t, l_meta_data_size);
    int l_meta_data_mem_shift = 0;
    memcpy(l_meta_data, &a_sign->type, sizeof(dap_sign_type_t));
    l_meta_data_mem_shift += sizeof(dap_sign_type_t);
    l_meta_data[l_meta_data_mem_shift++] = a_sign->total_count;
    l_meta_data[l_meta_data_mem_shift++] = a_sign->sign_count;
    memcpy(&l_meta_data[l_meta_data_mem_shift], a_sign->key_seq, a_sign->sign_count * sizeof(dap_multi_sign_keys_t));
    if (!dap_hash_fast(l_meta_data, l_meta_data_size, a_hash)) {
        DAP_DELETE(l_meta_data);
        DAP_DELETE(l_concatenated_hash);
        return false;
    }
    DAP_DELETE(l_meta_data);
    memcpy(l_concatenated_hash + sizeof(dap_chain_hash_fast_t), a_hash, sizeof(dap_chain_hash_fast_t));
    if (!dap_hash_fast(a_sign->key_hashes, a_sign->total_count * sizeof(dap_chain_hash_fast_t), a_hash)) {
        DAP_DELETE(l_concatenated_hash);
        return false;
    }
    memcpy(l_concatenated_hash + 2 * sizeof(dap_chain_hash_fast_t), a_hash, sizeof(dap_chain_hash_fast_t));
    if (!dap_hash_fast(l_concatenated_hash, 3 * sizeof(dap_chain_hash_fast_t), a_hash)) {
        DAP_DELETE(l_concatenated_hash);
        return false;
    }
    DAP_DELETE(l_concatenated_hash);
    return true;
}

/**
 * @brief dap_multi_sign_create Make multi-signature for specified message
 * @param a_params Pointer to multi-signature params structure
 * @param a_data Pointer to message to be signed with this multi-signature
 * @param a_data_size Message size
 * @return Pointer to multi-signature structure for specified message
 */
dap_multi_sign_t *dap_multi_sign_create(dap_multi_sign_params_t *a_params, const void *a_data, const size_t a_data_size)
{
    if (a_params->type.type != SIG_TYPE_MULTI_CHAINED) {
        log_it (L_ERROR, "Unsupported multi-signature type");
        return NULL;
    }
    if (!a_params || !a_params->total_count) {
        log_it (L_ERROR, "Wrong parameters of multi-signature");
        return NULL;
    }
    dap_multi_sign_t *l_sign = DAP_NEW_Z(dap_multi_sign_t);
    l_sign->type = a_params->type;
    l_sign->total_count = a_params->total_count;
    l_sign->key_hashes = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, a_params->total_count * sizeof(dap_chain_hash_fast_t));
    for (int i = 0; i < a_params->total_count; i++) {
        if (!dap_hash_fast(a_params->keys[i]->pub_key_data, a_params->keys[i]->pub_key_data_size, &l_sign->key_hashes[i])) {
            log_it (L_ERROR, "Can't create multi-signature hash");
            dap_multi_sign_delete(l_sign);
            return NULL;
        }
    }
    l_sign->sign_count = a_params->sign_count;
    l_sign->key_seq = DAP_NEW_Z_SIZE(dap_multi_sign_keys_t, a_params->sign_count * sizeof(dap_multi_sign_keys_t));
    l_sign->meta = DAP_NEW_Z_SIZE(dap_multi_sign_meta_t, a_params->sign_count * sizeof(dap_multi_sign_meta_t));
    for (int i = 0; i < l_sign->sign_count; i++) {
        uint8_t l_num = a_params->key_seq[i];
        l_sign->key_seq[i].num = l_num;
        l_sign->key_seq[i].type = dap_sign_type_from_key_type(a_params->keys[l_num]->type);
    }
    uint32_t l_pkeys_mem_shift = 0, l_signs_mem_shift = 0;
    size_t l_pkey_size, l_sign_size;
    dap_chain_hash_fast_t l_data_hash;
    bool l_hashed;
    for (int i = 0; i < l_sign->sign_count; i++) {
        if (i == 0) {
             l_hashed = dap_multi_sign_hash_data(l_sign, a_data, a_data_size, &l_data_hash);
        } else {
             l_hashed = dap_hash_fast(&l_sign->sign_data[l_signs_mem_shift], l_sign_size, &l_data_hash);
             l_signs_mem_shift += l_sign_size;
        }
        if (!l_hashed) {
            log_it (L_ERROR, "Can't create multi-signature hash");
            dap_multi_sign_delete(l_sign);
            return NULL;
        }
        int l_num = l_sign->key_seq[i].num;
        dap_sign_t *l_dap_sign_step = dap_sign_create(a_params->keys[l_num], &l_data_hash, sizeof(dap_chain_hash_fast_t), 0);
        if (!l_dap_sign_step) {
            log_it (L_ERROR, "Can't create multi-signature step signature");
            dap_multi_sign_delete(l_sign);
            return NULL;
        }
        uint8_t *l_pkey = dap_sign_get_pkey(l_dap_sign_step, &l_pkey_size);
        l_sign->meta[i].pkey_size = l_pkey_size;
        if (l_pkeys_mem_shift == 0) {
            l_sign->pub_keys = DAP_NEW_Z_SIZE(uint8_t, l_pkey_size);
        } else {
            l_sign->pub_keys = DAP_REALLOC(l_sign->pub_keys, l_pkeys_mem_shift + l_pkey_size);
        }
        memcpy(&l_sign->pub_keys[l_pkeys_mem_shift], l_pkey, l_pkey_size);
        l_pkeys_mem_shift += l_pkey_size;
        uint8_t *l_sign_step = dap_sign_get_sign(l_dap_sign_step, &l_sign_size);
        l_sign->meta[i].sign_size = l_sign_size;
        if (l_signs_mem_shift == 0) {
            l_sign->sign_data = DAP_NEW_Z_SIZE(uint8_t, l_sign_size);
        } else {
            l_sign->sign_data = DAP_REALLOC(l_sign->sign_data, l_signs_mem_shift + l_sign_size);
        }
        memcpy(&l_sign->sign_data[l_signs_mem_shift], l_sign_step, l_sign_size);
        DAP_DELETE(l_dap_sign_step);
    }
    return l_sign;
}

/**
 * @brief dap_multi_sign_verify Make verification test for multi-signed message
 * @param a_sign Pointer to multi-signature structure
 * @param a_data Pointer to message signed with this multi-signature
 * @param a_data_size Signed message size
 * @return 1 valid signature, 0 invalid signature, -1 verification error
 */
int dap_multi_sign_verify(dap_multi_sign_t *a_sign, const void *a_data, const size_t a_data_size)
{
    if (!a_sign || !a_data)
        return -1;
    if (a_sign->type.type != SIG_TYPE_MULTI_CHAINED) {
        log_it (L_ERROR, "Unsupported multi-signature type");
        return -1;
    }
    if (!a_sign->pub_keys || !a_sign->sign_data || !a_sign->key_hashes || !a_sign->meta || !a_sign->key_seq) {
        log_it (L_ERROR, "Invalid multi-signature format");
        return -1;
    }
    uint32_t l_pkeys_mem_shift = 0, l_signs_mem_shift = 0;
    for (int i = 0; i < a_sign->sign_count - 1; i++) {
        l_pkeys_mem_shift += a_sign->meta[i].pkey_size;
        l_signs_mem_shift += a_sign->meta[i].sign_size;
    }
    dap_chain_hash_fast_t l_data_hash;
    bool l_hashed;
    int l_verified = 0;
    for (int i = a_sign->sign_count - 1; i >= 0; i--) {
        size_t l_pkey_size = a_sign->meta[i].pkey_size;
        size_t l_sign_size = a_sign->meta[i].sign_size;
        dap_sign_t *l_step_sign = DAP_NEW_Z_SIZE(dap_sign_t,
                sizeof(dap_sign_hdr_t) + l_pkey_size + l_sign_size);
        l_step_sign->header.type = a_sign->key_seq[i].type;
        l_step_sign->header.sign_pkey_size = l_pkey_size;
        l_step_sign->header.sign_size = l_sign_size;
        memcpy(l_step_sign->pkey_n_sign, &a_sign->pub_keys[l_pkeys_mem_shift], l_pkey_size);
        if (i > 0) {
            l_pkeys_mem_shift -= a_sign->meta[i - 1].pkey_size;
        }
        memcpy(&l_step_sign->pkey_n_sign[l_pkey_size], &a_sign->sign_data[l_signs_mem_shift], l_sign_size);
        if (i > 0) {
            l_signs_mem_shift -= a_sign->meta[i - 1].sign_size;
        }
        if (i ==0) {
            l_hashed = dap_multi_sign_hash_data(a_sign, a_data, a_data_size, &l_data_hash);
        } else {
            l_hashed = dap_hash_fast(&a_sign->sign_data[l_signs_mem_shift], a_sign->meta[i - 1].sign_size, &l_data_hash);
        }
        if (!l_hashed) {
            log_it (L_ERROR, "Can't create multi-signature hash");
            DAP_DELETE(l_step_sign);
            return -1;
        }
        l_verified = dap_sign_verify(l_step_sign, &l_data_hash, sizeof(dap_chain_hash_fast_t));
        DAP_DELETE(l_step_sign);
        if (l_verified != 1) {
            return l_verified;
        }
    }
    return l_verified;
}

/**
 * @brief dap_multi_sign_delete Destroy multi-signature structure
 * @param a_sign Pointer to multi-signature structure to destroy
 * @return None
 */
void dap_multi_sign_delete(dap_multi_sign_t *a_sign)
{
    if (!a_sign)
        return;
    if (a_sign->sign_data) {
        DAP_DELETE(a_sign->sign_data);
    }
    if (a_sign->pub_keys) {
        DAP_DELETE(a_sign->pub_keys);
    }
    if (a_sign->key_hashes) {
        DAP_DELETE(a_sign->key_hashes);
    }
    if (a_sign->meta) {
        DAP_DELETE(a_sign->meta);
    }
    if (a_sign->key_seq) {
        DAP_DELETE(a_sign->key_seq);
    }
    DAP_DELETE(a_sign);
}

/**
 * @brief dap_sign_get_information Added in string information about signature
 * @param a_sign Signature can be NULL
 * @param a_str_out The output string pointer
 */
void dap_sign_get_information(dap_sign_t* a_sign, dap_string_t *a_str_out, const char *a_hash_out_type)
{
    dap_string_append_printf(a_str_out, "Signature: \n");
    if (a_sign != NULL){
        dap_chain_hash_fast_t l_hash_pkey;
        dap_string_append_printf(a_str_out, "\tType: %s\n",
                                 dap_sign_type_to_str(a_sign->header.type));
        if(dap_sign_get_pkey_hash(a_sign, &l_hash_pkey)){
            char *l_hash_str = NULL;
            if (!dap_strcmp(a_hash_out_type, "hex"))
                l_hash_str = dap_chain_hash_fast_to_str_new(&l_hash_pkey);
            else
                l_hash_str = dap_enc_base58_encode_hash_to_str(&l_hash_pkey);
            dap_string_append_printf(a_str_out, "\tPublic key hash: %s\n", l_hash_str);
            DAP_DELETE(l_hash_str);

        }
        dap_string_append_printf(a_str_out, "\tPublic key size: %u\n"
                                            "\tSignature size: %u\n",
                                 a_sign->header.sign_pkey_size,
                                 a_sign->header.sign_size);
    }else {
        dap_string_append_printf(a_str_out, "! Signature has data, corrupted or not valid\n");
    }
}

json_object* dap_sign_to_json(const dap_sign_t *a_sign){
    if (a_sign) {
        json_object *l_object = json_object_new_object();
        json_object *l_obj_type_sign = json_object_new_string(dap_sign_type_to_str(a_sign->header.type));
        json_object_object_add(l_object, "type", l_obj_type_sign);
        dap_chain_hash_fast_t l_hash_pkey = {};
        if (dap_sign_get_pkey_hash((dap_sign_t *) a_sign, &l_hash_pkey)) {
            char *l_hash = dap_chain_hash_fast_to_str_new(&l_hash_pkey);
            json_object *l_obj_pkey_hash = json_object_new_string(l_hash);
            json_object_object_add(l_object, "pkeyHash", l_obj_pkey_hash);
        }
        json_object *l_obj_pkey_size = json_object_new_uint64(a_sign->header.sign_pkey_size);
        json_object *l_obj_sign_size = json_object_new_uint64(a_sign->header.sign_size);
        json_object_object_add(l_object, "signPkeySize", l_obj_pkey_size);
        json_object_object_add(l_object, "signSize", l_obj_sign_size);
        return l_object;
    }
    return NULL;
}
