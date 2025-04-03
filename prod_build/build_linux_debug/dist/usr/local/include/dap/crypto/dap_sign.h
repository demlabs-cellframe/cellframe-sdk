/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#pragma once

#include <stdint.h>
#include "dap_common.h"
#include "dap_enc_ca.h"
#include "dap_enc_key.h"
#include "dap_hash.h"
#include "dap_string.h"
#include "json.h"

enum dap_sign_type_enum {
    SIG_TYPE_NULL = 0x0000,
    SIG_TYPE_BLISS = 0x0001,
    SIG_TYPE_TESLA = 0x0003, /// @brief
    SIG_TYPE_PICNIC = 0x0101, /// @brief
    SIG_TYPE_DILITHIUM = 0x0102, /// @brief
    SIG_TYPE_FALCON = 0x0103, /// @brief Falcon signature
    SIG_TYPE_SPHINCSPLUS = 0x0104, /// @brief Sphincs+ signature
    SIG_TYPE_ECDSA = 0x105,
    SIG_TYPE_SHIPOVNIK = 0x0106,
#ifdef DAP_PQLR
    SIG_TYPE_PQLR_DILITHIUM = 0x1102,
    SIG_TYPE_PQLR_FALCON = 0x1103,
    SIG_TYPE_PQLR_SPHINCS = 0x1104,
#endif
    SIG_TYPE_MULTI_CHAINED = 0x0f00, ///  @brief Has inside subset of different signatures and sign composed with all of them
    SIG_TYPE_MULTI_COMBINED = 0x0f01 ///  @brief Has inside subset of different public keys and sign composed with all of appropriate private keys
};
typedef uint32_t dap_sign_type_enum_t;

#define DAP_SIGN_HASH_TYPE_NONE      0x00
#define DAP_SIGN_HASH_TYPE_SHA3      0x01
#define DAP_SIGN_HASH_TYPE_STREEBOG  0x02
#define DAP_SIGN_HASH_TYPE_SIGN      0x0e
#define DAP_SIGN_HASH_TYPE_DEFAULT   0x0f  // not transferred in network, first try use sign hash, if false, use s_sign_hash_type_default

#define DAP_SIGN_PKEY_HASHING_FLAG BIT(7)
#define DAP_SIGN_ADD_PKEY_HASHING_FLAG(a) ((a) | DAP_SIGN_PKEY_HASHING_FLAG)
#define DAP_SIGN_REMOVE_PKEY_HASHING_FLAG(a) ((a) & ~DAP_SIGN_PKEY_HASHING_FLAG)
#define DAP_SIGN_GET_PKEY_HASHING_FLAG(a) ((a) & DAP_SIGN_PKEY_HASHING_FLAG)

typedef union dap_sign_type {
    dap_sign_type_enum_t type;
    uint32_t raw;
} DAP_ALIGN_PACKED dap_sign_type_t;

typedef struct dap_sign_hdr {
        dap_sign_type_t type; /// Signature type
        uint8_t hash_type;
        uint8_t padding;
        uint32_t sign_size; /// Signature size
        uint32_t sign_pkey_size; /// Signature serialized public key size
} DAP_ALIGN_PACKED dap_sign_hdr_t;

/**
  * @struct dap_sign
  * @brief Chain storage format for digital signature
  */
typedef struct dap_sign
{
    dap_sign_hdr_t header; /// Only header's hash is used for verification
    uint8_t pkey_n_sign[]; /// @param sig @brief raw signature data
} DAP_ALIGN_PACKED dap_sign_t;
typedef struct dap_pkey dap_pkey_t;
typedef dap_pkey_t *(*dap_sign_callback_t)(const uint8_t *);

#ifdef __cplusplus
extern "C" {
#endif


int dap_sign_init(uint8_t a_sign_hash_type_default);

uint64_t dap_sign_get_size(dap_sign_t * a_chain_sign);
int dap_sign_verify_by_pkey(dap_sign_t *a_chain_sign, const void *a_data, const size_t a_data_size, dap_pkey_t *a_pkey);
DAP_STATIC_INLINE int dap_sign_verify (dap_sign_t *a_chain_sign, const void *a_data, const size_t a_data_size)
{
    return dap_sign_verify_by_pkey(a_chain_sign, a_data, a_data_size, NULL);
}

/**
 * @brief verify, if a_sign->header.sign_pkey_size and a_sign->header.sign_size bigger, then a_max_key_size
 * @param a_sign signed data object 
 * @param a_max_sign_size max size of signature
 * @return 0 if pass, otjer if not 
 */
DAP_STATIC_INLINE int dap_sign_verify_size(dap_sign_t *a_sign, size_t a_max_sign_size)
{
    return !(a_sign && (a_max_sign_size > sizeof(dap_sign_t)) && (a_sign->header.sign_size) &&
           (a_sign->header.sign_pkey_size) && (a_sign->header.type.type != SIG_TYPE_NULL) &&
           ((uint64_t)a_sign->header.sign_size + a_sign->header.sign_pkey_size + sizeof(dap_sign_t) <= (uint64_t)a_max_sign_size));
}

/**
 * @brief dap_sign_verify_all
 * @param a_sign
 * @param a_sign_size_max
 * @param a_data
 * @param a_data_size
 * @return
 */
DAP_STATIC_INLINE int dap_sign_verify_all(dap_sign_t *a_sign, const size_t a_sign_size_max, const void * a_data, const size_t a_data_size)
{
    return dap_sign_verify_size(a_sign,a_sign_size_max) ? -2 : dap_sign_verify(a_sign,a_data, a_data_size) ? -1 : 0;
}

const char *dap_sign_get_str_recommended_types();

// Create sign of data hash with key provided algorythm of signing and hashing (independently)
dap_sign_t * dap_sign_create_with_hash_type(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size, uint32_t a_hash_type);

DAP_STATIC_INLINE dap_sign_t *dap_sign_create(dap_enc_key_t *a_key, const void *a_data, const size_t a_data_size)
{
    return dap_sign_create_with_hash_type(a_key, a_data, a_data_size, DAP_SIGN_HASH_TYPE_DEFAULT);
}
//Create sign on raw data without hashing. Singing algorythm is key provided
int dap_sign_create_output(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size, void * a_output, size_t *a_output_size);

size_t dap_sign_create_output_unserialized_calc_size(dap_enc_key_t *a_key);
//int dap_sign_create_output(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size
//                                 , void * a_output, size_t a_output_size );

dap_sign_type_t dap_sign_type_from_key_type( dap_enc_key_type_t a_key_type);
dap_enc_key_type_t  dap_sign_type_to_key_type(dap_sign_type_t  a_chain_sign_type);

uint8_t* dap_sign_get_sign(dap_sign_t *a_sign, size_t *a_sign_size);
uint8_t* dap_sign_get_pkey(dap_sign_t *a_sign, size_t *a_pub_key_out);
bool dap_sign_get_pkey_hash(dap_sign_t *a_sign, dap_chain_hash_fast_t *a_sign_hash);
bool dap_sign_compare_pkeys(dap_sign_t *l_sign1, dap_sign_t *l_sign2);

dap_enc_key_t *dap_sign_to_enc_key_by_pkey(dap_sign_t *a_chain_sign, dap_pkey_t *a_pkey);
DAP_STATIC_INLINE dap_enc_key_t *dap_sign_to_enc_key(dap_sign_t * a_chain_sign)
{  
    return dap_sign_to_enc_key_by_pkey(a_chain_sign, NULL);
}



const char * dap_sign_type_to_str(dap_sign_type_t a_chain_sign_type);
dap_sign_type_t dap_sign_type_from_str(const char * a_type_str);
bool dap_sign_type_is_depricated(dap_sign_type_t a_sign_type);
dap_sign_t **dap_sign_get_unique_signs(void *a_data, size_t a_data_size, size_t *a_signs_count);

void dap_sign_get_information(dap_sign_t *a_sign, dap_string_t *a_str_out, const char *a_hash_out_type);
void dap_sign_get_information_json(json_object* a_json_arr_reply, dap_sign_t* a_sign, json_object *a_json_out, const char *a_hash_out_type);

int dap_sign_set_pkey_by_hash_callback (dap_sign_callback_t a_callback);

/**
 * @brief get SHA3 hash of buffer (a_sign), storing in output buffer a_sign_hash
 * @param a_sign to check
 * @return true or false
 */
DAP_STATIC_INLINE bool dap_sign_is_use_pkey_hash(dap_sign_t *a_sign)
{
    return  a_sign && DAP_SIGN_GET_PKEY_HASHING_FLAG(a_sign->header.hash_type);
}

#ifdef __cplusplus
}
#endif
