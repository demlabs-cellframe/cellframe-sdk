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

#pragma once

#include <stdint.h>
#include "dap_common.h"
#include "dap_enc_ca.h"
#include "dap_enc_key.h"
#include "dap_pkey.h"
#include "dap_hash.h"
#include "dap_string.h"

enum dap_sign_type_enum {
    SIG_TYPE_NULL = 0x0000,
    SIG_TYPE_BLISS = 0x0001,
    SIG_TYPE_DEFO = 0x0002, /// @brief key image for anonymous transaction
    SIG_TYPE_TESLA = 0x0003, /// @brief
    SIG_TYPE_PICNIC = 0x0101, /// @brief
    SIG_TYPE_DILITHIUM = 0x0102, /// @brief
    SIG_TYPE_MULTI_CHAINED = 0x0f00, ///  @brief Has inside subset of different signatures and sign composed with all of them
    SIG_TYPE_MULTI_COMBINED = 0x0f01 ///  @brief Has inside subset of different public keys and sign composed with all of appropriate private keys
};
typedef uint32_t dap_sign_type_enum_t;

typedef union dap_sign_type {
    dap_sign_type_enum_t type;
    uint32_t raw;
} DAP_ALIGN_PACKED dap_sign_type_t;

typedef struct dap_sign_hdr {
        dap_sign_type_t type; /// Signature type
        uint16_t padding;
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

#define MULTI_SIGN_MAX_COUNT 255

typedef struct _dap_multi_sign_params_t {
    dap_sign_type_t type;               // Multi-signature type
    uint8_t total_count;                // Total key count
    uint8_t sign_count;                 // Signatures count
    uint8_t *key_seq;                   // Signing key sequence
    dap_enc_key_t **keys;               // Signing keys
} dap_multi_sign_params_t;

typedef struct _dap_multi_sign_meta_t {
    uint32_t pkey_size;                 // Size of public key
    uint32_t sign_size;                 // Size of signature
} DAP_ALIGN_PACKED dap_multi_sign_meta_t;

typedef struct _dap_multi_sign_keys_t {
    uint8_t num;
    dap_sign_type_t type;
} DAP_ALIGN_PACKED dap_multi_sign_keys_t;

typedef struct _dap_multi_sign_t {
/*** Hashed metadata ***/
    dap_sign_type_t type;               // Multi-signature type
    uint8_t total_count;                // Total key count
    uint8_t sign_count;                 // Signatures count
    dap_multi_sign_keys_t *key_seq;     // Signing key sequence
/*** Unhashed metadata ***/
    dap_multi_sign_meta_t *meta;        // Sizes of keys and signatures
/*** Key hashes ***/
    dap_chain_hash_fast_t *key_hashes;  // Total key hashes
/*** Serialized public keys ***/
    uint8_t *pub_keys;                  // Public keys for this signature
/*** Serialized signatures chain ***/
    uint8_t *sign_data;                 // Signatures data
} DAP_ALIGN_PACKED dap_multi_sign_t;

#ifdef __cplusplus
extern "C" {
#endif

size_t dap_sign_get_size(dap_sign_t * a_chain_sign);

int dap_sign_verify (dap_sign_t * a_chain_sign, const void * a_data, const size_t a_data_size);

dap_sign_t * dap_sign_create(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size
                                         ,  size_t a_output_wish_size );
dap_sign_t * dap_sign_pack(dap_enc_key_t *a_key, const void * a_sign_ser, const size_t a_sign_ser_size, const void * a_pkey, const size_t a_pub_key_size);

size_t dap_sign_create_output_unserialized_calc_size(dap_enc_key_t * a_key,size_t a_output_wish_size );
//int dap_sign_create_output(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size
//                                 , void * a_output, size_t a_output_size );


dap_sign_type_t dap_sign_type_from_key_type( dap_enc_key_type_t a_key_type);
dap_enc_key_type_t  dap_sign_type_to_key_type(dap_sign_type_t  a_chain_sign_type);

dap_sign_type_t dap_pkey_type_from_sign( dap_pkey_type_t a_pkey_type);

uint8_t* dap_sign_get_sign(dap_sign_t *a_sign, size_t *a_sign_out);
uint8_t* dap_sign_get_pkey(dap_sign_t *a_sign, size_t *a_pub_key_out);
bool dap_sign_get_pkey_hash(dap_sign_t *a_sign, dap_chain_hash_fast_t * a_sign_hash);
bool dap_sign_match_pkey_signs(dap_sign_t *l_sign1, dap_sign_t *l_sign2);

bool dap_sign_verify_size(dap_sign_t *a_sign, size_t a_max_key_size);
dap_enc_key_t *dap_sign_to_enc_key(dap_sign_t * a_chain_sign);
const char * dap_sign_type_to_str(dap_sign_type_t a_chain_sign_type);
dap_sign_type_t dap_sign_type_from_str(const char * a_type_str);
dap_sign_t **dap_sign_get_unique_signs(void *a_data, size_t a_data_size, size_t *a_signs_count);

uint8_t *dap_multi_sign_serialize(dap_multi_sign_t *a_sign, size_t *a_out_len);
dap_multi_sign_t *dap_multi_sign_deserialize(dap_sign_type_enum_t a_type, uint8_t *a_sign, size_t a_sign_len);
dap_multi_sign_params_t *dap_multi_sign_params_make(dap_sign_type_enum_t a_type, uint8_t a_total_count, uint8_t a_sign_count, dap_enc_key_t *a_key1, ...);
void dap_multi_sign_params_delete(dap_multi_sign_params_t *a_params);
dap_multi_sign_t *dap_multi_sign_create(dap_multi_sign_params_t *a_params, const void *a_data, const size_t a_data_size);
int dap_multi_sign_verify(dap_multi_sign_t *a_sign, const void *a_data, const size_t a_data_size);
void dap_multi_sign_delete(dap_multi_sign_t *a_sign);

void dap_sign_get_information(dap_sign_t *a_sign, dap_string_t *a_str_out, const char *a_hash_out_type);

#ifdef __cplusplus
}
#endif
