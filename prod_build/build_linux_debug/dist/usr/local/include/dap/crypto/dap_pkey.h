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
#include "dap_enc_key.h"
#include "dap_sign.h"

enum dap_pkey_type_enum {
    DAP_PKEY_TYPE_NULL = 0x0000,
    DAP_PKEY_TYPE_SIGN_BLISS = 0x0901,
    DAP_PKEY_TYPE_SIGN_TESLA = 0x0902,
    DAP_PKEY_TYPE_SIGN_DILITHIUM =  0x0903,
    DAP_PKEY_TYPE_SIGN_PICNIC = 0x0904,
    DAP_PKEY_TYPE_SIGN_FALCON = 0x0905,
    DAP_PKEY_TYPE_SIGN_SPHINCSPLUS = 0x0906,
    DAP_PKEY_TYPE_SIGN_ECDSA = 0x0907,
    DAP_PKEY_TYPE_SIGN_SHIPOVNIK = 0x0908,
    DAP_PKEY_TYPE_MULTI_CHAINED = 0xfffe,
    DAP_PKEY_TYPE_MULTI = 0xffff ///  @brief Has inside subset of different keys
};
typedef uint16_t dap_pkey_type_enum_t;

typedef union dap_pkey_type{
    dap_pkey_type_enum_t type;
    uint16_t raw;
} dap_pkey_type_t;

DAP_STATIC_INLINE const char *dap_pkey_type_to_str(dap_pkey_type_t a_type){
    switch (a_type.type) {
        case DAP_PKEY_TYPE_NULL:  return  "DAP_PKEY_TYPE_NULL";
        case DAP_PKEY_TYPE_MULTI: return "DAP_PKEY_TYPE_MULTI";
        case DAP_PKEY_TYPE_SIGN_BLISS: return "DAP_PKEY_TYPE_SIGN_BLISS";
        case DAP_PKEY_TYPE_SIGN_TESLA: return "DAP_PKEY_TYPE_SIGN_TESLA";
        case DAP_PKEY_TYPE_SIGN_PICNIC: return "DAP_PKEY_TYPE_SIGN_PICNIC";
        case DAP_PKEY_TYPE_SIGN_DILITHIUM: return "DAP_PKEY_TYPE_SIGN_DILITHIUM";
        case DAP_PKEY_TYPE_SIGN_FALCON: return "DAP_PKEY_TYPE_SIGN_FALCON";
        case DAP_PKEY_TYPE_SIGN_SPHINCSPLUS: return "DAP_PKEY_TYPE_SIGN_SPHINCSPLUS";
        case DAP_PKEY_TYPE_SIGN_ECDSA: return "DAP_PKEY_TYPE_SIGN_ECDSA";
        case DAP_PKEY_TYPE_SIGN_SHIPOVNIK: return "DAP_PKEY_TYPE_SIGN_SHIPOVNIK";
        case DAP_PKEY_TYPE_MULTI_CHAINED: return "DAP_PKEY_TYPE_MULTI_CHAINED";
        default: return "UNDEFINED";
    }
}

/**
 * @brief convert public key type (dap_pkey_type_t) to dap_sign_type_t type
 *
 * @param a_pkey_type dap_pkey_type_t key type
 * @return dap_sign_type_t
 */
DAP_STATIC_INLINE dap_sign_type_t dap_pkey_type_to_sign_type(dap_pkey_type_t a_pkey_type)
{
    dap_sign_type_t l_sign_type = {0};
    switch (a_pkey_type.type){
        case DAP_PKEY_TYPE_SIGN_BLISS: l_sign_type.type = SIG_TYPE_BLISS; break;
        case DAP_PKEY_TYPE_SIGN_PICNIC: l_sign_type.type = SIG_TYPE_PICNIC; break;
        case DAP_PKEY_TYPE_SIGN_TESLA: l_sign_type.type = SIG_TYPE_TESLA; break;
        case DAP_PKEY_TYPE_SIGN_DILITHIUM : l_sign_type.type = SIG_TYPE_DILITHIUM; break;
        case DAP_PKEY_TYPE_SIGN_FALCON : l_sign_type.type = SIG_TYPE_FALCON; break;
        case DAP_PKEY_TYPE_SIGN_SPHINCSPLUS : l_sign_type.type = SIG_TYPE_SPHINCSPLUS; break;
        case DAP_PKEY_TYPE_SIGN_ECDSA: l_sign_type.type = SIG_TYPE_ECDSA; break;
        case DAP_PKEY_TYPE_SIGN_SHIPOVNIK: l_sign_type.type = SIG_TYPE_SHIPOVNIK; break;
        case DAP_PKEY_TYPE_MULTI_CHAINED: l_sign_type.type = SIG_TYPE_MULTI_CHAINED; break;

        default: l_sign_type.type = SIG_TYPE_NULL; break;
    }
    return l_sign_type;
}

/**
 * @brief convert dap_sign_type_t type to public key type (dap_pkey_type_t)
 *
 * @param a_sign_type dap_sign_type_t key type
 * @return dap_pkey_type_t
 */
DAP_STATIC_INLINE dap_pkey_type_t dap_pkey_type_from_sign_type(dap_sign_type_t a_sign_type)
{
    dap_pkey_type_t l_pkey_type = {0};
    switch (a_sign_type.type){
        case SIG_TYPE_BLISS: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_BLISS; break;
        case SIG_TYPE_PICNIC: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_PICNIC; break;
        case SIG_TYPE_TESLA: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_TESLA; break;
        case SIG_TYPE_DILITHIUM: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_DILITHIUM; break;
        case SIG_TYPE_FALCON: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_FALCON; break;
        case SIG_TYPE_SPHINCSPLUS: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_SPHINCSPLUS; break;
        case SIG_TYPE_ECDSA: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_ECDSA; break;
        case SIG_TYPE_SHIPOVNIK: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_SHIPOVNIK; break;
        case SIG_TYPE_MULTI_CHAINED: l_pkey_type.type = DAP_PKEY_TYPE_MULTI_CHAINED; break;
        default: l_pkey_type.type = DAP_PKEY_TYPE_NULL; break;
    }
    return l_pkey_type;
}

/**
 * @brief convert public key type (dap_pkey_type_t) to dap_enc_key_type_t type
 *
 * @param a_pkey_type dap_pkey_type_t key type
 * @return dap_enc_key_type_t
 */
DAP_STATIC_INLINE dap_enc_key_type_t dap_pkey_type_to_enc_key_type(dap_pkey_type_t a_pkey_type)
{
    switch (a_pkey_type.type){
        case DAP_PKEY_TYPE_SIGN_BLISS: return DAP_ENC_KEY_TYPE_SIG_BLISS;
        case DAP_PKEY_TYPE_SIGN_PICNIC: return DAP_ENC_KEY_TYPE_SIG_PICNIC;
        case DAP_PKEY_TYPE_SIGN_TESLA: return DAP_ENC_KEY_TYPE_SIG_TESLA;
        case DAP_PKEY_TYPE_SIGN_DILITHIUM: return DAP_ENC_KEY_TYPE_SIG_DILITHIUM;
        case DAP_PKEY_TYPE_SIGN_FALCON: return DAP_ENC_KEY_TYPE_SIG_FALCON;
        case DAP_PKEY_TYPE_SIGN_SPHINCSPLUS: return DAP_ENC_KEY_TYPE_SIG_SPHINCSPLUS;
        case DAP_PKEY_TYPE_SIGN_ECDSA: return DAP_ENC_KEY_TYPE_SIG_ECDSA;
        case DAP_PKEY_TYPE_SIGN_SHIPOVNIK: return DAP_ENC_KEY_TYPE_SIG_SHIPOVNIK;
        case DAP_PKEY_TYPE_MULTI_CHAINED: return DAP_ENC_KEY_TYPE_SIG_MULTI_CHAINED;
        default:;
    }
    return DAP_ENC_KEY_TYPE_INVALID;
}

/**
 * @brief convert dap_enc_key_type_t type to public key type (dap_pkey_type_t)
 *
 * @param a_key_type dap_enc_key_type_t key type
 * @return dap_pkey_type_t
 */
DAP_STATIC_INLINE dap_pkey_type_t dap_pkey_type_from_enc_key_type(dap_enc_key_type_t a_key_type)
{
    dap_pkey_type_t l_pkey_type={0};
    switch (a_key_type){
        case DAP_ENC_KEY_TYPE_SIG_BLISS: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_BLISS; break;
        case DAP_ENC_KEY_TYPE_SIG_PICNIC: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_PICNIC; break;
        case DAP_ENC_KEY_TYPE_SIG_TESLA: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_TESLA; break;
        case DAP_ENC_KEY_TYPE_SIG_DILITHIUM: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_DILITHIUM; break;
        case DAP_ENC_KEY_TYPE_SIG_FALCON: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_FALCON; break;
        case DAP_ENC_KEY_TYPE_SIG_SPHINCSPLUS: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_SPHINCSPLUS; break;
        case DAP_ENC_KEY_TYPE_SIG_ECDSA: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_ECDSA; break;
        case DAP_ENC_KEY_TYPE_SIG_SHIPOVNIK: l_pkey_type.type = DAP_PKEY_TYPE_SIGN_SHIPOVNIK; break;
        case DAP_ENC_KEY_TYPE_SIG_MULTI_CHAINED: l_pkey_type.type = DAP_PKEY_TYPE_MULTI_CHAINED; break;
        default: l_pkey_type.type = DAP_PKEY_TYPE_NULL; break;
    }
    return l_pkey_type;
}

/**
  * @struct dap_pkey
  * @brief Public keys
  */
typedef struct dap_pkey {
    struct {
        dap_pkey_type_t type;   // Pkey type
        uint32_t size DAP_ALIGNED(4);          // Pkey size
    } DAP_PACKED header;
    uint8_t pkey[];             // Raw pkey data
} DAP_PACKED dap_pkey_t;

DAP_STATIC_INLINE size_t dap_pkey_get_size(const dap_pkey_t *a_pkey) { return a_pkey ? sizeof(dap_pkey_t) + a_pkey->header.size : 0; }

dap_pkey_t *dap_pkey_from_enc_key(dap_enc_key_t *a_key);

bool dap_pkey_get_hash(dap_pkey_t *a_pkey, dap_chain_hash_fast_t *a_out_hash);

DAP_STATIC_INLINE bool dap_pkey_compare_with_sign(dap_pkey_t *a_pkey, dap_sign_t *a_sign)
{
    return (dap_pkey_type_to_enc_key_type(a_pkey->header.type) == dap_sign_type_to_key_type(a_sign->header.type) &&
            a_pkey->header.size == a_sign->header.sign_pkey_size &&
            !memcmp(a_pkey->pkey, a_sign->pkey_n_sign, a_pkey->header.size));
}

DAP_STATIC_INLINE bool dap_pkey_compare(dap_pkey_t *a_pkey1, dap_pkey_t *a_pkey2)
{
    return (a_pkey1->header.type.raw == a_pkey2->header.type.raw &&
            a_pkey1->header.size == a_pkey2->header.size &&
            !memcmp(a_pkey1->pkey, a_pkey2->pkey, a_pkey1->header.size));
}

dap_pkey_t *dap_pkey_get_from_sign(dap_sign_t *a_sign);
dap_pkey_t *dap_pkey_get_from_hex_str(const char *a_hex_str);
dap_pkey_t *dap_pkey_get_from_base58_str(const char *a_base58_str);
dap_pkey_t *dap_pkey_get_from_str( const char *a_pkey_str);

char *dap_pkey_to_hex_str(const dap_pkey_t *a_pkey);
char *dap_pkey_to_base58_str(const dap_pkey_t *a_pkey);
char *dap_pkey_to_str(const dap_pkey_t *a_pkey, const char *a_str_type);
