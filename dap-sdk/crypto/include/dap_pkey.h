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
#include "dap_enc_key.h"

typedef union dap_pkey_type{
    enum {
        PKEY_TYPE_NULL = 0x0000,
        PKEY_TYPE_SIGN_BLISS = 0x0901,
        PKEY_TYPE_SIGN_TESLA = 0x0902,
        PKEY_TYPE_SIGN_DILITHIUM =  0x0903,
        PKEY_TYPE_SIGN_PICNIC = 0x0102,
        PKEY_TYPE_MULTI = 0xffff ///  @brief Has inside subset of different keys

    } type: 16;
    uint16_t raw;
} dap_pkey_type_t;
/**
  * @struct dap_pkey
  * @brief Public keys
  */
typedef struct dap_pkey{
    struct {
        dap_pkey_type_t type; /// Pkey type
        uint32_t size; /// Pkey size
    } header; /// Only header's hash is used for verification
    uint8_t pkey[]; /// @param pkey @brief raw pkey dat
} DAP_ALIGN_PACKED dap_pkey_t;

static dap_pkey_t m_dap_pkey_null; // For sizeof nothing more

dap_pkey_t *dap_pkey_from_enc_key(dap_enc_key_t *a_key);
static inline size_t dap_pkey_from_enc_key_output_calc(dap_enc_key_t *a_key)
{
    return sizeof(m_dap_pkey_null.header)+ a_key->pub_key_data_size;
}

int dap_pkey_from_enc_key_output(dap_enc_key_t *a_key, void * a_output);

