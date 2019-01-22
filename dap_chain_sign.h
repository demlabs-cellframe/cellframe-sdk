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

typedef union dap_chain_sign_type{
    enum {
        SIG_TYPE_BLISS = 0x0000,
        SIG_TYPE_DEFO = 0x0001, /// @brief key image for anonymous transaction
        SIG_TYPE_TESLA = 0x0002, /// @brief
        SIG_TYPE_PICNIC = 0x0101, /// @brief
        SIG_TYPE_MULTI = 0xffff ///  @brief Has inside subset of different signatures and sign composed with all of them
    } type: 16;
    uint16_t raw;
} dap_chain_sign_type_t;

/**
  * @struct dap_chain_sign
  * @brief Chain storage format for digital signature
  */
typedef struct dap_chain_sign{
    struct {
        dap_chain_sign_type_t type; /// Signature type
        uint16_t sign_size; /// Signature size
        uint32_t sign_pkey_size; /// Signature public key size
    } header; /// Only header's hash is used for verification
    uint8_t pkey_n_sign[]; /// @param sig @brief raw signature data
} DAP_ALIGN_PACKED dap_chain_sign_t;

int dap_chain_sign_verify (dap_chain_sign_t * a_chain_sign);

dap_chain_sign_t * dap_chain_sign_create(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size
                                         ,  size_t a_output_wish_size );

dap_chain_sign_type_t dap_chain_sign_type_from_key_type( dap_enc_key_type_t a_key_type);
dap_enc_key_type_t  dap_chain_sign_type_to_key_type(dap_chain_sign_type_t  a_chain_sign_type);

dap_enc_key_t *dap_chain_sign_to_enc_key(dap_chain_sign_t * a_chain_sign);
size_t dap_chain_sign_create_output_cals_size(dap_enc_key_t * a_key,size_t a_output_wish_size );
int dap_chain_sign_create_output(dap_enc_key_t *a_key, const void * a_data, const size_t a_data_size
                                 , void * a_output, size_t a_output_size );
