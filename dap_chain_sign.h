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

typedef union dap_chain_sign_type{
    enum {
        SIG_TYPE_PICNIC = 0x0000,
        SIG_TYPE_DEFO = 0x0001, /// @brief key image for anonymous transaction
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

dap_chain_sign_t* dap_chain_sign_new_generate(dap_chain_sign_t a_type, uint32_t a_sign_size, uint32_t a_sign_pkey_size);
size_t dap_chain_sign_enc_get_buf_out_size(dap_chain_pkey_t * a_pkey);
int dap_chain_pkey_enc(dap_chain_pkey_t a_type,const void * a_buf_in, uint32_t a_buf_in_size, void * a_buf_out); // 0 if success
