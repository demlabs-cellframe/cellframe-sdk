/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include "dap_enc_key.h"
#include "dap_chain_common.h"

#include "dap_chain_wallet.h"

#define DAP_CHAIN_WALLET_FILE_SIGNATURE 0x1a167bef15feea18

typedef struct dap_chain_wallet_key{
    struct {
        dap_chain_sign_type_t sig_type; /// Signature type
        uint32_t key_size; /// Private key size
    } header;
    uint8_t key_raw[]; /// Raw data of the private key
} DAP_ALIGN_PACKED dap_chain_wallet_key_t;


typedef struct dap_chain_wallet_file
{
    struct {
        uint64_t signature;
        uint32_t version;
        uint8_t type; /// Wallet storage type 0x00 - uncompressed and unencrypted
        uint64_t keys_size;
    } DAP_ALIGN_PACKED header;
    uint8_t keys[];
} DAP_ALIGN_PACKED dap_chain_wallet_file_t;

typedef struct dap_chain_wallet_internal
{
    dap_chain_addr_t addr;
    char * file_name;
    size_t keys_count;
    dap_enc_key_t ** keys;
} dap_chain_wallet_internal_t;

#define DAP_CHAIN_WALLET_INTERNAL(a) ((dap_chain_wallet_internal_t *) a->_internal  )

#define DAP_CHAIN_WALLET_INTERNAL_LOCAL(a) dap_chain_wallet_internal_t * l_wallet_internal = DAP_CHAIN_WALLET_INTERNAL(a)

#define DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(a) dap_chain_wallet_internal_t * l_wallet_internal = DAP_NEW_Z(dap_chain_wallet_internal_t); a->_internal = l_wallet_internal
