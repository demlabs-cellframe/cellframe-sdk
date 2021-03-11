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

#include "dap_cert.h"
#include "dap_cert_file.h"
#include "dap_chain_common.h"

#include "dap_chain_wallet.h"

#define DAP_CHAIN_WALLETS_FILE_SIGNATURE 0x1a167bef15feea18

typedef struct dap_chain_wallet_cert_hdr{
    uint32_t version;
    uint32_t cert_raw_size; /// Certificate size
} DAP_ALIGN_PACKED dap_chain_wallet_cert_hdr_t;

typedef struct dap_chain_wallet_cert{
    dap_chain_wallet_cert_hdr_t header;
    dap_cert_file_t cert_raw; /// Raw certs data
} DAP_ALIGN_PACKED dap_chain_wallet_cert_t;

typedef struct dap_chain_wallet_file_hdr{
    uint64_t signature;
    uint32_t version;
    uint8_t type; /// Wallets storage type 0x00 - uncompressed and unencrypted
    uint64_t padding;
} DAP_ALIGN_PACKED dap_chain_wallet_file_hdr_t;

typedef struct dap_chain_wallet_file
{
    dap_chain_wallet_file_hdr_t header;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_chain_wallet_file_t;

typedef struct dap_chain_wallet_internal
{
    dap_chain_addr_t *addr;
    char * file_name;
    size_t certs_count;
    dap_cert_t ** certs;
} dap_chain_wallet_internal_t;

#define DAP_CHAIN_WALLET_INTERNAL(a) (a ? (dap_chain_wallet_internal_t *) a->_internal : NULL)

#define DAP_CHAIN_WALLET_INTERNAL_LOCAL(a) dap_chain_wallet_internal_t * l_wallet_internal = DAP_CHAIN_WALLET_INTERNAL(a)

#define DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(a) dap_chain_wallet_internal_t * l_wallet_internal = DAP_NEW_Z(dap_chain_wallet_internal_t); a->_internal = l_wallet_internal
