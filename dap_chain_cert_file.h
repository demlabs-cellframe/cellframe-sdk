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
#include "dap_chain_cert.h"

// Magic .dapcert signature
#define DAP_CHAIN_CERT_FILE_HDR_SIGN 0x0F300C4711E29380
#define DAP_CHAIN_CERT_FILE_VERSION 1

// Default certificate with private key and optionaly some signs
#define DAP_CHAIN_CERT_FILE_TYPE_PRIVATE 0x00
// Default certificate with public key and optionaly some signs
#define DAP_CHAIN_CERT_FILE_TYPE_PUBLIC 0xf0


typedef struct dap_chain_cert_file_hdr
{
    uint64_t sign;
    int version;
    uint8_t type;
    dap_chain_sign_type_t sign_type;
    uint64_t data_size;
    uint64_t data_pvt_size;
    uint64_t inheritor_size;
    time_t ts_last_used;
} DAP_ALIGN_PACKED dap_chain_cert_file_hdr_t;

typedef struct dap_chain_cert_file{
    dap_chain_cert_file_hdr_t hdr;
    uint8_t data[];
}DAP_ALIGN_PACKED dap_chain_cert_file_t;

int dap_chain_cert_file_save(dap_chain_cert_t * a_cert, const char * a_cert_file_path);
dap_chain_cert_t* dap_chain_cert_file_load(const char * a_cert_file_path);
