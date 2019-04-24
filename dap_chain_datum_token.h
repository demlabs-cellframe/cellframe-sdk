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
#include "dap_chain_sign.h"

// Token declaration
typedef struct dap_chain_datum_token{
    struct {
        uint16_t version;
        char ticker[10];
        uint64_t total_supply;
        uint16_t signs_number; // Emission auth signs
    } DAP_ALIGN_PACKED header;
    uint8_t signs[]; // Signs if exists
} DAP_ALIGN_PACKED dap_chain_datum_token_t;

// Token emission
typedef struct dap_chain_datum_token_emission{
    uint16_t version;
    char ticker[10];
    dap_chain_addr_t address; // Emission holder's address
    uint64_t value;
} DAP_ALIGN_PACKED dap_chain_datum_token_emission_t;


//
void dap_chain_datum_token_register(dap_chain_datum_token_t * a_token);
dap_chain_sign_t * dap_chain_datum_token_get_sign( dap_chain_datum_token_t * a_token, size_t a_token_size_max, uint16_t a_sign_number);

dap_chain_datum_token_t* dap_chain_datum_token_find_by_ticker(const char a_ticker[10] );
dap_chain_datum_token_t* dap_chain_datum_token_find_by_hash(dap_chain_hash_fast_t * a_hash );
