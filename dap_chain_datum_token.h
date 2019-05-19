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
        uint16_t signs_valid; // Emission auth signs
        uint16_t signs_total; // Emission auth signs
    } DAP_ALIGN_PACKED header;
    uint8_t signs[]; // Signs if exists

} DAP_ALIGN_PACKED dap_chain_datum_token_t;


#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH              0x01
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO              0x02
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER        0x03
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT    0x04
// Token emission
typedef struct dap_chain_datum_token_emission{
    struct  {
        uint8_t version;
        uint8_t type; // Emission Type
        char ticker[10];
        dap_chain_addr_t address; // Emission holder's address
        uint64_t value;
    } DAP_ALIGN_PACKED hdr;
    union {
        struct {
            dap_chain_addr_t addr;
            int flags;
            uint64_t lock_time;
        } DAP_ALIGN_PACKED type_smart_contract;
        struct {
            uint64_t value_start;// Default value. Static if nothing else is defined
            char value_change_algo_codename[32];
        } DAP_ALIGN_PACKED type_atom_owner;
        struct {
            char codename[32];
        } DAP_ALIGN_PACKED type_algo;
        struct {
            uint16_t signs_count;
            uint8_t  signs[];
        } DAP_ALIGN_PACKED type_auth;// Signs if exists
    } data;
} DAP_ALIGN_PACKED dap_chain_datum_token_emission_t;

