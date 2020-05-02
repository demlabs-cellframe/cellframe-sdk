/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include <stdio.h>
#include "uthash.h"
#include "dap_chain_common.h"

typedef struct dap_chain dap_chain_t;
typedef struct dap_chain_cell dap_chain_cell_t;

typedef struct dap_chain_cell {
    dap_chain_cell_id_t id;
    dap_chain_t * chain;

    char * file_storage_path;
    FILE * file_storage; /// @param file_cache @brief Cache for raw blocks
    uint8_t file_storage_type; /// @param file_storage_type  @brief Is file_storage is raw, compressed or smth else

    UT_hash_handle hh;
} dap_chain_cell_t;

/**
 *
 */
#define DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE 32
typedef struct dap_chain_cell_delc_req {
    dap_chain_addr_t wallet_address;  // Need new wallet address where the hold coins should be directed. Must have undefined cell
    uint64_t create_ts;
    union{
        uint8_t raw[DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE];
        char str[DAP_CHAIN_CELL_DECL_REQ_SIGN_SIZE];
    } info;
} DAP_ALIGN_PACKED dap_chain_cell_decl_req_t;

/**
  * @struct dap_chain_cell_decl
  * @details New cell declaration
  *
  */
#define DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE 32
typedef struct dap_chain_cell_decl{
    dap_chain_cell_decl_req_t request;
    dap_chain_cell_id_t cell_id;
    uint64_t accept_ts;
    union{
        uint8_t raw[DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE];
        char str[DAP_CHAIN_CELL_DECL_ACCEPT_INFO_SIZE];
    } accept_info;
} DAP_ALIGN_PACKED dap_chain_cell_decl_t;


int dap_chain_cell_init(void);
dap_chain_cell_t * dap_chain_cell_create(void);
dap_chain_cell_t * dap_chain_cell_create_fill(dap_chain_t * a_chain, dap_chain_cell_id_t a_cell_id);
void dap_chain_cell_delete(dap_chain_cell_t *a_cell);
int dap_chain_cell_load(dap_chain_t * a_chain, const char * a_cell_file_path);
int dap_chain_cell_file_update( dap_chain_cell_t * a_cell);
int dap_chain_cell_file_append( dap_chain_cell_t * a_cell,const void* a_atom, size_t a_atom_size);
