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

#define DAP_CHAIN_CELL_FILE_VERSION 1
#define DAP_CHAIN_CELL_FILE_SIGNATURE 0xfa340bef153eba48
#define DAP_CHAIN_CELL_FILE_TYPE_RAW 0
#define DAP_CHAIN_CELL_FILE_TYPE_COMPRESSED 1

/**
  * @struct dap_chain_cell_file_header
  */
typedef struct dap_chain_cell_file_header
{
    uint64_t signature;
    uint32_t version;
    uint8_t type;
    dap_chain_id_t chain_id;
    dap_chain_net_id_t chain_net_id;
    dap_chain_cell_id_t cell_id;
} DAP_ALIGN_PACKED dap_chain_cell_file_header_t;

typedef struct dap_chain_cell {
    dap_chain_t * chain;
    dap_chain_cell_id_t id;
    char * file_storage_path;
    FILE * file_storage; /// @param file_cache @brief Cache for raw blocks
    uint8_t file_storage_type; /// @param file_storage_type  @brief Is file_storage is raw, compressed or smth else

    UT_hash_handle hh;
} dap_chain_cell_t;

int dap_chain_cell_load_file ( dap_chain_cell_t * a_cell, const char * a_cell_file_path );
int dap_chain_cell_save_file ( dap_chain_cell_t * a_cell, const char * a_cell_file_path);
