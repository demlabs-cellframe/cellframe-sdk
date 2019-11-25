/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
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
#include "dap_math_ops.h"
#include "dap_chain_common.h"

#define DAP_CHAIN_DATUM_VERSION 0x00

/// End section, means all the rest of the block is empty
#define DAP_CHAIN_DATUM_BLOCK_END                 0x0000
/// Section with additional roots, for example transaction roots
#define DAP_CHAIN_DATUM_BLOCK_ROOTS 0x0001

/// Transaction header section
#define DAP_CHAIN_DATUM_TX                  0x0100

/// Transaction request section
#define DAP_CHAIN_DATUM_TX_REQUEST          0x0300

/// Smart contract: DVM code section
#define DAP_CHAIN_DATUM_WASM_CODE            0x0900
/// Smart contract: DVM code section
#define DAP_CHAIN_DATUM_WASM_DATA            0x0901

/// Smart contract: EVM code section
#define DAP_CHAIN_DATUM_EVM_CODE            0x0910

/// Smart contract: EVM data section
#define DAP_CHAIN_DATUM_EVM_DATA            0x0911

/// Pub key section, with sign and address
#define DAP_CHAIN_DATUM_PKEY                0x0c00


/// Token
#define DAP_CHAIN_DATUM_TOKEN_DECL                0xf000
#define DAP_CHAIN_DATUM_TOKEN_EMISSION       0xf100

static const char * c_datum_type_str[]={
    [DAP_CHAIN_DATUM_TX]="DATUM_TX",
    [DAP_CHAIN_DATUM_TX_REQUEST]="DATUM_TX_REQUEST",
    [DAP_CHAIN_DATUM_WASM_CODE]="DATUM_WASM_CODE",
    [DAP_CHAIN_DATUM_WASM_DATA]="DATUM_WASM_DATA",
    [DAP_CHAIN_DATUM_EVM_CODE]="DATUM_EVM_CODE",
    [DAP_CHAIN_DATUM_EVM_DATA]="DATUM_EVM_DATA",
    [DAP_CHAIN_DATUM_PKEY]="DATUM_PKEY",
    [DAP_CHAIN_DATUM_TOKEN_DECL]="DATUM_TOKEN_DECL",
    [DAP_CHAIN_DATUM_TOKEN_EMISSION]="DATUM_TOKEN_EMISSION",
};

#define DAP_CHAIN_DATUM_ID_SIZE 4

// Datum subchain type id
typedef union dap_chain_datum_typeid{
    uint8_t data[DAP_CHAIN_DATUM_ID_SIZE];
} DAP_ALIGN_PACKED dap_chain_datum_typeid_t;


/**
  * @struct dap_chain_block_section
  * @brief section inside the block
  */
typedef struct dap_chain_datum{
    struct{
        /// Datum version
        uint8_t version_id;
        /// Section type id
        uint16_t type_id;
        /// Data section size
        uint32_t data_size;
        /// Create timestamp (GM time)
        uint64_t ts_create;
    } DAP_ALIGN_PACKED header;
    uint8_t data[]; /// Stored datum body
} DAP_ALIGN_PACKED dap_chain_datum_t;


struct dap_chain;
typedef struct dap_chain dap_chain_t;

typedef struct dap_chain_datum_iter{
    dap_chain_t * chain;
    dap_chain_datum_t * cur;
    void * cur_item;
    void * atom_iter;
} dap_chain_datum_iter_t;

typedef dap_chain_datum_iter_t* (*dap_chain_datum_callback_iter_create_t)(dap_chain_t * );
typedef dap_chain_datum_t* (*dap_chain_datum_callback_iter_get_first_t)(dap_chain_datum_iter_t * );
typedef dap_chain_datum_t* (*dap_chain_datum_callback_iter_get_next_t)(dap_chain_datum_iter_t *  );
typedef void (*dap_chain_datum_callback_iter_delete_t)(dap_chain_datum_iter_t *  );


static inline size_t dap_chain_datum_size(dap_chain_datum_t * a_datum)
{
    if(!a_datum)
        return 0;
    return  sizeof(a_datum->header) + a_datum->header.data_size;
}

dap_chain_datum_t * dap_chain_datum_create(uint16_t a_type_id, const void * a_data, size_t a_data_size);

