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

/// CA with public key and self signed metadata
#define DAP_CHAIN_DATUM_CA                  0x0c00

/// Token
/// Simple token decl
#define DAP_CHAIN_DATUM_TOKEN_DECL           0xf000
#define DAP_CHAIN_DATUM_TOKEN_EMISSION       0xf100
#define DAP_CHAIN_DATUM_TOKEN_DISMISSAL      0xf200

#define DAP_CHAIN_DATUM_CUSTOM               0xffff

#define DAP_DATUM_TYPE_STR(t, s)                \
    switch (t) {                            \
        case DAP_CHAIN_DATUM_TX:            \
            s = "DATUM_TX"; break;          \
        case DAP_CHAIN_DATUM_TX_REQUEST:    \
            s = "DATUM_WASM_CODE"; break;   \
        case DAP_CHAIN_DATUM_WASM_CODE:     \
            s = "DATUM_WASM_CODE"; break;   \
        case DAP_CHAIN_DATUM_WASM_DATA:     \
            s = "DATUM_WASM_DATA"; break;   \
        case DAP_CHAIN_DATUM_EVM_CODE:      \
            s = "DATUM_EVM_CODE"; break;    \
        case DAP_CHAIN_DATUM_EVM_DATA:      \
            s = "DATUM_EVM_DATA"; break;    \
        case DAP_CHAIN_DATUM_CA:            \
            s = "DATUM_CA"; break;          \
        case DAP_CHAIN_DATUM_CUSTOM:        \
            s = "DATUM_CUSTOM"; break;      \
        case DAP_CHAIN_DATUM_TOKEN_DECL:    \
            s = "DATUM_TOKEN_DECL"; break;  \
        case DAP_CHAIN_DATUM_TOKEN_EMISSION:\
            s = "DATUM_TOKEN_EMISSION"; break;\
        default:                            \
            s = "DATUM_UNKNOWN"; break;     \
}

#define DAP_CHAIN_DATUM_ID_SIZE 2

// Datum subchain type id
typedef union dap_chain_datum_typeid{
    uint8_t data[DAP_CHAIN_DATUM_ID_SIZE];
    uint16_t uint16;
} DAP_ALIGN_PACKED dap_chain_datum_typeid_t;


/**
  * @struct dap_chain_block_section
  * @brief section inside the block
  */
typedef struct dap_chain_datum{
    struct{
        /// Datum version
        uint8_t version_id;
        /// Datum type id
        uint16_t type_id;
        /// Data section size
        uint32_t data_size;
        /// Create timestamp (GM time)
        uint64_t ts_create;
    } DAP_ALIGN_PACKED header;
    byte_t data[]; /// Stored datum body
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


/**
 * @brief dap_chain_datum_size
 * @param a_datum
 * @return
 */
static inline size_t dap_chain_datum_size(dap_chain_datum_t * a_datum)
{
    if(!a_datum)
        return 0;
    return  sizeof(a_datum->header) + a_datum->header.data_size;
}

dap_chain_datum_t * dap_chain_datum_create(uint16_t a_type_id, const void * a_data, size_t a_data_size);


static inline const char *dap_chain_datum_type_id_to_str(uint16_t a_type_id)
{
    const char * l_ret;
    DAP_DATUM_TYPE_STR(a_type_id,l_ret);
    return l_ret;
}
