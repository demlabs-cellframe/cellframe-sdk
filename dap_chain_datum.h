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
#define dap_chain_datum_END                 0x0000
/// Section with additional roots, for example transaction roots
#define dap_chain_datum_hashtree_roots 0x0001

/// Transaction header section
#define DAP_CHAIN_DATUM_TX                  0x0100

/// Transaction request section
#define DAP_CHAIN_DATUM_TX_REQUEST          0x0300

/// Smart contract: DVM code section
#define DAP_CHAIN_DATUM_DVM_CODE            0x0900
/// Smart contract: DVM code section
#define DAP_CHAIN_DATUM_DVM_DATA            0x0901

/// Smart contract: EVM code section
#define DAP_CHAIN_DATUM_EVM_CODE            0x0910

/// Smart contract: EVM data section
#define DAP_CHAIN_DATUM_EVM_DATA            0x0911

/// Pub key section, with sign and address
#define DAP_CHAIN_DATUM_PKEY                0x0c00


/// Token
#define DAP_CHAIN_DATUM_TOKEN                0xf000
#define DAP_CHAIN_DATUM_TOKEN_EMISSION       0xf100


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
        uint8_t version_id; /// Datum version
        uint16_t type_id; /// Section type id
        uint32_t data_size; /// Data section size
        uint64_t ts_create; /// Create timestamp (GM time)
    } DAP_ALIGN_PACKED header;
    uint8_t data[]; // datum stored data goes after the last sign
                               // Sign block goes after the last hash, every sign type
                              // has its own predefined size or stores its inside.
                              // After signs goes data block and and till the end of datum.
} DAP_ALIGN_PACKED dap_chain_datum_t;

struct dap_chain;
typedef struct dap_chain dap_chain_t;

typedef struct dap_chain_datum_iter{
    dap_chain_t * chain;
    dap_chain_datum_t * cur;
} dap_chain_datum_iter_t;

typedef dap_chain_datum_iter_t* (*dap_chain_datum_callback_iter_create_t)(dap_chain_t * );
typedef dap_chain_datum_t* (*dap_chain_datum_callback_iter_get_first_t)(dap_chain_datum_iter_t * );
typedef dap_chain_datum_t* (*dap_chain_datum_callback_iter_get_next_t)(dap_chain_datum_iter_t *  );
typedef void (*dap_chain_datum_callback_iter_delete_t)(dap_chain_datum_iter_t *  );


size_t dap_chain_datum_data_size(dap_chain_datum_t * a_datum);

dap_chain_datum_t * dap_chain_datum_create(uint16_t a_type_id, const void * a_data, size_t a_data_size);
