/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_hashtree_roots.h"

#define DAP_CHAIN_BLOCK_SIGNATURE 0xDA05BF8E

#define DAP_CHAIN_BLOCK_ID_SIZE 4

typedef union dap_chain_block_typeid{
    uint8_t data[DAP_CHAIN_BLOCK_ID_SIZE];
} DAP_ALIGN_PACKED dap_chain_block_typeid_t;

/**
  * @struct dap_chain_block_hdr
  * @brief Block header
  */
typedef struct dap_chain_block_hdr{
   uint32_t signature; /// @param signature @brief Magic number, always equels to DAP_CHAIN_BLOCK_SIGNATURE
   int32_t version; /// @param version @brief block version (be carefull, signed value, as Bitcoin has)
   dap_chain_cell_id_t cell_id; /// Cell id
   uint32_t size_ex_signs; /// @param size of the whole block except signatures meta
   dap_chain_time_t ts_created; /// @param timestamp @brief Block create time timestamp
   uint16_t meta_count; // Meta values number
   uint16_t datum_count; // Datums's count
} DAP_ALIGN_PACKED dap_chain_block_hdr_t;

// Metadata item
typedef struct dap_chain_block_meta{
    uint8_t type; /// Meta type
    uint16_t size;   /// Data size trailing the section
    byte_t data[]; /// Section's data
} DAP_ALIGN_PACKED dap_chain_block_meta_t;

// Section with datum
typedef struct  dap_chain_block_datum{
    uint32_t size_t;
    dap_chain_datum_t datum;
}DAP_ALIGN_PACKED dap_chain_block_datum_t;

/**
 * @struct dap_chain_block
 * @brief The dap_chain_block struct
 */
typedef struct  dap_chain_block{
    dap_chain_block_hdr_t hdr;
    uint8_t meta_n_datum_n_sign[]; // Here are: metadata, datum sections and verificator signatures
} DAP_ALIGN_PACKED dap_chain_block_t;

// Init module
int dap_chain_block_init();
// Deinit module
void dap_chain_block_deinit();

// Create new block
dap_chain_block_t * dap_chain_block_new(dap_chain_hash_fast_t * a_prev_block );

// Add datum in block
dap_chain_datum_t * dap_chain_block_datum_add(dap_chain_block_t * a_block, dap_chain_datum_t * a_datum, size_t a_datum_size);
void dap_chain_block_datum_del_by_hash(dap_chain_block_t * a_block, dap_chain_hash_fast_t* a_datum_hash);
