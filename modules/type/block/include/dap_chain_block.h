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
#include <stdalign.h>
#include <stdint.h>
#include <stddef.h>
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
 * @brief The dap_chain_block struct
 */
typedef struct  dap_chain_block{
     struct block_header{
        uint32_t signature; /// @param signature @brief Magic number, always equels to DAP_CHAIN_BLOCK_SIGNATURE
        int32_t version; /// @param version @brief block version (be carefull, signed value, as Bitcoin has)
        uint32_t size; /// @param size of the whole block
        uint64_t timestamp; /// @param timestamp @brief Block create time timestamp
        uint64_t difficulty; /// difficulty level
        uint64_t nonce; /// Nonce value to allow header variation for mining
        union{
            struct{ // Zero-level block without sharding
                dap_chain_hash_t prev_block; /// @param prev_block Hash of the previous block
                dap_chain_hash_t padding0; //
            uint32_t padding1; //
            uint64_t padding2; // Always zero (should be well compresed)
            };
            struct{
                dap_chain_hash_t prev_block_0lvl; /// @param prev_block Hash of the previous block
                dap_chain_hash_t prev_block_shard; /// @param prev_block Hash of the previous block
            uint32_t shard_id; // Shard id
            uint64_t nonce2; // Second NonCE for block mining inside the shard
            };
        };
        dap_chain_hash_t root_sections;/// @param root_main Main tree's root for all sections's hashes
    } DAP_ALIGN_PACKED header;
    uint8_t datums[]; // Sections
} DAP_ALIGN_PACKED dap_chain_block_t;

int dap_chain_block_init();
void dap_chain_block_deinit();

dap_chain_block_t * dap_chain_block_new(dap_chain_hash_t * a_prev_block );

dap_chain_datum_t * dap_chain_block_create_section(dap_chain_block_t * a_block, uint32_t a_section_offset
                                                     , uint16_t a_section_type, uint32_t a_section_data_size );


/**
 * @brief dap_chain_block_calc_hash
 * @param a_block
 * @return
 */
static inline void dap_chain_block_hash_calc(dap_chain_block_t * a_block, dap_chain_hash_t * a_hash){
    dap_hash(a_block,a_block->header.size,a_hash->raw,
             sizeof(a_hash->raw),DAP_HASH_TYPE_SLOW_0);
}

