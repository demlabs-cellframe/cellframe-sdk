/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

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
#ifndef _DAP_CHAIN_BLOCK_H_
#define _DAP_CHAIN_BLOCK_H_
#include <stdalign.h>
#include <stdint.h>
#include <stddef.h>
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"
#include "dap_chain_block_section.h"
#include "dap_chain_block_roots.h"

#define DAP_CHAIN_BLOCK_SIGNATURE 0xDA05BF8E


/**
 * @brief The dap_chain_block struct
 */
typedef struct  dap_chain_block{
    struct {
        uint32_t signature; /// @param signature @brief Magic number, always equels to DAP_CHAIN_BLOCK_SIGNATURE
        int32_t version; /// @param version @brief block version (be carefull, signed value, as Bitcoin has)
        dap_chain_hash_t prev_block; /// @param prev_block Hash of the previous block
        dap_chain_hash_t root_main;/// @param root_main Main tree's root for all block's hashes
        uint64_t timestamp; /// @param timestamp @brief Block create time timestamp
        uint64_t difficulty; /// difficulty level
        uint64_t nonce; /// Nonce value to allow header variation for mining
        uint32_t section_size; /// @param secion_size Size of section[] array
    } header;
    dap_chain_block_section_t section[];
} DAP_ALIGN_PACKED dap_chain_block_t;

int dap_chain_block_init();
void dap_chain_block_deinit();

#endif
