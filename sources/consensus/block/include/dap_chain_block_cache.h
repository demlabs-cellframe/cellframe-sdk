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
#include "dap_chain_block.h"
#include "dap_hash.h"

typedef struct dap_chain_block_cache{
    dap_chain_hash_t block_hash;
    uint32_t sections_size;

    double block_mine_time;
    dap_chain_block_t * block;
} dap_chain_block_cache_t;

dap_chain_block_cache_t * dap_chain_block_cache_new(dap_chain_block_t * a_block);
void dap_chain_block_cache_delete(dap_chain_block_cache_t * a_block_cache);
dap_chain_block_t* dap_chain_block_cache_sections_size_grow(dap_chain_block_cache_t * a_block_cache,size_t a_sections_size_grow );

void dap_chain_block_cache_dump(dap_chain_block_cache_t * a_block_cache);
