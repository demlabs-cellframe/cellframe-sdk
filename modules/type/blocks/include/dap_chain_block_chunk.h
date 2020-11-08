/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2020
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
#include "dap_chain_block_cache.h"
#include "dap_chain_cs_blocks.h"

typedef struct dap_chain_block_chunk dap_chain_block_chunk_t;
typedef struct dap_chain_block_cache_hash{
    dap_chain_block_chunk_t * chunk;
    dap_chain_block_cache_t *block_cache;
    time_t ts_created;
    dap_chain_hash_fast_t block_hash;
    UT_hash_handle hh;
} dap_chain_block_cache_hash_t;


typedef struct dap_chain_block_chunk{
    dap_chain_block_cache_hash_t *block_cache_hash;
    dap_chain_block_cache_t *block_cache_first;
    struct dap_chain_block_chunk * prev;
    struct dap_chain_block_chunk * next;
} dap_chain_block_chunk_t;


typedef struct dap_chain_block_chunks{
    dap_chain_cs_blocks_t * blocks;

    dap_chain_block_cache_t *cache;

    dap_chain_block_chunk_t * chunks_first;
    dap_chain_block_chunk_t * chunks_last;
    char * gdb_group;
} dap_chain_block_chunks_t;

dap_chain_block_chunks_t * dap_chain_block_chunks_create(dap_chain_cs_blocks_t * a_blocks);
void dap_chain_block_chunks_delete(dap_chain_block_chunks_t * a_chunks);

dap_chain_block_cache_t * dap_chain_block_chunks_add(dap_chain_block_chunks_t * a_chunks, dap_chain_block_t *a_block ,size_t a_block_size);
