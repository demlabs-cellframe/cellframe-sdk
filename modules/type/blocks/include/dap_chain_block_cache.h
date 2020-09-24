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
#include "dap_chain_block.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "uthash.h"

typedef struct dap_chain_block_cache{
    // Block's general non-nested attributes
    dap_chain_hash_fast_t block_hash;
    size_t block_size;

    // Block's datums
    uint32_t datum_count;
    dap_chain_datum_t ** datum;

    // Block's metadatas
    uint32_t meta_count;
    dap_chain_block_meta_t** meta;

    // Block's signatures
    size_t sign_count; // Number of signatures in block's tail
    dap_sign_t ** sign; // Pointer to signatures in block

    // Pointer to block itself
    dap_chain_block_t * block;

    // Inhertied nested data
    void * _inheritor;

    // uthash handle
    UT_hash_handle hh;
} dap_chain_block_cache_t;

int dap_chain_block_cache_init();
void dap_chain_block_cache_deinit();

dap_chain_block_cache_t * dap_chain_block_cache_new(dap_chain_block_t * a_block, size_t a_block_size);
void dap_chain_block_cache_update(dap_chain_block_cache_t * a_block_cache);
void dap_chain_block_cache_delete(dap_chain_block_cache_t * a_block_cache);
