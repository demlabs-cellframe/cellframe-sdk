/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017
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
#include "dap_chain_datum_tx.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "uthash.h"
#include "dap_chain_ledger.h"

typedef struct dap_chain_cs_blocks dap_chain_cs_blocks_t;

typedef struct dap_chain_block_cache {
    // Block's general non-nested attributes
    dap_chain_hash_fast_t block_hash;
    char* block_hash_str;
    size_t block_size;
    uint64_t block_number;

    // Local platform values representation
    time_t ts_created;

    // Block's datums
    size_t datum_count;
    dap_chain_datum_t ** datum;
    dap_hash_fast_t *datum_hash;

    // Extracted metadata
    dap_chain_hash_fast_t prev_hash;
    dap_chain_hash_fast_t anchor_hash;
    dap_chain_hash_fast_t merkle_root;
    dap_chain_hash_fast_t* links_hash;
    size_t links_hash_count;
    uint64_t nonce;
    uint64_t nonce2;
    bool is_genesis;

    // Block's signatures
    size_t sign_count; // Number of signatures in block's tail
    //dap_sign_t **sign; // Pointer to signatures in block

    // Pointer to block itself
    dap_chain_block_t * block;

    // Links to prev and next block
    struct dap_chain_block_cache * prev;
    struct dap_chain_block_cache * next;

    // uthash handle
    UT_hash_handle hh;
} dap_chain_block_cache_t;

int dap_chain_block_cache_init();
void dap_chain_block_cache_deinit();


dap_chain_block_cache_t *dap_chain_block_cache_new(dap_hash_fast_t *a_block_hash, dap_chain_block_t *a_block,
                                                   size_t a_block_size, uint64_t a_block_number, bool a_copy_block);
dap_chain_block_cache_t *dap_chain_block_cache_dup(dap_chain_block_cache_t *a_block);
int dap_chain_block_cache_update(dap_chain_block_cache_t *a_block_cache, dap_hash_fast_t *a_block_hash);
void dap_chain_block_cache_delete(dap_chain_block_cache_t *a_block_cache);

// Get the list of 'out_cond' items from previous transactions with summary out value. Put this summary value to a_value_out
dap_list_t * dap_chain_block_get_list_tx_cond_outs_with_val(dap_ledger_t *a_ledger,dap_chain_block_cache_t * a_block_cache,uint256_t *a_value_out);


