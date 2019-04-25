/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
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
#include <stdbool.h>

//#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_out_cond.h"

int dap_chain_node_datum_tx_cache_init(dap_enc_key_t *a_key, const char *a_token_name, dap_chain_addr_t *a_addr,
        uint64_t a_value);

dap_chain_hash_fast_t* dap_chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *a_tx);

/**
 * Add new transaction to the cache
 *
 * return 1 OK, -1 error
 */
int dap_chain_node_datum_tx_cache_add(dap_chain_datum_tx_t *a_tx);

/**
 * Delete transaction from the cache
 *
 * return 1 OK, -1 error, -2 tx_hash not found
 */
int dap_chain_node_datum_tx_cache_del(dap_chain_hash_fast_t *tx_hash);

/**
 * Delete all transactions from the cache
 */
void dap_chain_node_datum_tx_cache_del_all(void);

/**
 * Return number transactions from the cache
 */
int dap_chain_node_datum_tx_cache_count(void);

/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find(dap_chain_hash_fast_t *tx_hash);

/**
 * Check whether used 'out' items
 */
bool dap_chain_node_datum_tx_cache_is_used_out_item(dap_chain_hash_fast_t *a_tx_hash, int a_idx_out);

/**
 * Calculate balance of addr
 *
 */
uint64_t dap_chain_datum_tx_cache_calc_balance(dap_chain_addr_t *a_addr);


// Get the transaction in the cache by the addr in 'out' item
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find_by_addr(dap_chain_addr_t *a_addr,
        dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache by the public key that signed the transaction, starting with a_tx_first_hash
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find_by_pkey(char *a_public_key, size_t a_public_key_size,
        dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache with the out_cond item
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find_out_cond(dap_chain_addr_t *a_addr,
        dap_chain_hash_fast_t *a_tx_first_hash);

uint64_t dap_chain_node_datum_tx_cache_get_out_cond_value(dap_chain_addr_t *a_addr, dap_chain_tx_out_cond_t **tx_out_cond);

