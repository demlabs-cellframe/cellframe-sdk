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
#include "dap_common.h"
#include "dap_list.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_token.h"
#include "dap_chain_datum_tx_items.h"

// Checks the emission of the token, usualy on zero chain
#define DAP_CHAIN_UTXO_CHECK_TOKEN_EMISSION       0x0001

// Check double spending in local cell
#define DAP_CHAIN_UTXO_CHECK_LOCAL_DS           0x0002

// Check the double spending  in all cells
#define DAP_CHAIN_UTXO_CHECK_CELLS_DS          0x0100




int dap_chain_utxo_init( uint16_t a_check_flags);

// Load utxo from mempool
int dap_chain_utxo_load(const char *a_net_name, const char *a_chain_name);

void dap_chain_utxo_set_local_cell_id ( dap_chain_cell_id_t a_local_cell_id);

dap_chain_hash_fast_t* dap_chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *a_tx);


/**
 * Add new transaction to the cache
 *
 * return 1 OK, -1 error
 */
int dap_chain_utxo_tx_add(dap_chain_datum_tx_t *a_tx);


/**
 * Add new token datum
 *
 */

int dap_chain_utxo_token_add(dap_chain_datum_token_t *a_token, size_t a_token_size);

/**
 * Add token emission datum
 */
int dap_chain_utxo_token_emission_add(const dap_chain_datum_token_emission_t *a_token_emission, size_t a_token_emission_size);

dap_chain_datum_token_emission_t * dap_chain_utxo_token_emission_find(const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash);

const char* dap_chain_utxo_tx_get_token_ticker_by_hash(dap_chain_hash_fast_t *tx_hash);

void dap_chain_utxo_addr_get_token_ticker_all(dap_chain_addr_t * a_addr, char *** a_tickers, size_t * a_tickers_size );

// Checking a new transaction before adding to the cache
int dap_chain_utxo_tx_cache_check(dap_chain_datum_tx_t *a_tx, dap_list_t **a_list_bound_items);

int dap_chain_node_datum_tx_cache_check(dap_chain_datum_tx_t *a_tx, dap_list_t **a_list_bound_items);



/**
 * Delete transaction from the cache
 *
 * return 1 OK, -1 error, -2 tx_hash not found
 */
int dap_chain_utxo_tx_remove(dap_chain_hash_fast_t *tx_hash);

/**
 * Delete all transactions from the cache
 */
void dap_chain_utxo_purge(void);

/**
 * Return number transactions from the cache
 */
_dap_int128_t dap_chain_utxo_count(void);

/**
 * Check whether used 'out' items
 */
bool dap_chain_utxo_tx_hash_is_used_out_item(dap_chain_hash_fast_t *a_tx_hash, int a_idx_out);

/**
 * Calculate balance of addr
 *
 */
uint64_t dap_chain_utxo_calc_balance(const dap_chain_addr_t *a_addr,const char *a_token_ticker);


/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
const dap_chain_datum_tx_t* dap_chain_utxo_tx_find_by_hash(dap_chain_hash_fast_t *tx_hash);

// Get the transaction in the cache by the addr in out item
const dap_chain_datum_tx_t* dap_chain_utxo_tx_find_by_addr(const dap_chain_addr_t *a_addr,
        dap_chain_hash_fast_t *a_tx_first_hash);



// Get the transaction in the cache by the public key that signed the transaction, starting with a_tx_first_hash
const dap_chain_datum_tx_t* dap_chain_utxo_tx_find_by_pkey(char *a_public_key, size_t a_public_key_size,
        dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache with the out_cond item
const dap_chain_datum_tx_t* dap_chain_utxo_tx_cache_find_out_cond(dap_chain_addr_t *a_addr,
        dap_chain_hash_fast_t *a_tx_first_hash);

// Get the value from all transactions in the cache with out_cond item
uint64_t dap_chain_utxo_tx_cache_get_out_cond_value(dap_chain_addr_t *a_addr,
        dap_chain_tx_out_cond_t **tx_out_cond);
