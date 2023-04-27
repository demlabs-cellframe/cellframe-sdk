/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
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
#include "dap_hash.h"
#include "dap_list.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_token.h"
#include "dap_chain_datum_tx_items.h"

typedef struct dap_ledger {
    char *net_name;
    dap_list_t *tx_add_notifiers;
    void *_internal;
} dap_ledger_t;

typedef bool (* dap_chain_ledger_verificator_callback_t)(dap_ledger_t * a_ledger, dap_hash_fast_t *a_tx_out_hash,  dap_chain_tx_out_cond_t *a_tx_out_cond,
                                                         dap_chain_datum_tx_t *a_tx_in, bool a_owner);
typedef bool (* dap_chain_ledger_verificator_callback_out_t)(dap_ledger_t * a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_cond);
typedef void (* dap_chain_ledger_tx_add_notify_t)(void *a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx);

typedef struct dap_chain_net dap_chain_net_t;
// Checks the emission of the token, usualy on zero chain
#define DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION    0x0001

// Check double spending in local cell
#define DAP_CHAIN_LEDGER_CHECK_LOCAL_DS          0x0002

// Check the double spending  in all cells
#define DAP_CHAIN_LEDGER_CHECK_CELLS_DS          0x0100

// Error code for no previous transaction (candidate to threshold)
#define DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS  -111
// Error code for no emission for a transaction (candidate to threshold)
#define DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION  -112
// Error code for no token for an emission (candidate to threshold)
#define DAP_CHAIN_CS_VERIFY_CODE_TX_NO_TOKEN     -113

#define DAP_CHAIN_LEDGER_TOKENS_STR              "tokens"
#define DAP_CHAIN_LEDGER_EMISSIONS_STR           "emissions"
#define DAP_CHAIN_LEDGER_STAKE_LOCK_STR          "stake_lock"
#define DAP_CHAIN_LEDGER_TXS_STR                 "txs"
#define DAP_CHAIN_LEDGER_SPENT_TXS_STR           "spent_txs"
#define DAP_CHAIN_LEDGER_BALANCES_STR            "balances"

int dap_chain_ledger_init();
void dap_chain_ledger_deinit();

dap_ledger_t* dap_chain_ledger_create(uint16_t a_check_flags, char *a_net_name);

// Remove dap_ledger_t structure
void dap_chain_ledger_handle_free(dap_ledger_t *a_ledger);

// Load ledger from mempool
//int dap_chain_ledger_load(const char *a_net_name, const char *a_chain_name);

void dap_chain_ledger_set_local_cell_id(dap_ledger_t *a_ledger, dap_chain_cell_id_t a_local_cell_id);

// Add new verificator callback with associated subtype. Returns 1 if callback replaced, overwise returns 0
int dap_chain_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype, dap_chain_ledger_verificator_callback_t a_callback, dap_chain_ledger_verificator_callback_out_t a_callback_added);


/**
 * @brief dap_chain_node_datum_tx_calc_hash
 * @param a_tx
 * @return
 */
DAP_STATIC_INLINE dap_chain_hash_fast_t* dap_chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *a_tx)
{
    dap_chain_hash_fast_t *tx_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), tx_hash);
    return tx_hash;
}

DAP_STATIC_INLINE char *dap_chain_ledger_get_gdb_group(dap_ledger_t *a_ledger, const char *a_suffix)
{
    return a_ledger && a_ledger->net_name && a_suffix
            ? dap_strdup_printf("local.ledger-cache.%s.%s", a_ledger->net_name, a_suffix)
            : NULL;
}

dap_chain_net_t * dap_chain_ledger_get_net(dap_ledger_t * a_ledger);

/**
 * Add new transaction to the cache
 *
 * return 1 OK, -1 error
 */
int dap_chain_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold);
int dap_chain_ledger_tx_load(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash);


int dap_chain_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx);

/**
 * Check token ticker existance
 *
 */

dap_chain_datum_token_t *dap_chain_ledger_token_ticker_check(dap_ledger_t * a_ledger, const char *a_token_ticker);

/**
 * Get list transaction
 *
 */

char * dap_ledger_token_tx_item_list(dap_ledger_t * a_ledger, dap_chain_addr_t *a_addr, const char *a_hash_out_type);

/**
 * Add new token datum
 *
 */

int dap_chain_ledger_token_add(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size);
int dap_chain_ledger_token_load(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size);
int dap_chain_ledger_token_decl_add_check(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size);
dap_list_t *dap_chain_ledger_token_info(dap_ledger_t *a_ledger);
dap_string_t *dap_chain_ledger_threshold_info(dap_ledger_t *a_ledger);
dap_string_t *dap_chain_ledger_threshold_hash_info(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *l_tx_treshold_hash);
dap_string_t *dap_chain_ledger_balance_info(dap_ledger_t *a_ledger);

// Get all token-declarations
dap_list_t* dap_chain_ledger_token_decl_all(dap_ledger_t *a_ledger);

size_t dap_chain_ledger_token_auth_signs_valid(dap_ledger_t *a_ledger, const char * a_token_ticker);
size_t dap_chain_ledger_token_auth_signs_total(dap_ledger_t *a_ledger, const char * a_token_ticker);
dap_list_t * dap_chain_ledger_token_auth_signs_hashes(dap_ledger_t *a_ledger, const char * a_token_ticker);

/**
 * Add token emission datum
 */
int dap_chain_ledger_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size,
                                        dap_hash_fast_t *a_emission_hash, bool a_from_threshold);
int dap_chain_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size);

// Check if it addable
int dap_chain_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size);

/* Add stake-lock item */
int dap_chain_ledger_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash);

dap_chain_datum_token_emission_t *dap_chain_ledger_token_emission_find(dap_ledger_t *a_ledger,
        const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash);

const char* dap_chain_ledger_tx_get_token_ticker_by_hash(dap_ledger_t *a_ledger,dap_chain_hash_fast_t *a_tx_hash);

void dap_chain_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size);

void dap_chain_ledger_addr_get_token_ticker_all_fast(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size);

// Checking a new transaction before adding to the cache
int dap_chain_ledger_tx_cache_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash,
                                    bool a_from_threshold, dap_list_t **a_list_bound_items, dap_list_t **a_list_tx_out,  char **a_main_ticker);

/**
 * Delete transaction from the cache
 *
 * return 1 OK, -1 error, -2 tx_hash not found
 */
int dap_chain_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, dap_time_t a_spent_time);

/**
 * Delete all transactions from the cache
 */
void dap_chain_ledger_purge(dap_ledger_t *a_ledger, bool a_preserve_db);

/**
 * End of load mode with no chackes for incoming datums
 */
void dap_chain_ledger_load_end(dap_ledger_t *a_ledger);

/**
 * Return number transactions from the cache
 */
unsigned dap_chain_ledger_count(dap_ledger_t *a_ledger);

uint64_t dap_chain_ledger_count_from_to(dap_ledger_t * a_ledger, dap_time_t a_ts_from, dap_time_t a_ts_to);
size_t dap_chain_ledger_count_tps(dap_ledger_t *a_ledger, struct timespec *a_ts_from, struct timespec *a_ts_to);
void dap_chain_ledger_start_tps_count(dap_ledger_t *a_ledger);

/**
 * Check whether used 'out' items
 */
bool dap_chain_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out, dap_chain_hash_fast_t *l_out_spndr_hash);

/**
 * Calculate balance of addr
 *
 */
uint256_t dap_chain_ledger_calc_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
        const char *a_token_ticker);

uint256_t dap_chain_ledger_calc_balance_full(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
            const char *a_token_ticker);

/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
 dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash);
bool dap_chain_ledger_tx_spent_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash);
dap_hash_fast_t *dap_chain_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash);

 // Get the transaction in the cache by the addr in out item
 dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_addr(dap_ledger_t *a_ledger, const char * a_token,
         const dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache by the public key that signed the transaction, starting with a_tx_first_hash
const dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_pkey(dap_ledger_t *a_ledger,
        char *a_public_key, size_t a_public_key_size, dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache with the out_cond item
dap_chain_datum_tx_t* dap_chain_ledger_tx_cache_find_out_cond(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_first_hash,
                                                              dap_chain_tx_out_cond_t **a_out_cond, int *a_out_cond_idx, char *a_token_ticker);

// Get all transactions from the cache with the specified out_cond items
dap_list_t* dap_chain_ledger_tx_cache_find_out_cond_all(dap_ledger_t *a_ledger, dap_chain_net_srv_uid_t a_srv_uid);


// Get the value from all transactions in the cache with out_cond item
uint256_t dap_chain_ledger_tx_cache_get_out_cond_value(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_addr_t *a_addr,
                                                       dap_chain_tx_out_cond_t **tx_out_cond);

// Get the list of 'out' items from previous transactions with summary value >= than a_value_need
// Put this summary value to a_value_transfer
dap_list_t *dap_chain_ledger_get_list_tx_outs_with_val(dap_ledger_t *a_ledger, const char *a_token_ticker, const dap_chain_addr_t *a_addr_from,
                                                       uint256_t a_value_need, uint256_t *a_value_transfer);
// Get the list of 'out_cond' items with summary value >= than a_value_need
dap_list_t *dap_chain_ledger_get_list_tx_cond_outs_with_val(dap_ledger_t *a_ledger, const char *a_token_ticker,  const dap_chain_addr_t *a_addr_from,
        dap_chain_tx_out_cond_subtype_t a_subtype, uint256_t a_value_need, uint256_t *a_value_transfer);


// Getting a list of transactions from the ledger.
dap_list_t * dap_chain_ledger_get_txs(dap_ledger_t *a_ledger, size_t a_count, size_t a_page, bool reverse);

void dap_chain_ledger_tx_add_notify(dap_ledger_t *a_ledger, dap_chain_ledger_tx_add_notify_t a_callback, void *a_arg);

//bool dap_chain_ledger_fee_verificator(dap_ledger_t * a_ledger,dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx, bool a_owner);
