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
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_list.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in_ems.h"
#include "dap_chain_datum_tx_items.h"

typedef struct dap_ledger {
    char *net_name;
    dap_chain_net_id_t net_id;
    void *_internal;
} dap_ledger_t;

/**
 * @brief Error codes for accepting a transaction to the ledger.
 */
typedef enum dap_chain_ledger_tx_check{
    DAP_CHAIN_LEDGER_TX_CHECK_OK = 0,
    DAP_CHAIN_LEDGER_TX_CHECK_NULL_TX,
    DAP_CHAIN_LEDGER_TX_CHECK_INVALID_TX_SIZE,
    DAP_CHAIN_LEDGER_TX_ALREADY_CACHED,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NULL_TX,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_INVALID_TX_SIGN,
    DAP_CHAIN_LEDGER_TX_CACHE_IN_EMS_ALREADY_USED,
    DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_IN_EMS_ALREADY_USED,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_EMISSION_NOT_FOUND,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TX_NO_VALID_INPUTS,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TICKER_NOT_FOUND,
    DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_INVALID_TOKEN,
    DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS,
    DAP_CHAIN_LEDGER_TX_CACHE_MULT256_OVERFLOW_EMS_LOCKED_X_RATE,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS,
    DAP_CHAIN_LEDGER_TX_CACHE_NO_OUT_ITEMS_FOR_BASE_TX,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_TOKEN_EMS_VALUE_EXEEDS_CUR_SUPPLY,
    DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_UNEXPECTED_VALUE,
    DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_TICKER_NOT_FOUND,
    DAP_CHAIN_LEDGER_TX_CACHE_STAKE_LOCK_OTHER_TICKER_EXPECTED,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_OUT_ITEM_ALREADY_USED,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TX_NOT_FOUND,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ITEM_NOT_FOUND,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PKEY_HASHES_DONT_MATCH,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_NO_VERIFICATOR_SET,
    DAP_CHAIN_LEDGER_TX_CACHE_VERIFICATOR_CHECK_FAILURE,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TICKER_NOT_FOUND,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TOKEN_NOT_FOUND,
    DAP_CHAIN_LEDGER_PERMISSION_CHECK_FAILED,
    DAP_CHAIN_LEDGER_TX_CACHE_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS,
    /* add custom codes here */

    DAP_CHAIN_LEDGER_TX_CHECK_UNKNOWN /* MAX */
} dap_chain_ledger_tx_check_t;

typedef enum dap_chain_ledger_emission_err{
    DAP_CHAIN_LEDGER_EMISSION_ADD_OK = 0,
    DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_IS_NULL,
    DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_EMS_ALREADY_CACHED,
    DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_THRESHOLD_OVERFLOW,
    DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_VALUE_EXEEDS_CURRENT_SUPPLY,
    DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_NOT_ENOUGH_VALID_SIGNS,
    DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_CANT_FIND_DECLARATION_TOKEN,
    DAP_CHAIN_LEDGER_EMISSION_ADD_CHECK_ZERO_VALUE,
    DAP_CHAIN_LEDGER_EMISSION_ADD_TSD_CHECK_FAILED,
    /* add custom codes here */
    DAP_CHAIN_LEDGER_EMISSION_ADD_MEMORY_PROBLEM,
    DAP_CHAIN_LEDGER_EMISSION_ADD_UNKNOWN /* MAX */
} dap_chain_ledger_emission_err_code_t;

typedef enum dap_chain_ledger_token_decl_add_err{
    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_OK = 0,
    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_LEDGER_IS_NULL,
    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_DECL_DUPLICATE,
    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_CHECK,
    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOKEN_UPDATE_ABSENT_TOKEN,
    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_NOT_ENOUGH_VALID_SIGN,
    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_ERR_TOTAL_SIGNS_EXCEED_UNIQUE_SIGNS,
    /* add custom codes here */

    DAP_CHAIN_LEDGER_TOKEN_DECL_ADD_UNKNOWN /* MAX */
} dap_chain_ledger_token_decl_add_err_t;

typedef bool (*dap_chain_ledger_verificator_callback_t)(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_tx_out_cond, dap_chain_datum_tx_t *a_tx_in, bool a_owner);
typedef void (*dap_chain_ledger_updater_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_t *a_prev_cond);
typedef void (* dap_chain_ledger_tx_add_notify_t)(void *a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx);
typedef void (* dap_chain_ledger_bridged_tx_notify_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg);
typedef bool (*dap_chain_ledger_cache_tx_check_callback_t)(dap_hash_fast_t *a_tx_hash);
typedef struct dap_chain_net dap_chain_net_t;
typedef void (*dap_chain_ledger_voting_callback_t)(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx);
//Change this UUID to automatically reload ledger cache on next node startup
#define DAP_CHAIN_LEDGER_CACHE_RELOAD_ONCE_UUID "0c92b759-a565-448f-b8bd-99103dacf7fc"

// Checks the emission of the token, usualy on zero chain
#define DAP_CHAIN_LEDGER_CHECK_TOKEN_EMISSION    0x0001

// Check double spending in local cell
#define DAP_CHAIN_LEDGER_CHECK_LOCAL_DS          0x0002

// Check the double spending in all cells
#define DAP_CHAIN_LEDGER_CHECK_CELLS_DS          0x0100

#define DAP_CHAIN_LEDGER_CACHE_ENABLED           0x0200

// Error code for no previous transaction (for stay in mempool)
#define DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS  DAP_CHAIN_LEDGER_TX_CACHE_CHECK_PREV_TX_NOT_FOUND
// Error code for no emission for a transaction (for stay in mempoold)
#define DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION  DAP_CHAIN_LEDGER_TX_CACHE_CHECK_EMISSION_NOT_FOUND
// Error code for no decree for anchor (for stay in mempool)
#define DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE       -1113

#define DAP_CHAIN_LEDGER_TOKENS_STR              "tokens"
#define DAP_CHAIN_LEDGER_EMISSIONS_STR           "emissions"
#define DAP_CHAIN_LEDGER_STAKE_LOCK_STR          "stake_lock"
#define DAP_CHAIN_LEDGER_TXS_STR                 "txs"
#define DAP_CHAIN_LEDGER_SPENT_TXS_STR           "spent_txs"
#define DAP_CHAIN_LEDGER_BALANCES_STR            "balances"

int dap_chain_ledger_init();
void dap_chain_ledger_deinit();

dap_ledger_t *dap_chain_ledger_create(uint16_t a_flags, dap_chain_net_id_t a_net_id, char *a_net_name, const char *a_net_native_ticker, dap_list_t *a_poa_certs);

void dap_chain_ledger_set_fee(dap_ledger_t *a_ledger, uint256_t a_fee, dap_chain_addr_t a_fee_addr);

// Remove dap_ledger_t structure
void dap_chain_ledger_handle_free(dap_ledger_t *a_ledger);

// Load ledger from mempool
//int dap_chain_ledger_load(const char *a_net_name, const char *a_chain_name);

void dap_chain_ledger_set_local_cell_id(dap_ledger_t *a_ledger, dap_chain_cell_id_t a_local_cell_id);

/**
 * @brief dap_chain_node_datum_tx_calc_hash
 * @param a_tx
 * @return
 */
DAP_STATIC_INLINE dap_chain_hash_fast_t* dap_chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *a_tx)
{
    dap_chain_hash_fast_t *tx_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
    if (!tx_hash) {
        return NULL;
    }
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), tx_hash);
    return tx_hash;
}

DAP_STATIC_INLINE char *dap_chain_ledger_get_gdb_group(dap_ledger_t *a_ledger, const char *a_suffix)
{
    return a_ledger && a_ledger->net_name && a_suffix
            ? dap_strdup_printf("local.ledger-cache.%s.%s", a_ledger->net_name, a_suffix)
            : NULL;
}

/**
 * Add new transaction to the cache
 *
 * return 1 OK, -1 error
 */
int dap_chain_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold);
int dap_chain_ledger_tx_load(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash);


int dap_chain_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, size_t a_datum_size, dap_hash_fast_t *a_datum_hash);

char* dap_chain_ledger_tx_check_err_str(int a_code);

/**
 * Print list transaction from ledger
 *
 */

char * dap_ledger_token_tx_item_list(dap_ledger_t * a_ledger, dap_chain_addr_t *a_addr, const char *a_hash_out_type, bool a_unspent_only);

/**
 * Check token ticker existance
 *
 */

dap_chain_datum_token_t *dap_chain_ledger_token_ticker_check(dap_ledger_t * a_ledger, const char *a_token_ticker);

/**
 * Add new token datum
 *
 */

int dap_chain_ledger_token_add(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size);
int dap_chain_ledger_token_load(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size);
int dap_chain_ledger_token_decl_add_check(dap_ledger_t *a_ledger, dap_chain_datum_token_t *a_token, size_t a_token_size);
char *dap_chain_ledger_token_decl_add_err_code_to_str(int a_code);
dap_list_t *dap_chain_ledger_token_info(dap_ledger_t *a_ledger);

// Get all token-declarations
dap_list_t* dap_chain_ledger_token_decl_all(dap_ledger_t *a_ledger);

dap_string_t *dap_chain_ledger_threshold_info(dap_ledger_t *a_ledger);
dap_string_t *dap_chain_ledger_threshold_hash_info(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *l_tx_treshold_hash);
dap_string_t *dap_chain_ledger_balance_info(dap_ledger_t *a_ledger);

size_t dap_chain_ledger_token_auth_signs_valid(dap_ledger_t *a_ledger, const char * a_token_ticker);
size_t dap_chain_ledger_token_auth_signs_total(dap_ledger_t *a_ledger, const char * a_token_ticker);
dap_list_t * dap_chain_ledger_token_auth_pkeys_hashes(dap_ledger_t *a_ledger, const char * a_token_ticker);

/**
 * Add token emission datum
 */
int dap_chain_ledger_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size,
                                        dap_hash_fast_t *a_emission_hash, bool a_from_threshold);
int dap_chain_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_hash_fast_t *a_token_emission_hash);
char *dap_chain_ledger_token_emission_err_code_to_str(int a_code);

// Check if it addable
int dap_chain_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_chain_hash_fast_t *a_emission_hash);

/* Add stake-lock item */
int dap_chain_ledger_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash);

dap_chain_datum_token_emission_t *dap_chain_ledger_token_emission_find(dap_ledger_t *a_ledger,
        const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash);

const char* dap_chain_ledger_tx_get_token_ticker_by_hash(dap_ledger_t *a_ledger,dap_chain_hash_fast_t *a_tx_hash);

void dap_chain_ledger_addr_get_token_ticker_all_depricated(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size);

void dap_chain_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size);

bool dap_chain_ledger_tx_poa_signed(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx);

// Checking a new transaction before adding to the cache
int dap_chain_ledger_tx_cache_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash,
                                    bool a_from_threshold, dap_list_t **a_list_bound_items, dap_list_t **a_list_tx_out, char **a_main_ticker);

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
void dap_chain_ledger_set_tps_start_time(dap_ledger_t *a_ledger);

/**
 * Check whether used 'out' items
 */
bool dap_chain_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out, dap_hash_fast_t *a_out_spender);

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
dap_chain_datum_tx_t* dap_chain_ledger_tx_spent_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash);
dap_hash_fast_t *dap_chain_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash);

 // Get the transaction in the cache by the addr in out item
dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_addr(dap_ledger_t *a_ledger, const char * a_token,
         const dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache by the public key that signed the transaction, starting with a_tx_first_hash
const dap_chain_datum_tx_t* dap_chain_ledger_tx_find_by_pkey(dap_ledger_t *a_ledger,
        char *a_public_key, size_t a_public_key_size, dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache with the out_cond item
dap_chain_datum_tx_t* dap_chain_ledger_tx_cache_find_out_cond(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type,
                                                              dap_chain_hash_fast_t *a_tx_first_hash, dap_chain_tx_out_cond_t **a_out_cond,
                                                              int *a_out_cond_idx, char *a_token_ticker);

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

// Add new verificator callback with associated subtype. Returns 1 if callback replaced, overwise returns 0
int dap_chain_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype, dap_chain_ledger_verificator_callback_t a_callback,
                                     dap_chain_ledger_updater_callback_t a_callback_added);

// Add new verificator callback for voting. Returns 1 if callback replaced, overwise returns 0
int dap_chain_ledger_voting_verificator_add(dap_chain_ledger_voting_callback_t a_callback);

// Getting a list of transactions from the ledger.
dap_list_t * dap_chain_ledger_get_txs(dap_ledger_t *a_ledger, size_t a_count, size_t a_page, bool a_reverse, bool a_unspent_only);

//bool dap_chain_ledger_fee_verificator(dap_ledger_t* a_ledger, dap_chain_tx_out_cond_t* a_cond, dap_chain_datum_tx_t* a_tx, bool a_owner);

void dap_chain_ledger_tx_add_notify(dap_ledger_t *a_ledger, dap_chain_ledger_tx_add_notify_t a_callback, void *a_arg);
void dap_chain_ledger_bridged_tx_notify_add(dap_ledger_t *a_ledger, dap_chain_ledger_bridged_tx_notify_t a_callback, void *a_arg);


bool dap_chain_ledger_cache_enabled(dap_ledger_t *a_ledger);
void dap_chain_ledger_set_cache_tx_check_callback(dap_ledger_t *a_ledger, dap_chain_ledger_cache_tx_check_callback_t a_callback);
