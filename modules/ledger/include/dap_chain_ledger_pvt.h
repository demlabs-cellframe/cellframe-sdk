/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024, All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_chain_ledger.h"

#define MAX_OUT_ITEMS   10

enum ledger_permissions {
    LEDGER_PERMISSION_RECEIVER_ALLOWED,
    LEDGER_PERMISSION_RECEIVER_BLOCKED,
    LEDGER_PERMISSION_SENDER_ALLOWED,
    LEDGER_PERMISSION_SENDER_BLOCKED
};

typedef struct dap_ledger_token_emission_item {
    dap_chain_hash_fast_t datum_token_emission_hash;
    dap_chain_datum_token_emission_t *datum_token_emission;
    size_t datum_token_emission_size;
    dap_chain_hash_fast_t tx_used_out;
    dap_nanotime_t ts_added;
    UT_hash_handle hh;
} dap_ledger_token_emission_item_t;

typedef struct dap_ledger_token_update_item {
    dap_hash_fast_t			update_token_hash;
    dap_chain_datum_token_t	*datum_token_update;
    size_t					datum_token_update_size;
    time_t					updated_time;
    UT_hash_handle hh;
} dap_ledger_token_update_item_t;

typedef struct dap_ledger_token_item {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint16_t subtype;
    dap_chain_datum_token_t *datum_token;
    uint64_t datum_token_size;

    uint256_t total_supply;
    uint256_t current_supply;

    pthread_rwlock_t token_emissions_rwlock;
    dap_ledger_token_emission_item_t * token_emissions;

    pthread_rwlock_t token_ts_updated_rwlock;
    dap_ledger_token_update_item_t * token_ts_updated;
    time_t last_update_token_time;

    // for auth operations
    dap_pkey_t ** auth_pkeys;
    dap_chain_hash_fast_t *auth_pkey_hashes;
    size_t auth_signs_total;
    size_t auth_signs_valid;
    uint32_t          flags;
    dap_chain_addr_t *tx_recv_allow;
    size_t            tx_recv_allow_size;
    dap_chain_addr_t *tx_recv_block;
    size_t            tx_recv_block_size;
    dap_chain_addr_t *tx_send_allow;
    size_t            tx_send_allow_size;
    dap_chain_addr_t *tx_send_block;
    size_t            tx_send_block_size;
    char *description;
    // For delegated tokens
    bool is_delegated;
    char delegated_from[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t emission_rate;

    UT_hash_handle hh;
} dap_ledger_token_item_t;

typedef struct dap_ledger_tx_out_metadata {
    dap_hash_fast_t tx_spent_hash_fast;
    dap_list_t *trackers;
} dap_ledger_tx_out_metadata_t;

// ledger cache item - one of unspent outputs
typedef struct dap_ledger_tx_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    dap_nanotime_t ts_added;
    UT_hash_handle hh;
    struct {
        dap_time_t ts_created;      // Transation datum timestamp mirrored & cached
        uint32_t n_outs;
        uint32_t n_outs_used;
        char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        byte_t multichannel;
        dap_time_t ts_spent;
        dap_chain_srv_uid_t tag; //tag (or service this tx is belong to)
        dap_chain_tx_tag_action_type_t action;
    } DAP_ALIGN_PACKED cache_data;
    dap_ledger_tx_out_metadata_t out_metadata[]; // spent outs list
} dap_ledger_tx_item_t;

typedef struct dap_ledger_stake_lock_item {
    dap_chain_hash_fast_t tx_for_stake_lock_hash;
    dap_chain_hash_fast_t tx_used_out;
    UT_hash_handle hh;
} dap_ledger_stake_lock_item_t;

typedef struct dap_ledger_reward_key {
    dap_hash_fast_t block_hash;
    dap_hash_fast_t sign_pkey_hash;
} DAP_ALIGN_PACKED dap_ledger_reward_key_t;

typedef struct dap_ledger_reward_item {
    dap_ledger_reward_key_t key;
    dap_hash_fast_t spender_tx;
    UT_hash_handle hh;
} dap_ledger_reward_item_t;

// in-memory wallet balance
typedef struct dap_ledger_wallet_balance {
    char *key;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t balance;
    UT_hash_handle hh;
} dap_ledger_wallet_balance_t;

typedef struct dap_ledger_hal_item {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_ledger_hal_item_t;

// private types definition
typedef struct dap_ledger_decree_item {
    dap_hash_fast_t decree_hash;
    bool wait_for_apply, is_applied;
    dap_chain_datum_decree_t *decree;
    dap_hash_fast_t anchor_hash;
    UT_hash_handle hh;
} dap_ledger_decree_item_t;

typedef struct dap_ledger_anchor_item {
    dap_hash_fast_t anchor_hash;
    dap_chain_datum_anchor_t *anchor;
    UT_hash_handle hh;
} dap_ledger_anchor_item_t;

// dap_ledger_t private section
typedef struct dap_ledger_private {
    // separate access to transactions
    pthread_rwlock_t ledger_rwlock;
    dap_ledger_tx_item_t *ledger_items;
    // separate access to tokens
    pthread_rwlock_t tokens_rwlock;
    dap_ledger_token_item_t *tokens;
    // separate acces to stake items
    pthread_rwlock_t stake_lock_rwlock;
    dap_ledger_stake_lock_item_t *emissions_for_stake_lock;
    // separate access to rewards
    pthread_rwlock_t rewards_rwlock;
    dap_ledger_reward_item_t *rewards;
    // separate access to balances
    pthread_rwlock_t balance_accounts_rwlock;
    dap_ledger_wallet_balance_t *balance_accounts;
    // separate access to threshold
    pthread_rwlock_t threshold_txs_rwlock;
    dap_ledger_tx_item_t *threshold_txs;
    dap_interval_timer_t threshold_txs_free_timer;
    // separate access to decrees storage & processing
    pthread_rwlock_t decrees_rwlock;
    dap_list_t *decree_owners_pkeys;
    uint16_t decree_num_of_owners;
    uint16_t decree_min_num_of_signers;
    dap_ledger_decree_item_t *decrees;
    dap_ledger_anchor_item_t *anchors;

    // Save/load operations condition
    pthread_mutex_t load_mutex;
    pthread_cond_t load_cond;
    bool load_end;
    // Ledger flags
    bool check_ds, check_cells_ds, check_token_emission, cached, mapped, threshold_enabled;
    //notifiers
    dap_list_t *bridged_tx_notifiers;
    dap_list_t *tx_add_notifiers;
    dap_ledger_cache_tx_check_callback_t cache_tx_check_callback;
    // White- and blacklist
    dap_ledger_hal_item_t *hal_items, *hrl_items;
} dap_ledger_private_t;

#define PVT(a) ( (dap_ledger_private_t *) a->_internal )

extern bool g_debug_ledger;

bool dap_ledger_pvt_cache_gdb_load_tokens_callback(dap_global_db_instance_t *a_dbi,
                                                   int a_rc, const char *a_group,
                                                   const size_t a_values_total, const size_t a_values_count,
                                                   dap_global_db_obj_t *a_values, void *a_arg);
bool dap_ledger_pvt_cache_gdb_load_stake_lock_callback(dap_global_db_instance_t *a_dbi,
                                                       int a_rc, const char *a_group,
                                                       const size_t a_values_total, const size_t a_values_count,
                                                       dap_global_db_obj_t *a_values, void *a_arg);
bool dap_ledger_pvt_cache_gdb_load_balances_callback(dap_global_db_instance_t *a_dbi,
                                                      int a_rc, const char *a_group,
                                                      const size_t a_values_total, const size_t a_values_count,
                                                      dap_global_db_obj_t *a_values, void *a_arg);
int dap_ledger_pvt_threshold_txs_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash);
void dap_ledger_pvt_threshold_txs_proc(dap_ledger_t *a_ledger);
dap_ledger_token_item_t *dap_ledger_pvt_find_token(dap_ledger_t *a_ledger, const char *a_token_ticker);
bool dap_ledger_pvt_token_supply_check(dap_ledger_token_item_t *a_token_item, uint256_t a_value);
bool dap_ledger_pvt_token_supply_check_update(dap_ledger_t *a_ledger, dap_ledger_token_item_t *a_token_item, uint256_t a_value, bool a_for_removing);
dap_ledger_token_emission_item_t *dap_ledger_pvt_emission_item_find(dap_ledger_t *a_ledger,
                const char *a_token_ticker, const dap_chain_hash_fast_t *a_token_emission_hash, dap_ledger_token_item_t **a_token_item);
dap_ledger_check_error_t dap_ledger_pvt_addr_check(dap_ledger_token_item_t *a_token_item, dap_chain_addr_t *a_addr, bool a_receive);
void dap_ledger_pvt_emission_cache_update(dap_ledger_t *a_ledger, dap_ledger_token_emission_item_t *a_emission_item);
