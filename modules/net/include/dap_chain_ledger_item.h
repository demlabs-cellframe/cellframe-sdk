/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include <pthread.h>
#include <time.h>
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_tx.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_net.h"
#include "dap_pkey.h"
#include "uthash.h"
#include "dap_chain_ledger_tx.h"
#include "dap_chain_ledger.h"


// ============================================================================
// Ledger item structures (must be defined before dap_ledger_token_item_t)
// ============================================================================

/**
 * @brief Token emission item structure
 */
typedef struct dap_ledger_token_emission_item {
    dap_chain_hash_fast_t datum_token_emission_hash;
    dap_chain_datum_token_emission_t *datum_token_emission;
    size_t datum_token_emission_size;
    dap_chain_hash_fast_t tx_used_out;
    dap_nanotime_t ts_added;
    UT_hash_handle hh;
} dap_ledger_token_emission_item_t;

/**
 * @brief Token update item structure
 */
typedef struct dap_ledger_token_update_item {
    dap_hash_fast_t			update_token_hash;
    dap_chain_datum_token_t	*datum_token_update;
    size_t					datum_token_update_size;
    time_t					updated_time;
    UT_hash_handle hh;
} dap_ledger_token_update_item_t;

/**
 * @brief Token item structure (in-memory cache for token data)
 * @details This structure caches token information in the ledger for fast access.
 *          It includes token metadata, supply tracking, emission history, and UTXO blocking.
 */
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
    uint32_t             flags;
    struct spec_address *tx_recv_allow;
    size_t               tx_recv_allow_size;
    struct spec_address *tx_recv_block;
    size_t               tx_recv_block_size;
    struct spec_address *tx_send_allow;
    size_t               tx_send_allow_size;
    struct spec_address *tx_send_block;
    size_t               tx_send_block_size;
    char *description;
    // For delegated tokens
    bool is_delegated;
    char delegated_from[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t emission_rate;

    /**
     * @brief UTXO blocking mechanism (per-token blocklist)
     * @details utxo_blocklist: Hash table (uthash) of blocked UTXOs for this token
     *          utxo_blocklist_rwlock: Read-write lock for thread-safe access
     *          utxo_blocklist_count: Number of blocked UTXOs (for monitoring/auditing)
     *          
     *          Controlled by flags:
     *          - UTXO_BLOCKING_DISABLED (BIT 16): Disables UTXO blocking entirely
     *          - STATIC_UTXO_BLOCKLIST (BIT 17): Makes blocklist immutable after token creation
     *          
     *          Access pattern:
     *          - Read operations (lookup): pthread_rwlock_rdlock
     *          - Write operations (add/remove): pthread_rwlock_wrlock
     *          
     * @see dap_ledger_utxo_block_item_t for blocklist entry structure
     * @see s_ledger_utxo_is_blocked for blocking check logic
     * @see s_ledger_utxo_block_add, s_ledger_utxo_block_remove for management
     */
    pthread_rwlock_t utxo_blocklist_rwlock;           ///< RW lock for thread-safe blocklist access
    struct dap_ledger_utxo_block_item *utxo_blocklist; ///< Hash table (uthash) of blocked UTXOs
    size_t utxo_blocklist_count;                       ///< Number of blocked UTXOs (for monitoring)

    UT_hash_handle hh;
} dap_ledger_token_item_t;

// ============================================================================
// Additional ledger item structures
// ============================================================================

/**
 * @brief Stake lock item structure
 */
typedef struct dap_ledger_stake_lock_item {
    dap_chain_hash_fast_t	tx_for_stake_lock_hash;
    dap_chain_hash_fast_t	tx_used_out;
    UT_hash_handle hh;
} dap_ledger_stake_lock_item_t;

/**
 * @brief Special address structure (for allow/block lists)
 */
struct spec_address {
    dap_chain_addr_t addr;
    dap_time_t becomes_effective;
};

/**
 * @brief UTXO blocklist key structure
 * @details Composite key for hash table lookup (tx_hash + out_idx identifies unique UTXO).
 *          Total size: 36 bytes (32B hash + 4B index)
 */
typedef struct dap_ledger_utxo_block_key {
    dap_chain_hash_fast_t tx_hash;  ///< Transaction hash (32 bytes)
    uint32_t out_idx;                ///< Output index within transaction (4 bytes)
} dap_ledger_utxo_block_key_t;

/**
 * @brief UTXO blocking action types (for history tracking)
 * @details Each history entry records what action was performed:
 *          - BLOCK_ACTION_ADD: UTXO was blocked (added to blocklist)
 *          - BLOCK_ACTION_REMOVE: UTXO was unblocked (removed from blocklist)
 *          - BLOCK_ACTION_CLEAR: All UTXOs for token were cleared
 */
typedef enum dap_ledger_utxo_block_action {
    BLOCK_ACTION_ADD = 1,      ///< UTXO blocked
    BLOCK_ACTION_REMOVE = 2,   ///< UTXO unblocked
    BLOCK_ACTION_CLEAR = 3     ///< All UTXOs cleared
} dap_ledger_utxo_block_action_t;

/**
 * @brief UTXO blocking history item (for Zero/Main Chain sync)
 * @details Stores a single change event in UTXO blocking history.
 *          History is needed because token_update appears on Zero Chain earlier than
 *          Main Chain updates blockchain_time. Without history, sync order can cause
 *          inconsistencies.
 *          
 *          History forms a double-linked list sorted chronologically by bc_time.
 *          
 * @note Critical for Zero/Main Chain synchronization
 */
typedef struct dap_ledger_utxo_block_history_item {
    dap_ledger_utxo_block_action_t action;  ///< What happened (ADD/REMOVE/CLEAR)
    dap_time_t bc_time;                      ///< Blockchain time when action occurred
    dap_time_t becomes_effective;            ///< When blocking becomes active (for ADD)
    dap_time_t becomes_unblocked;            ///< When blocking expires (for REMOVE)
    dap_hash_fast_t token_update_hash;       ///< Which token_update caused this
    
    // Double-linked list for chronological ordering
    struct dap_ledger_utxo_block_history_item *next;
    struct dap_ledger_utxo_block_history_item *prev;
} dap_ledger_utxo_block_history_item_t;

/**
 * @brief UTXO blocklist item (hash table entry)
 * @details Each token has its own UTXO blocklist stored as in-memory hash table (uthash).
 *          This structure represents a single blocked UTXO with temporal semantics:
 *          - becomes_effective: when blocking activates (delayed activation support)
 *          - becomes_unblocked: when blocking deactivates (delayed unblocking support)
 *          
 *          Blocking state is determined by:
 *          blocked = (blockchain_time >= becomes_effective) && 
 *                    (becomes_unblocked == 0 || blockchain_time < becomes_unblocked)
 *          
 *          Full history tracking for Zero/Main Chain sync.
 *          History is stored as double-linked list, separate RW lock prevents blocking.
 *          
 * @note Thread-safety: Access protected by utxo_blocklist_rwlock in dap_ledger_token_item_t
 * @note History thread-safety: Access protected by history_rwlock (separate lock)
 */
typedef struct dap_ledger_utxo_block_item {
    dap_ledger_utxo_block_key_t key;  ///< Key for hash table lookup (tx_hash + out_idx)
    
    // Current state (for fast lookup without history replay)
    dap_time_t blocked_time;           ///< When it was added to blocklist (for auditing)
    dap_time_t becomes_effective;      ///< When blocking becomes active (blockchain time)
    dap_time_t becomes_unblocked;      ///< When unblocking becomes active (0 = never/permanent)
    
    // Full history for Zero/Main Chain sync
    dap_ledger_utxo_block_history_item_t *history_head;  ///< Start of history (oldest)
    dap_ledger_utxo_block_history_item_t *history_tail;  ///< End of history (newest)
    pthread_rwlock_t history_rwlock;                      ///< Separate lock for history access
    
    UT_hash_handle hh;                 ///< uthash handle (for hash table operations)
} dap_ledger_utxo_block_item_t;

/**
 * @brief Ledger cache item - one of unspent outputs
 */
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
        byte_t padding[6];
        byte_t multichannel;
        dap_time_t ts_spent;
        byte_t pad[7];
        dap_chain_net_srv_uid_t tag; //tag (or service this tx is belong to)
        dap_chain_tx_tag_action_type_t action;
        dap_chain_hash_fast_t tx_hash_spent_fast[]; // spent outs list
    } DAP_ALIGN_PACKED cache_data;
} dap_ledger_tx_item_t;

/**
 * @brief Ledger cache GDB record structure
 */
typedef struct dap_ledger_cache_gdb_record {
    uint64_t cache_size;
    uint64_t datum_size;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_ledger_cache_gdb_record_t;

/**
 * @brief Ledger tokenizer structure
 */
typedef struct dap_ledger_tokenizer {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t sum;
    UT_hash_handle hh;
} dap_ledger_tokenizer_t;

/**
 * @brief Ledger reward key structure
 */
typedef struct dap_ledger_reward_key {
    dap_hash_fast_t block_hash;
    dap_hash_fast_t sign_pkey_hash;
} DAP_ALIGN_PACKED dap_ledger_reward_key_t;

/**
 * @brief Ledger reward item structure
 */
typedef struct dap_ledger_reward_item {
    dap_ledger_reward_key_t key;
    dap_hash_fast_t spender_tx;
    UT_hash_handle hh;
} dap_ledger_reward_item_t;

/**
 * @brief Ledger transaction bound structure
 */
typedef struct dap_ledger_tx_bound {
    uint8_t type;
    uint16_t prev_out_idx;
    uint256_t value;
    union {
        dap_ledger_token_item_t *token_item;    // For current_supply update on emissions
        dap_chain_tx_out_cond_t *cond;          // For conditional output
        struct {
            char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
            dap_chain_addr_t addr_from;
        } in;
    };
    union {
        dap_ledger_tx_item_t *prev_item;        // For not emission TX
        dap_ledger_token_emission_item_t *emission_item;
        dap_ledger_stake_lock_item_t *stake_lock_item;
        dap_ledger_reward_key_t reward_key;
    };
} dap_ledger_tx_bound_t;

/**
 * @brief In-memory wallet balance structure
 */
typedef struct dap_ledger_wallet_balance {
    char *key;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t balance;
    UT_hash_handle hh;
} dap_ledger_wallet_balance_t;

/**
 * @brief Ledger cache item structure
 */
typedef struct dap_ledger_cache_item {
    dap_chain_hash_fast_t *hash;
    bool found;
} dap_ledger_cache_item_t;

/**
 * @brief Ledger cache string item structure
 */
typedef struct dap_ledger_cache_str_item {
    char *key;
    bool found;
} dap_ledger_cache_str_item_t;

/**
 * @brief Ledger transaction notifier structure
 */
typedef struct dap_ledger_tx_notifier {
    dap_ledger_tx_add_notify_t callback;
    void *arg;
} dap_ledger_tx_notifier_t;

/**
 * @brief Ledger bridged transaction notifier structure
 */
typedef struct dap_ledger_bridged_tx_notifier {
    dap_ledger_bridged_tx_notify_t callback;
    void *arg;
} dap_ledger_bridged_tx_notifier_t;

/**
 * @brief Ledger HAL (Hard Accept List) item structure
 */
typedef struct dap_ledger_hal_item {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_ledger_hal_item_t;
