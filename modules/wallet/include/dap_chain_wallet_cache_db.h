/*
 * Authors:
 * Olzhas Zharasbaev
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
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

/**
 * @file dap_chain_wallet_cache_db.h
 * @brief GlobalDB storage structures for wallet cache persistence
 * @author CellFrame Team (Olzhas Zharasbaev)
 * @date 2025-10-09
 * @version 1.0
 * 
 * @details This module provides structures and functions for storing wallet cache
 *          in GlobalDB, enabling persistent storage of wallet transaction metadata
 *          with lazy loading capability.
 * 
 * @section overview Overview
 * The wallet cache DB module allows saving wallet transaction metadata to persistent
 * storage (GlobalDB) instead of keeping everything in RAM. This provides:
 * - Persistence across node restarts
 * - Reduced RAM usage (10-100x improvement for large wallets)
 * - Lazy loading of transaction data from chain files
 * 
 * @section architecture Architecture
 * Storage format uses variable-length structures:
 * ```
 * [dap_wallet_cache_db_t header]
 *   ├─ version, net_id, chain_id
 *   ├─ tx_count, unspent_count
 *   └─ wallet_addr
 * [Transactions section]
 *   ├─ [tx1: header + inputs[] + outputs[]]
 *   ├─ [tx2: header + inputs[] + outputs[]]
 *   └─ ...
 * [Unspent outputs section]
 *   └─ [unspent_output array]
 * ```
 * 
 * @section usage Usage Example
 * ```c
 * // Saving wallet cache to GlobalDB
 * dap_wallet_cache_db_t *cache = dap_wallet_cache_db_create(addr, net_id, chain_id);
 * // ... fill cache with transactions ...
 * size_t size = calculate_total_size(cache);
 * dap_wallet_cache_db_save(cache, size, net_name, chain_name);
 * dap_wallet_cache_db_free(cache);
 * 
 * // Loading wallet cache from GlobalDB
 * dap_wallet_cache_db_t *loaded = dap_wallet_cache_db_load(addr, net_id, net_name, chain_name);
 * if (loaded) {
 *     // Process loaded cache
 *     dap_wallet_cache_db_free(loaded);
 * }
 * ```
 * 
 * @section storage GlobalDB Storage
 * - Group: wallet.cache.{net_id}.{chain_name}
 * - Key: {wallet_addr_base58}
 * - Value: Serialized dap_wallet_cache_db_t structure
 * 
 * @see dap_chain_wallet_cache.c for main implementation
 * @see dap_global_db.h for GlobalDB API
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_common.h"
#include "dap_time.h"
#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_math_ops.h"

/**
 * @brief Wallet cache database structures for GlobalDB storage
 * 
 * This replaces RAM-based uthash storage with persistent GlobalDB storage.
 * Data is stored per wallet address per chain per network.
 */

#define DAP_WALLET_CACHE_DB_VERSION 1

/**
 * @brief Transaction cache record for database storage
 * 
 * Stores transaction metadata with file location instead of pointer.
 * The actual transaction data can be read from cell file using cell_id + offset.
 */
typedef struct dap_wallet_tx_cache_db {
    dap_hash_fast_t tx_hash;                          // Transaction hash
    dap_hash_fast_t atom_hash;                        // Atom/block hash containing this tx
    
    // File location (replaces dap_chain_datum_tx_t *tx pointer)
    dap_chain_cell_id_t cell_id;                      // Cell ID (0 for non-celled chains)
    off_t file_offset;                                // File offset of BLOCK in cell file
    size_t datum_offset_in_block;                     // Offset of datum WITHIN the block (0 for DAG where datum=atom)
    size_t tx_size;                                   // Transaction size in bytes
    
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];    // Main token ticker
    bool multichannel;                                // Has multiple token types
    int ret_code;                                     // Ledger check result code
    dap_chain_srv_uid_t srv_uid;                      // Service UID
    uint32_t action;                                  // Action type (dap_chain_tx_tag_action_type_t)
    
    uint16_t inputs_count;                            // Number of inputs for this wallet
    uint16_t outputs_count;                           // Number of outputs for this wallet
    
    // Variable length data follows:
    // dap_wallet_tx_cache_input_db_t inputs[inputs_count];
    // dap_wallet_tx_cache_output_db_t outputs[outputs_count];
} DAP_ALIGN_PACKED dap_wallet_tx_cache_db_t;

/**
 * @brief Transaction input record for database
 */
typedef struct dap_wallet_tx_cache_input_db {
    dap_chain_hash_fast_t tx_prev_hash;              // Previous transaction hash
    int tx_out_prev_idx;                             // Previous output index
    uint256_t value;                                 // Value being spent
} DAP_ALIGN_PACKED dap_wallet_tx_cache_input_db_t;

/**
 * @brief Transaction output record for database
 * 
 * Stores output index and metadata. The actual output data is in transaction,
 * which can be read from file using tx location info.
 */
typedef struct dap_wallet_tx_cache_output_db {
    int tx_out_idx;                                  // Output index in transaction
    uint8_t out_type;                                // Output type (TX_ITEM_TYPE_OUT_*)
} DAP_ALIGN_PACKED dap_wallet_tx_cache_output_db_t;

/**
 * @brief Unspent output record for database
 * 
 * This is the most critical structure for wallet operations.
 * Fast access to unspent outputs is essential for creating new transactions.
 */
typedef struct dap_wallet_unspent_out_db {
    dap_hash_fast_t tx_hash;                         // Transaction hash
    int out_idx;                                     // Output index
    
    // File location to quickly read the output
    dap_chain_cell_id_t cell_id;                     // Cell ID
    off_t file_offset;                               // File offset of transaction
    size_t tx_size;                                  // Transaction size
    
    uint8_t out_type;                                // Output type
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];   // Token ticker
    uint256_t value;                                 // Output value
} DAP_ALIGN_PACKED dap_wallet_unspent_out_db_t;

/**
 * @brief Main wallet cache database record
 * 
 * This is the root structure stored in GlobalDB.
 * Group: "wallet.cache.{net_id}.{chain_name}"
 * Key: "{wallet_addr_hex}"
 */
typedef struct dap_wallet_cache_db {
    uint32_t version;                                // Schema version
    dap_chain_addr_t wallet_addr;                    // Wallet address
    dap_chain_net_id_t net_id;                       // Network ID
    dap_chain_id_t chain_id;                         // Chain ID
    
    uint32_t tx_count;                               // Number of transactions
    uint32_t unspent_count;                          // Number of unspent outputs
    
    dap_time_t last_update;                          // Last cache update timestamp
    
    // Variable length data follows:
    // dap_wallet_tx_cache_db_t transactions[tx_count];
    // dap_wallet_unspent_out_db_t unspent_outputs[unspent_count];
} DAP_ALIGN_PACKED dap_wallet_cache_db_t;

// Helper macros for accessing variable-length data
#define DAP_WALLET_CACHE_DB_TXS(cache) \
    ((dap_wallet_tx_cache_db_t*)((uint8_t*)(cache) + sizeof(dap_wallet_cache_db_t)))

#define DAP_WALLET_CACHE_DB_UNSPENTS(cache) \
    ((dap_wallet_unspent_out_db_t*)((uint8_t*)(cache) + sizeof(dap_wallet_cache_db_t) + \
     sizeof(dap_wallet_tx_cache_db_t) * (cache)->tx_count))

// Function prototypes for serialization/deserialization
size_t dap_wallet_cache_db_calc_size(uint32_t a_tx_count, uint32_t a_unspent_count);
dap_wallet_cache_db_t* dap_wallet_cache_db_create(dap_chain_addr_t *a_addr, 
                                                   dap_chain_net_id_t a_net_id,
                                                   dap_chain_id_t a_chain_id);
void dap_wallet_cache_db_free(dap_wallet_cache_db_t *a_cache);

// GlobalDB key generation
char* dap_wallet_cache_db_get_group(dap_chain_net_id_t a_net_id, const char *a_chain_name);
char* dap_wallet_cache_db_get_key(dap_chain_addr_t *a_wallet_addr);

// GlobalDB operations
int dap_wallet_cache_db_save(dap_wallet_cache_db_t *a_cache, size_t a_cache_size, const char *a_net_name, const char *a_chain_name);
dap_wallet_cache_db_t* dap_wallet_cache_db_load(dap_chain_addr_t *a_addr, dap_chain_net_id_t a_net_id, 
                                                 const char *a_net_name, const char *a_chain_name);
