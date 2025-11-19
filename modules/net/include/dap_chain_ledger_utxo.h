/*
 * Authors:
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DAP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>
#include "dap_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_item.h"

// Forward declaration
typedef struct dap_ledger_token_item dap_ledger_token_item_t;

/**
 * @brief Get UTXO blocking state at specific blockchain time
 * @details Reconstructs UTXO blocking state by replaying history up to specified time.
 *          Critical for Zero/Main Chain synchronization where token_update arrives
 *          on Zero Chain before Main Chain updates blockchain_time.
 * @param a_token_item Token containing UTXO blocklist
 * @param a_tx_hash Transaction hash
 * @param a_out_idx Output index
 * @param a_blockchain_time Blockchain time to query state at
 * @return true if UTXO was blocked at that time, false otherwise
 */
bool dap_ledger_utxo_block_get_state_at_time(dap_ledger_token_item_t *a_token_item,
                                              dap_chain_hash_fast_t *a_tx_hash,
                                              uint32_t a_out_idx,
                                              dap_time_t a_blockchain_time);

/**
 * @brief Check if UTXO is blocked for given token (current time)
 * @param a_token_item Token item to check
 * @param a_tx_hash Transaction hash
 * @param a_out_idx Output index
 * @param a_ledger Ledger instance (for blockchain_time)
 * @return true if blocked, false otherwise
 */
bool dap_ledger_utxo_is_blocked(dap_ledger_token_item_t *a_token_item,
                                dap_chain_hash_fast_t *a_tx_hash,
                                uint32_t a_out_idx,
                                dap_ledger_t *a_ledger);

/**
 * @brief Add UTXO to blocklist
 * @param a_token_item Token item
 * @param a_tx_hash Transaction hash
 * @param a_out_idx Output index
 * @param a_becomes_effective Time when blocking becomes active (blockchain time)
 * @param a_token_update_hash Hash of token_update datum (for history)
 * @param a_ledger Ledger instance (for blockchain time)
 * @return 0 if success, -1 on error
 */
int dap_ledger_utxo_block_add(dap_ledger_token_item_t *a_token_item,
                              dap_chain_hash_fast_t *a_tx_hash,
                              uint32_t a_out_idx,
                              dap_time_t a_becomes_effective,
                              dap_hash_fast_t *a_token_update_hash,
                              dap_ledger_t *a_ledger);

/**
 * @brief Remove UTXO from blocklist (with optional delayed unblocking)
 * @details With history tracking: records REMOVE action in history, keeps item in hash table.
 *          Item cleanup happens during periodic history cleanup, not immediately.
 * @param a_token_item Token item
 * @param a_tx_hash Transaction hash
 * @param a_out_idx Output index
 * @param a_becomes_unblocked Time when unblocking becomes active (0 = immediate removal)
 * @param a_token_update_hash Hash of token_update datum (for history tracking)
 * @param a_ledger Ledger instance (for blockchain time)
 * @return 0 if success, -1 on error
 */
int dap_ledger_utxo_block_remove(dap_ledger_token_item_t *a_token_item,
                                 dap_chain_hash_fast_t *a_tx_hash,
                                 uint32_t a_out_idx,
                                 dap_time_t a_becomes_unblocked,
                                 dap_hash_fast_t *a_token_update_hash,
                                 dap_ledger_t *a_ledger);

/**
 * @brief Clear entire UTXO blocklist for token
 * @details CRITICAL: Records CLEAR action in history but DOES NOT delete items from hash table!
 *          This is essential for Zero/Main Chain sync - CLEAR may arrive on Zero Chain
 *          before Main Chain catches up, so we need full history for state reconstruction.
 *          Items remain in hash table with CLEAR action in history for accurate replay.
 * @param a_token_item Token item
 * @param a_token_update_hash Hash of token_update datum (for history tracking)
 * @param a_ledger Ledger instance (for blockchain time)
 * @return 0 if success, -1 on error
 */
int dap_ledger_utxo_block_clear(dap_ledger_token_item_t *a_token_item,
                                dap_hash_fast_t *a_token_update_hash,
                                dap_ledger_t *a_ledger);

