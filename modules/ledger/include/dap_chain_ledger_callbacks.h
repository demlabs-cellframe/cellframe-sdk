/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 
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

#include "dap_chain_common.h"
#include "dap_json_rpc.h"

/**
 * @file dap_chain_ledger_callbacks.h
 * @brief Ledger callback system for external integrations
 * 
 * Ledger is LOW-LEVEL module that doesn't depend on upper layers.
 * Instead, upper layers (wallet-cache, wallet-shared) register callbacks
 * to be notified about ledger events.
 * 
 * ARCHITECTURE:
 * - Ledger = LOW (doesn't know about wallet)
 * - Wallet-cache/shared = HIGH (depends on ledger, registers callbacks)
 */

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct dap_chain_addr dap_chain_addr_t;
typedef struct dap_chain_datum_tx dap_chain_datum_tx_t;
typedef struct dap_ledger dap_ledger_t;

/**
 * @brief Callback: get wallet name by address (for debug/JSON output)
 * 
 * @param a_addr Address to lookup
 * @return Wallet name or NULL if not found
 * 
 * Registered by: wallet-cache module
 */
typedef const char* (*dap_ledger_addr_to_wallet_name_cb_t)(const dap_chain_addr_t *a_addr);

/**
 * @brief Callback: add wallet info to JSON object (for debug output)
 * 
 * @param a_json_obj JSON object to add wallet info to
 * @param a_wallet_name Wallet name
 * @param a_wallet_path Path to wallets directory
 * 
 * Registered by: wallet module (if needed)
 */
typedef void (*dap_ledger_wallet_info_to_json_cb_t)(dap_json_object_t *a_json_obj, 
                                                      const char *a_wallet_name,
                                                      const char *a_wallet_path);

/**
 * @brief Callback: notify about TX addition (for shared TX cache)
 * 
 * @param a_tx Transaction that was added
 * @param a_net_name Network name
 * 
 * Registered by: wallet-shared module
 */
typedef void (*dap_ledger_tx_added_cb_t)(dap_chain_datum_tx_t *a_tx, 
                                          const char *a_net_name);

/**
 * @brief Ledger callbacks structure
 * 
 * All callbacks are OPTIONAL. Ledger works without any callbacks.
 * Callbacks are for OPTIONAL features (debug, caching, etc.)
 */
typedef struct dap_ledger_callbacks {
    dap_ledger_addr_to_wallet_name_cb_t    addr_to_wallet_name;  // Optional: address → wallet name
    dap_ledger_wallet_info_to_json_cb_t    wallet_info_to_json;  // Optional: wallet info for JSON
    dap_ledger_tx_added_cb_t                tx_added;             // Optional: TX addition notification
} dap_ledger_callbacks_t;

/**
 * @brief Register ledger callbacks
 * 
 * @param a_callbacks Callbacks structure (can have NULLs for unused callbacks)
 */
void dap_ledger_callbacks_register(const dap_ledger_callbacks_t *a_callbacks);

/**
 * @brief Get current ledger callbacks
 * 
 * @return Pointer to callbacks structure (never NULL, but callbacks inside can be NULL)
 */
const dap_ledger_callbacks_t* dap_ledger_callbacks_get(void);

#ifdef __cplusplus
}
#endif

