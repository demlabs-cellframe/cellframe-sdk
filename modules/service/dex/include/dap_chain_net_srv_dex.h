/*
 * Authors:
 * Constantin Papizh <pa3.14zh@gmail.com>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
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

 *
 * DEX v2 service (SRV_DEX) API
 */

#pragma once

// Follow xchange includes for type availability
#include "dap_chain_net_srv.h"
#include "dap_chain_wallet.h"
#include "dap_chain_datum_tx_out_cond.h"

#define DAP_CHAIN_NET_SRV_DEX_ID 0x000000000000000AULL

typedef enum dex_tx_type{
    DEX_TX_TYPE_UNDEFINED,
    DEX_TX_TYPE_ORDER,        // has SRV_DEX OUT only (composer writes this to payload)
    DEX_TX_TYPE_EXCHANGE,     // trade (buyer-leftover SRV_DEX OUT optionally) (composer writes this)
    DEX_TX_TYPE_UPDATE,       // seller-leftover update (SRV_DEX OUT with non-blank root) (composer writes this)
    DEX_TX_TYPE_INVALIDATE    // internal-only classification (no SRV_DEX OUT, no seller payouts)
} dex_tx_type_t;

// Match API
dap_hash_fast_t *dap_chain_net_srv_dex_match_hashes(
        dap_chain_net_t *a_net, const char *a_sell_token, const char *a_buy_token,
        dap_chain_net_id_t *a_sell_net_id, dap_chain_net_id_t *a_buy_net_id,
        uint256_t *a_max_value, uint256_t *a_min_rate, size_t *a_num_matches, bool a_is_budget_buy);
    
int dap_chain_net_srv_dex_init();
void dap_chain_net_srv_dex_deinit();

// Create order
typedef enum dap_chain_net_srv_dex_create_error_list{
    DEX_CREATE_ERROR_OK = 0,
    DEX_CREATE_ERROR_INVALID_ARGUMENT,
    DEX_CREATE_ERROR_TOKEN_TICKER_SELL_NOT_FOUND,
    DEX_CREATE_ERROR_TOKEN_TICKER_BUY_NOT_FOUND,
    DEX_CREATE_ERROR_PAIR_NOT_ALLOWED,
    DEX_CREATE_ERROR_RATE_IS_ZERO,
    DEX_CREATE_ERROR_FEE_IS_ZERO,
    DEX_CREATE_ERROR_VALUE_SELL_IS_ZERO,
    DEX_CREATE_ERROR_INTEGER_OVERFLOW,
    DEX_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE,
    DEX_CREATE_ERROR_NOT_ENOUGH_CASH,
    DEX_CREATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_create_error_t;

dap_chain_net_srv_dex_create_error_t dap_chain_net_srv_dex_create(
        dap_chain_net_t *a_net, const char *a_token_buy,
        const char *a_token_sell, uint256_t a_value_sell,
        uint256_t a_rate, uint8_t a_min_fill_combined,
        uint256_t a_fee, dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

// Remove (invalidate) order by root or tail hash
typedef enum dap_chain_net_srv_dex_remove_error_list{
    DEX_REMOVE_ERROR_OK = 0,
    DEX_REMOVE_ERROR_INVALID_ARGUMENT,
    DEX_REMOVE_ERROR_FEE_IS_ZERO,
    DEX_REMOVE_ERROR_TX_NOT_FOUND,
    DEX_REMOVE_ERROR_INVALID_OUT,
    DEX_REMOVE_ERROR_NOT_OWNER,
    DEX_REMOVE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_remove_error_t;

dap_chain_net_srv_dex_remove_error_t dap_chain_net_srv_dex_remove(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
        uint256_t a_fee, dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

/* Update (modify) order by owner */
typedef enum dap_chain_net_srv_dex_update_error_list{
    DEX_UPDATE_ERROR_OK = 0,
    DEX_UPDATE_ERROR_INVALID_ARGUMENT,
    DEX_UPDATE_ERROR_NOT_FOUND,
    DEX_UPDATE_ERROR_NOT_OWNER,
    DEX_UPDATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_update_error_t;

dap_chain_net_srv_dex_update_error_t dap_chain_net_srv_dex_update(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_order_root,
        bool a_has_new_value, uint256_t a_new_value,
        uint256_t a_fee, dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

// Purchase against single order
typedef enum dap_chain_net_srv_dex_purchase_error_list{
    DEX_PURCHASE_ERROR_OK = 0,
    DEX_PURCHASE_ERROR_INVALID_ARGUMENT,
    DEX_PURCHASE_ERROR_ORDER_NOT_FOUND,
    DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY,
    DEX_PURCHASE_MULTI_ERROR_PAIR_MISMATCH,
    DEX_PURCHASE_MULTI_ERROR_SIDE_MISMATCH,
    DEX_PURCHASE_AUTO_ERROR_NO_MATCHES,
    DEX_PURCHASE_ERROR_COMPOSE_TX
    // TODO: Add more informative codes
} dap_chain_net_srv_dex_purchase_error_t;

dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase(
    dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
    uint256_t a_value, bool a_is_budget_buy, uint256_t a_fee, dap_chain_wallet_t *a_wallet,
    bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx);

// Multi-purchase against list of orders (M:1). Orders must belong to one pair (sell/buy).
dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase_multi(
    dap_chain_net_t *a_net,
    dap_hash_fast_t *a_order_hashes, size_t a_orders_count, uint256_t a_value, bool a_is_budget_buy, uint256_t a_fee,
    dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx);

typedef struct dex_match_table_entry dex_match_table_entry_t;

dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase_auto(
        dap_chain_net_t *a_net,
        const char *a_sell_token, const char *a_buy_token,
        uint256_t a_value, bool a_is_budget_buy, uint256_t a_fee, uint256_t a_min_rate,
        dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
        dap_chain_datum_tx_t **a_tx, dex_match_table_entry_t **a_matches);

// Legacy migration from SRV_XCHANGE to SRV_DEX (owner-only bridge)
typedef enum dap_chain_net_srv_dex_migrate_error_list{
    DEX_MIGRATE_ERROR_OK = 0,
    DEX_MIGRATE_ERROR_INVALID_ARGUMENT,
    DEX_MIGRATE_ERROR_PREV_NOT_FOUND,
    DEX_MIGRATE_ERROR_PREV_NOT_XCHANGE,
    DEX_MIGRATE_ERROR_NOT_OWNER,
    DEX_MIGRATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_migrate_error_t;

dap_chain_net_srv_dex_migrate_error_t dap_chain_net_srv_dex_migrate(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_prev_hash,
        uint256_t a_rate_new, uint256_t a_fee,
        dap_chain_wallet_t *a_wallet, dap_chain_datum_tx_t **a_tx);

// Cancel all orders by seller for a specific canonical pair (BASE/QUOTE)
typedef enum dap_chain_net_srv_dex_cancel_all_error_list{
    DEX_CANCEL_ALL_ERROR_OK = 0,
    DEX_CANCEL_ALL_ERROR_INVALID_ARGUMENT,
    DEX_CANCEL_ALL_ERROR_WALLET,
    DEX_CANCEL_ALL_ERROR_ORDERS_EMPTY,
    DEX_CANCEL_ALL_ERROR_WALLET_MISMATCH,
    DEX_CANCEL_ALL_NOT_ENOUGH_CASH_FOR_FEE,
    DEX_CANCEL_ALL_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_cancel_all_error_t;

dap_chain_net_srv_dex_cancel_all_error_t dap_chain_net_srv_dex_cancel_all_by_seller(
        dap_chain_net_t *a_net,
        const dap_chain_addr_t *a_seller,
        const char *a_base_token, const char *a_quote_token,
        int a_limit,
        uint256_t a_fee,
        dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

int dap_chain_net_srv_dex_decree_callback(dap_ledger_t *a_ledger, bool a_apply, dap_tsd_t *a_params, size_t a_params_size);

// Dump DEX memcache to log
void dap_chain_net_srv_dex_dump_orders_cache();

/**
 * @brief Adjust min_fill field in cached order
 * @param a_net Network
 * @param a_order_tail Order tail hash
 * @param a_new_minfill New min_fill value to set
 * @param a_out_old_minfill [out] Returns old value for later restore (can be NULL)
 * @return 0 on success, -1 invalid args, -2 order not found
 */
int dap_chain_net_srv_dex_cache_adjust_minfill(
    dap_chain_net_t *a_net,
    const dap_hash_fast_t *a_order_tail,
    uint8_t a_new_minfill,
    uint8_t *a_out_old_minfill
);