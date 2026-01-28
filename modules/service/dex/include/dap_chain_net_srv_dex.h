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

// Fee calculation constants (256-bit values as 64-bit for GET_256_FROM_64)
#define DAP_DEX_FEE_UNIT_NATIVE   10000000000000000ULL   // 0.01 × 10^18 (per-pair step for native abs fee)
#define DAP_DEX_FEE_STEP_PCT      1000000000000000ULL    // 0.001 × 10^18 (0.1% step for percentage fee)
#define DAP_DEX_POW18             1000000000000000000ULL // 1.0 × 10^18

typedef enum dex_tx_type{
    DEX_TX_TYPE_UNDEFINED,
    DEX_TX_TYPE_ORDER,        // has SRV_DEX OUT only (composer writes this to payload)
    DEX_TX_TYPE_EXCHANGE,     // trade (buyer-leftover SRV_DEX OUT optionally) (composer writes this)
    DEX_TX_TYPE_UPDATE,       // seller-leftover update (SRV_DEX OUT with non-blank root) (composer writes this)
    DEX_TX_TYPE_INVALIDATE    // internal-only classification (no SRV_DEX OUT, no seller payouts)
} dex_tx_type_t;

/**
 * @brief Query matching orders by criteria (cache-first, ledger fallback)
 * @param a_net           Target network
 * @param a_sell_token    Token buyer wants to sell (receive from perspective of order seller)
 * @param a_buy_token     Token buyer wants to buy (sell token of order)
 * @param a_sell_net_id   Network ID for sell token (can be NULL for same-network)
 * @param a_buy_net_id    Network ID for buy token (can be NULL for same-network)
 * @param a_max_value     Max value to match (NULL = unlimited)
 * @param a_rate_cap      Rate limit: orders with rate > this are excluded (NULL = no limit)
 * @param a_num_matches   [out] Number of matches found
 * @param a_is_budget_buy If true, a_max_value is budget in buy tokens, in sell tokens otherwise
 * @return Array of order tail hashes sorted by price (caller must DAP_DELETE), NULL if none
 */
dap_hash_fast_t *dap_chain_net_srv_dex_match_hashes(
        dap_chain_net_t *a_net, const char *a_sell_token, const char *a_buy_token,
        dap_chain_net_id_t *a_sell_net_id, dap_chain_net_id_t *a_buy_net_id,
        uint256_t *a_max_value, uint256_t *a_rate_cap, size_t *a_num_matches, bool a_is_budget_buy);

/**
 * @brief Initialize DEX service (register callbacks, load config)
 * @return 0 on success
 */
int dap_chain_net_srv_dex_init();

/**
 * @brief Deinitialize DEX service (free caches, unregister callbacks)
 */
void dap_chain_net_srv_dex_deinit();

/**
 * @brief Check if pair is whitelisted via DEX decrees
 * @param a_sell_token   Sell token ticker
 * @param a_sell_net_id  Sell token net id
 * @param a_buy_token    Buy token ticker
 * @param a_buy_net_id   Buy token net id
 * @return true if pair is whitelisted
 */
bool dap_chain_net_srv_dex_pair_is_whitelisted(const char *a_sell_token, dap_chain_net_id_t a_sell_net_id,
                                               const char *a_buy_token, dap_chain_net_id_t a_buy_net_id);

/* ============================================================================
 * Order Creation
 * ============================================================================ */
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

/**
 * @brief Create new DEX order (sell a_token_sell for a_token_buy at a_rate)
 * @param a_net               Target network
 * @param a_token_buy         Token to receive in exchange
 * @param a_token_sell        Token to sell (locked in order)
 * @param a_value_sell        Amount of sell token to lock (datoshi, 10^18)
 * @param a_rate              Exchange rate in canonical QUOTE/BASE format
 * @param a_min_fill_combined Min fill policy: bits 0-6 = percentage (0-100), bit 7 = base mode
 *                            (0 = pct of current remaining, 1 = pct of original value)
 * @param a_fee               Validator fee in native tokens (must be > 0)
 * @param a_wallet            Wallet for signing and UTXO source
 * @param a_tx                [out] Composed TX (caller submits via mempool)
 * @return Error code; pair must be whitelisted via decree
 */
dap_chain_net_srv_dex_create_error_t dap_chain_net_srv_dex_create(
        dap_chain_net_t *a_net, const char *a_token_buy,
        const char *a_token_sell, uint256_t a_value_sell,
        uint256_t a_rate, uint8_t a_min_fill_combined,
        uint256_t a_fee, dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

/* ============================================================================
 * Order Removal (Invalidation)
 * ============================================================================ */
typedef enum dap_chain_net_srv_dex_remove_error_list{
    DEX_REMOVE_ERROR_OK = 0,
    DEX_REMOVE_ERROR_INVALID_ARGUMENT,
    DEX_REMOVE_ERROR_FEE_IS_ZERO,
    DEX_REMOVE_ERROR_TX_NOT_FOUND,
    DEX_REMOVE_ERROR_INVALID_OUT,
    DEX_REMOVE_ERROR_NOT_OWNER,
    DEX_REMOVE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_remove_error_t;

/**
 * @brief Cancel (invalidate) order, returning locked funds to owner
 * @param a_net          Target network
 * @param a_order_hash   Order root or current tail hash (resolved automatically)
 * @param a_fee          Validator fee in native tokens (must be > 0)
 * @param a_wallet       Owner wallet (must match order's seller_addr)
 * @param a_tx           [out] Composed invalidation TX
 * @return Error code; only order owner can cancel
 */
dap_chain_net_srv_dex_remove_error_t dap_chain_net_srv_dex_remove(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
        uint256_t a_fee, dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

/* ============================================================================
 * Order Update
 * ============================================================================ */
typedef enum dap_chain_net_srv_dex_update_error_list{
    DEX_UPDATE_ERROR_OK = 0,
    DEX_UPDATE_ERROR_INVALID_ARGUMENT,
    DEX_UPDATE_ERROR_NOT_FOUND,
    DEX_UPDATE_ERROR_NOT_OWNER,
    DEX_UPDATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_update_error_t;

/**
 * @brief Update order value (rate is immutable). Excess returned to owner.
 * @param a_net            Target network
 * @param a_order_root     Order root hash (tail resolved automatically)
 * @param a_has_new_value  Must be true (required flag)
 * @param a_new_value      New order value (must be > 0 and <= current; use remove for full close)
 * @param a_fee            Validator fee in native tokens
 * @param a_wallet         Owner wallet (must match order's seller_addr)
 * @param a_tx             [out] Composed update TX
 * @return Error code; only order owner can update
 */
dap_chain_net_srv_dex_update_error_t dap_chain_net_srv_dex_update(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_order_root,
        bool a_has_new_value, uint256_t a_new_value,
        uint256_t a_fee, dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

/* ============================================================================
 * Purchase (Trade Execution)
 * ============================================================================ */
typedef enum dap_chain_net_srv_dex_purchase_error_list{
    DEX_PURCHASE_ERROR_OK = 0,
    DEX_PURCHASE_ERROR_INVALID_ARGUMENT,
    DEX_PURCHASE_ERROR_ORDER_NOT_FOUND,
    DEX_PURCHASE_ERROR_ORDER_SPENT,
    DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY,
    DEX_PURCHASE_MULTI_ERROR_PAIR_MISMATCH,
    DEX_PURCHASE_MULTI_ERROR_SIDE_MISMATCH,
    DEX_PURCHASE_AUTO_ERROR_NO_MATCHES,
    DEX_PURCHASE_ERROR_COMPOSE_TX
    // TODO: Add more informative codes
} dap_chain_net_srv_dex_purchase_error_t;

/**
 * @brief Execute trade against single order (direct hash purchase)
 * @param a_net             Target network
 * @param a_order_hash      Order root or tail hash (resolved automatically)
 * @param a_value           Trade amount (interpretation depends on a_is_budget_buy)
 * @param a_is_budget_buy   true: a_value is max budget in BUY tokens (order's sell token)
 *                          false: a_value is exact amount of SELL tokens (order's buy token)
 * @param a_fee             Validator fee in native tokens
 * @param a_wallet          Buyer wallet for signing and UTXO source
 * @param a_create_buyer_order_on_leftover If true, create new order from unspent funds
 * @param a_leftover_rate   Rate for buyer-leftover order (ignored if above is false)
 * @param a_tx              [out] Composed trade TX
 * @return Error code; self-purchase prohibited
 */
dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase(
    dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
    uint256_t a_value, bool a_is_budget_buy, uint256_t a_fee, dap_chain_wallet_t *a_wallet,
    bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx);

/**
 * @brief Execute trade against multiple orders in single TX (M:1)
 * @param a_net             Target network
 * @param a_order_hashes    Array of order hashes (root or tail)
 * @param a_orders_count    Number of orders in array
 * @param a_value           Total trade amount (same semantics as purchase)
 * @param a_is_budget_buy   true: budget mode, false: exact sell mode
 * @param a_fee             Validator fee
 * @param a_wallet          Buyer wallet
 * @param a_create_buyer_order_on_leftover Create order from unspent
 * @param a_leftover_rate   Rate for leftover order
 * @param a_tx              [out] Composed trade TX
 * @return Error code; all orders must belong to same canonical pair
 */
dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase_multi(
    dap_chain_net_t *a_net,
    dap_hash_fast_t *a_order_hashes, size_t a_orders_count, uint256_t a_value, bool a_is_budget_buy, uint256_t a_fee,
    dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
    dap_chain_datum_tx_t **a_tx);

/**
 * @brief Auto-match purchase: find best orders and execute trade
 * @param a_net             Target network
 * @param a_sell_token      Token buyer wants to sell
 * @param a_buy_token       Token buyer wants to buy
 * @param a_value           Trade amount (interpretation per a_is_budget_buy)
 * @param a_is_budget_buy   true: budget mode, false: exact sell mode
 * @param a_fee             Validator fee
 * @param a_rate_cap        Rate limit: skip orders with rate > this (0 = no limit)
 * @param a_wallet          Buyer wallet
 * @param a_create_buyer_order_on_leftover Create order from unspent
 * @param a_leftover_rate   Rate for leftover order
 * @param a_tx              [out] Composed TX (can be NULL for dry-run)
 * @return Error code; uses cache for matching, ledger fallback
 */
dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase_auto(
        dap_chain_net_t *a_net,
        const char *a_sell_token, const char *a_buy_token,
        uint256_t a_value, bool a_is_budget_buy, uint256_t a_fee, uint256_t a_rate_cap,
        dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate,
        dap_chain_datum_tx_t **a_tx);

/* ============================================================================
 * Legacy Migration (XCHANGE -> DEX)
 * ============================================================================ */
typedef enum dap_chain_net_srv_dex_migrate_error_list{
    DEX_MIGRATE_ERROR_OK = 0,
    DEX_MIGRATE_ERROR_INVALID_ARGUMENT,
    DEX_MIGRATE_ERROR_PREV_NOT_FOUND,
    DEX_MIGRATE_ERROR_PREV_NOT_XCHANGE,
    DEX_MIGRATE_ERROR_NOT_OWNER,
    DEX_MIGRATE_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_migrate_error_t;

/**
 * @brief Migrate legacy XCHANGE order to DEX (owner-only one-way bridge)
 * @param a_net          Target network
 * @param a_prev_hash    Hash of XCHANGE order TX (must be SRV_XCHANGE subtype)
 * @param a_rate_new     New rate in legacy XCHANGE semantics (BUY per SELL); converted to QUOTE/BASE canonical format
 * @param a_fee          Validator fee in native tokens
 * @param a_wallet       Owner wallet (must match XCHANGE order's seller_addr)
 * @param a_tx           [out] Composed migration TX
 * @return Error code; XCHANGE order consumed, DEX order created
 */
dap_chain_net_srv_dex_migrate_error_t dap_chain_net_srv_dex_migrate(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_prev_hash,
        uint256_t a_rate_new, uint256_t a_fee,
        dap_chain_wallet_t *a_wallet, dap_chain_datum_tx_t **a_tx);

/* ============================================================================
 * Batch Cancellation
 * ============================================================================ */
typedef enum dap_chain_net_srv_dex_cancel_all_error_list{
    DEX_CANCEL_ALL_ERROR_OK = 0,
    DEX_CANCEL_ALL_ERROR_INVALID_ARGUMENT,
    DEX_CANCEL_ALL_ERROR_WALLET,
    DEX_CANCEL_ALL_ERROR_ORDERS_EMPTY,
    DEX_CANCEL_ALL_ERROR_WALLET_MISMATCH,
    DEX_CANCEL_ALL_NOT_ENOUGH_CASH_FOR_FEE,
    DEX_CANCEL_ALL_ERROR_COMPOSE_TX
} dap_chain_net_srv_dex_cancel_all_error_t;

/**
 * @brief Cancel all orders by seller for specific canonical pair (batch invalidation)
 * @param a_net           Target network
 * @param a_seller        Seller address (must match wallet)
 * @param a_base_token    Base token of canonical pair (required)
 * @param a_quote_token   Quote token of canonical pair (required)
 * @param a_limit         Max orders to cancel (0 = unlimited, capped by TX size)
 * @param a_fee           Validator fee in native tokens (covers all cancellations)
 * @param a_wallet        Seller wallet (must match a_seller)
 * @param a_tx            [out] Composed batch cancellation TX
 * @return Error code; creates single TX with multiple IN_CONDs
 */
dap_chain_net_srv_dex_cancel_all_error_t dap_chain_net_srv_dex_cancel_all_by_seller(
        dap_chain_net_t *a_net,
        const dap_chain_addr_t *a_seller,
        const char *a_base_token, const char *a_quote_token,
        int a_limit,
        uint256_t a_fee,
        dap_chain_wallet_t *a_wallet,
        dap_chain_datum_tx_t **a_tx);

/* ============================================================================
 * Governance (Decree Callback)
 * ============================================================================ */

/**
 * @brief Process DEX decree from governance TX
 * @param a_ledger      Network ledger
 * @param a_apply       true: apply changes, false: validation only (dry-run)
 * @param a_params      TSD parameters (method, tokens, fees, etc.)
 * @param a_params_size Size of TSD data
 * @return 0 on success, negative on error
 * @note Methods: FEE_SET(1), PAIR_ADD(2), PAIR_REMOVE(3), PAIR_FEE_SET(4), PAIR_FEE_SET_ALL(5)
 */
int dap_chain_net_srv_dex_decree_callback(dap_ledger_t *a_ledger, bool a_apply, dap_tsd_t *a_params, size_t a_params_size);

/* ============================================================================
 * Debug / Diagnostics
 * ============================================================================ */

/**
 * @brief Dump order cache to log (debug)
 */
void dap_chain_net_srv_dex_dump_orders_cache();

/**
 * @brief Dump history cache to log (debug)
 */
void dap_chain_net_srv_dex_dump_history_cache();

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