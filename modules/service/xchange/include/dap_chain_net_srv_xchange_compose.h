/**
 * @file dap_chain_net_srv_xchange_compose.h
 * @brief Xchange service transaction compose API
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_tx_compose_api.h"  // NEW: Plugin-based TX compose API
#include "dap_json.h"
#include "dap_ledger.h"  // For ledger access

// Forward declarations
typedef struct dap_ledger dap_ledger_t;

// Error codes for xchange purchase compose operations
typedef enum dap_chain_net_srv_xchange_purchase_compose_error {
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NONE = 0,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_PARAMS,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_ITEMS_FOUND,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_COND_TX,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TOKEN_TICKER,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_NO_TIMESTAMP,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_PRICE_CREATE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FEE,
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_FUNDS
} dap_chain_net_srv_xchange_purchase_compose_error_t;

/**
 * @brief Register xchange TX builders with TX Compose Plugin API
 */
int dap_chain_net_srv_xchange_compose_init(void);

/**
 * @brief Unregister xchange TX builders
 */
void dap_chain_net_srv_xchange_compose_deinit(void);

// ========== TX BUILDER API (creates unsigned transactions) ==========

/**
 * @brief Create xchange order transaction (PURE TX builder)
 * @param a_ledger Ledger for UTXO selection
 * @param a_token_buy Token ticker to buy
 * @param a_token_sell Token ticker to sell
 * @param a_datoshi_sell Amount to sell
 * @param a_rate Exchange rate
 * @param a_fee Transaction fee
 * @param a_wallet_addr Wallet address for signing and change
 * @return Unsigned transaction or NULL on error
 */
dap_chain_datum_tx_t* dap_xchange_tx_create_order(
    dap_ledger_t *a_ledger,
    const char *a_token_buy,
    const char *a_token_sell,
    uint256_t a_datoshi_sell,
    uint256_t a_rate,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr);

/**
 * @brief Invalidate xchange order (PURE TX builder)
 * @param a_ledger Ledger for transaction lookup
 * @param a_order_hash Order transaction hash to invalidate
 * @param a_fee Transaction fee
 * @param a_wallet_addr Wallet address (must be order owner)
 * @return Unsigned transaction or NULL on error
 */
dap_chain_datum_tx_t *dap_xchange_tx_create_invalidate(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_order_hash,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr);

/**
 * @brief Create xchange purchase transaction (PURE TX builder)
 * @param a_ledger Ledger for UTXO selection
 * @param a_order_hash Order to purchase from
 * @param a_value Amount to purchase
 * @param a_fee Transaction fee
 * @param a_wallet_addr Buyer wallet address
 * @return Unsigned transaction or NULL on error
 */
dap_chain_datum_tx_t *dap_xchange_tx_create_purchase(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_order_hash,
    uint256_t a_value,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr);

// ========== HELPER FUNCTIONS ==========

/**
 * @brief Create price structure from order conditional transaction
 * @param a_ledger Ledger context
 * @param a_cond_tx Conditional transaction output
 * @param a_ts_created Timestamp when created
 * @param a_order_hash Order hash
 * @param a_hash_out Output hash
 * @param a_token_ticker Token ticker
 * @param a_fee Fee pointer
 * @param a_ret_is_invalid Return invalid flag
 * @return Price structure or NULL on error
 */
dap_chain_net_srv_xchange_price_t *dap_xchange_price_from_order(
    dap_ledger_t *a_ledger,
    dap_chain_tx_out_cond_t *a_cond_tx, 
    dap_time_t a_ts_created, 
    dap_hash_fast_t *a_order_hash, 
    dap_hash_fast_t *a_hash_out, 
    const char *a_token_ticker,
    uint256_t *a_fee, 
    bool a_ret_is_invalid);

/**
 * @brief Find last transaction in xchange order chain
 * @param a_ledger Ledger to search in
 * @param a_order_hash Initial order hash
 * @param a_seller_addr Seller address
 * @param a_ts_created Output: timestamp created
 * @param a_token_ticker Output: token ticker (caller must free)
 * @param a_prev_cond_idx Output: previous conditional index
 * @param a_hash_out Output: transaction hash
 * @return Last conditional output or NULL
 */
dap_chain_tx_out_cond_t *dap_xchange_find_last_tx(
    dap_ledger_t *a_ledger,
    dap_hash_fast_t *a_order_hash,
    dap_chain_addr_t *a_seller_addr,
    dap_time_t *a_ts_created,
    char **a_token_ticker,
    int32_t *a_prev_cond_idx,
    dap_hash_fast_t *a_hash_out);

// ========== CLI/RPC WRAPPERS (return JSON responses) ==========

/**
 * @brief CLI wrapper for xchange order creation
 * @details Creates order, signs it, puts to mempool, returns JSON response
 */
dap_json_t *dap_chain_tx_compose_xchange_create(
    dap_chain_net_id_t a_net_id,
    const char *a_token_sell,
    const char *a_token_buy,
    dap_chain_addr_t *a_wallet_addr,
    const char *a_value_str,
    const char *a_rate_str,
    const char *a_fee_str);

/**
 * @brief CLI wrapper for xchange order removal
 * @details Invalidates order, signs, puts to mempool, returns JSON
 */
dap_json_t *dap_chain_tx_compose_xchange_order_remove(
    dap_chain_net_id_t a_net_id,
    const char *a_order_hash_str,
    const char *a_fee_str,
    dap_chain_addr_t *a_wallet_addr);

/**
 * @brief CLI wrapper for xchange purchase
 * @details Creates purchase TX, signs, puts to mempool, returns JSON
 */
dap_json_t *dap_chain_tx_compose_xchange_purchase(
    dap_chain_net_id_t a_net_id,
    const char *a_order_hash,
    const char* a_value,
    const char* a_fee,
    dap_chain_addr_t *a_wallet_addr);
