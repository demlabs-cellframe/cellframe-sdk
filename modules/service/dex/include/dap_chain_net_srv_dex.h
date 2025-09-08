/*
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

// Match criteria
typedef struct dex_match_criteria {
    const char *sell_token;    // what the buyer wants to get
    const char *buy_token;     // what the buyer pays
    dap_chain_net_id_t sell_net_id;
    dap_chain_net_id_t buy_net_id;
    uint256_t max_buy_value;   // amount in buy_token
    uint256_t min_rate;        // rate threshold (minimum acceptable for the buyer)
} dex_match_criteria_t;

// Match API retained, but internal representation changed; see implementation
dap_hash_fast_t *dap_chain_net_srv_dex_match_hashes(dap_chain_net_t *a_net, const char *a_sell_token, const char *a_buy_token,
    dap_chain_net_id_t *a_sell_net_id, dap_chain_net_id_t *a_buy_net_id,
    uint256_t *a_max_buy_value, uint256_t *a_min_rate, size_t *a_num_matches);
    
int dap_chain_net_srv_dex_init();
void dap_chain_net_srv_dex_deinit();

// Create order
typedef enum dap_chain_net_srv_dex_create_error_list{
    DEX_CREATE_ERROR_OK = 0,
    DEX_CREATE_ERROR_INVALID_ARGUMENT,
    DEX_CREATE_ERROR_TOKEN_TICKER_SELL_NOT_FOUND,
    DEX_CREATE_ERROR_TOKEN_TICKER_BUY_NOT_FOUND,
    DEX_CREATE_ERROR_RATE_IS_ZERO,
    DEX_CREATE_ERROR_FEE_IS_ZERO,
    DEX_CREATE_ERROR_VALUE_SELL_IS_ZERO,
    DEX_CREATE_ERROR_INTEGER_OVERFLOW,
    DEX_CREATE_ERROR_NOT_ENOUGH_CASH_FOR_FEE,
    DEX_CREATE_ERROR_NOT_ENOUGH_CASH,
    DEX_CREATE_ERROR_COMPOSE_TX,
    DEX_CREATE_ERROR_MEMPOOL_PUT
} dap_chain_net_srv_dex_create_error_t;

dap_chain_net_srv_dex_create_error_t dap_chain_net_srv_dex_create(dap_chain_net_t *a_net, const char *a_token_buy,
                                      const char *a_token_sell, uint256_t a_value_sell,
                                      uint256_t a_rate, uint8_t a_min_fill_combined,
                                      uint256_t a_fee, dap_chain_wallet_t *a_wallet,
                                      char *a_out_tx_hash);

// Remove (invalidate) order by root or tail hash
typedef enum dap_chain_net_srv_dex_remove_error_list{
    DEX_REMOVE_ERROR_OK = 0,
    DEX_REMOVE_ERROR_INVALID_ARGUMENT,
    DEX_REMOVE_ERROR_FEE_IS_ZERO,
    DEX_REMOVE_ERROR_TX_NOT_FOUND,
    DEX_REMOVE_ERROR_INVALID_OUT,
    DEX_REMOVE_ERROR_NOT_OWNER,
    DEX_REMOVE_ERROR_COMPOSE_TX,
    DEX_REMOVE_ERROR_MEMPOOL_PUT
} dap_chain_net_srv_dex_remove_error_t;

dap_chain_net_srv_dex_remove_error_t dap_chain_net_srv_dex_remove(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
                                      uint256_t a_fee, dap_chain_wallet_t *a_wallet, char *a_out_tx_hash);

/* Update (modify) order by owner */
typedef enum dap_chain_net_srv_dex_update_error_list{
    DEX_UPDATE_ERROR_OK = 0,
    DEX_UPDATE_ERROR_INVALID_ARGUMENT,
    DEX_UPDATE_ERROR_NOT_FOUND,
    DEX_UPDATE_ERROR_NOT_OWNER,
    DEX_UPDATE_ERROR_COMPOSE_TX,
    DEX_UPDATE_ERROR_MEMPOOL_PUT
} dap_chain_net_srv_dex_update_error_t;

dap_chain_net_srv_dex_update_error_t dap_chain_net_srv_dex_update(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_order_root,
        bool a_has_new_rate, uint256_t a_new_rate,
        bool a_has_new_value, uint256_t a_new_value,
        uint256_t a_fee, dap_chain_wallet_t *a_wallet,
        char *a_hash_out);

// Purchase against single order
typedef enum dap_chain_net_srv_dex_purchase_error_list{
    DEX_PURCHASE_ERROR_OK = 0,
    DEX_PURCHASE_ERROR_INVALID_ARGUMENT,
    DEX_PURCHASE_ERROR_ORDER_NOT_FOUND,
    DEX_PURCHASE_ERROR_COMPOSE_TX,
    DEX_PURCHASE_ERROR_MEMPOOL_PUT
} dap_chain_net_srv_dex_purchase_error_t;

dap_chain_net_srv_dex_purchase_error_t dap_chain_net_srv_dex_purchase(dap_chain_net_t *a_net, dap_hash_fast_t *a_order_hash,
                                        uint256_t a_value_buy, uint256_t a_fee, dap_chain_wallet_t *a_wallet, char *a_hash_out);

// Multi-purchase against list of orders (M:1). Orders must belong to one pair (sell/buy).
typedef enum dap_chain_net_srv_dex_purchase_multi_error_list{
    DEX_PURCHASE_MULTI_ERROR_OK = 0,
    DEX_PURCHASE_MULTI_ERROR_INVALID_ARGUMENT,
    DEX_PURCHASE_MULTI_ERROR_ORDERS_EMPTY,
    DEX_PURCHASE_MULTI_ERROR_PAIR_MISMATCH,
    DEX_PURCHASE_MULTI_ERROR_COMPOSE_TX,
    DEX_PURCHASE_MULTI_ERROR_MEMPOOL_PUT
} dap_chain_net_srv_dex_purchase_multi_error_t;

dap_chain_net_srv_dex_purchase_multi_error_t dap_chain_net_srv_dex_purchase_multi(dap_chain_net_t *a_net,
        dap_hash_fast_t *a_order_hashes, size_t a_orders_count, uint256_t a_value_buy, uint256_t a_fee,
        dap_chain_wallet_t *a_wallet, bool a_create_buyer_order_on_leftover, uint256_t a_leftover_rate, char *a_hash_out);

// Legacy migration from SRV_XCHANGE to SRV_DEX (owner-only bridge)
typedef enum dap_chain_net_srv_dex_migrate_error_list{
    DEX_MIGRATE_ERROR_OK = 0,
    DEX_MIGRATE_ERROR_INVALID_ARGUMENT,
    DEX_MIGRATE_ERROR_PREV_NOT_FOUND,
    DEX_MIGRATE_ERROR_PREV_NOT_XCHANGE,
    DEX_MIGRATE_ERROR_COMPOSE_TX,
    DEX_MIGRATE_ERROR_NOT_OWNER,
    DEX_MIGRATE_ERROR_MEMPOOL_PUT
} dap_chain_net_srv_dex_migrate_error_t;

dap_chain_net_srv_dex_migrate_error_t dap_chain_net_srv_dex_migrate(
        dap_chain_net_t *a_net, dap_hash_fast_t *a_prev_hash,
        uint256_t a_rate_new, uint256_t a_fee,
        dap_chain_wallet_t *a_wallet, char *a_out_tx_hash);

