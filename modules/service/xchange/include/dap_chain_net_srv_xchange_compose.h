/**
 * @file dap_chain_net_srv_xchange_compose.h
 * @brief Xchange service transaction compose API
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_chain_tx_compose.h"  // Xchange depends on compose, not vice versa
#include "dap_json.h"

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
    DAP_CHAIN_NET_SRV_XCHANGE_PURCHASE_COMPOSE_ERR_TX_CREATE
} dap_chain_net_srv_xchange_purchase_compose_error_t;

/**
 * @brief Register xchange compose callbacks with compose module
 */
int dap_chain_net_srv_xchange_compose_init(void);

// Xchange compose functions (migrated from modules/compose/)

/**
 * @brief Create price structure from order conditional transaction
 */
dap_chain_net_srv_xchange_price_t *dap_chain_net_srv_xchange_compose_price_from_order(
    dap_chain_tx_out_cond_t *a_cond_tx, 
    dap_time_t a_ts_created, 
    dap_hash_fast_t *a_order_hash, 
    dap_hash_fast_t *a_hash_out, 
    const char *a_token_ticker,
    uint256_t *a_fee, 
    bool a_ret_is_invalid, 
    dap_chain_tx_compose_config_t *a_config);

/**
 * @brief Invalidate xchange transaction (create invalidation tx)
 */
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_compose_tx_invalidate(
    dap_chain_net_srv_xchange_price_t *a_price, 
    dap_chain_tx_out_cond_t *a_cond_tx, 
    dap_chain_addr_t *a_wallet_addr, 
    dap_chain_addr_t *a_seller_addr, 
    const char *a_tx_ticker, 
    uint32_t a_prev_cond_idx, 
    dap_chain_tx_compose_config_t *a_config);

/**
 * @brief Find last transaction in xchange order chain
 * @details Follows the chain of transactions from initial order to the last one
 */
dap_chain_tx_out_cond_t *dap_chain_net_srv_xchange_compose_find_last_tx(
    dap_hash_fast_t *a_order_hash,  
    dap_chain_addr_t *a_seller_addr,  
    dap_chain_tx_compose_config_t *a_config, 
    const char **a_ts_created_str, 
    const char **a_token_ticker, 
    uint32_t *a_prev_cond_idx, 
    dap_hash_fast_t *a_hash_out);

/**
 * @brief Remove xchange order (invalidate order transaction)
 * @param a_hash_tx Order transaction hash to remove
 * @param a_fee Network fee for removal transaction
 * @param a_wallet_addr Wallet address (must be order owner)
 * @param a_config Compose configuration
 * @return Created transaction or NULL on error
 */
dap_chain_datum_tx_t* dap_chain_net_srv_xchange_compose_order_remove(
    dap_hash_fast_t *a_hash_tx, 
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr, 
    dap_chain_tx_compose_config_t *a_config);

/**
 * @brief CLI wrapper for xchange order removal
 */
dap_json_t *dap_chain_net_srv_xchange_compose_cli_order_remove(
    const char *l_net_str, 
    const char *l_order_hash_str, 
    const char *l_fee_str, 
    dap_chain_addr_t *a_wallet_addr, 
    const char *l_url_str, 
    uint16_t l_port, 
    const char *l_cert_path);
