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

// Error codes for xchange compose operations
typedef enum dap_chain_net_srv_xchange_compose_error {
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_OK = 0,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_OWNER,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH
} dap_chain_net_srv_xchange_compose_error_t;

/**
 * @brief Register xchange compose callbacks with compose module
 */
int dap_chain_net_srv_xchange_compose_init(void);

// Xchange compose functions (partial migration - most remain in modules/compose/)

dap_chain_net_srv_xchange_price_t *dap_chain_net_srv_xchange_price_from_order_compose(
    dap_chain_tx_out_cond_t *a_cond_tx, 
    dap_time_t a_ts_created, 
    dap_hash_fast_t *a_order_hash, 
    dap_hash_fast_t *a_hash_out, 
    const char *a_token_ticker,
    uint256_t *a_fee, 
    bool a_ret_is_invalid, 
    compose_config_t *a_config);

dap_chain_datum_tx_t* dap_xchange_tx_invalidate_compose(
    dap_chain_net_srv_xchange_price_t *a_price, 
    dap_chain_tx_out_cond_t *a_cond_tx, 
    dap_chain_addr_t *a_wallet_addr, 
    dap_chain_addr_t *a_seller_addr, 
    const char *a_tx_ticker, 
    uint32_t a_prev_cond_idx, 
    compose_config_t *a_config);
