/**
 * @file dap_chain_net_srv_xchange_compose.h
 * @brief Xchange service transaction compose API
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_json.h"

// Forward declarations
typedef struct compose_config compose_config_t;
typedef struct dap_chain_addr dap_chain_addr_t;
typedef struct dap_chain_tx_out_cond dap_chain_tx_out_cond_t;

/**
 * @brief Register xchange compose callbacks with compose module
 */
int dap_chain_net_srv_xchange_compose_init(void);

// Xchange compose functions (moved from modules/compose/)

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

dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(
    dap_chain_net_srv_xchange_price_t *a_price, 
    dap_chain_addr_t *a_seller_addr,
    compose_config_t *a_config);

dap_chain_datum_tx_t* dap_chain_net_srv_xchange_create_compose(
    const char *a_token_buy,
    const char *a_token_sell, 
    uint256_t a_datoshi_sell,
    uint256_t a_rate, 
    uint256_t a_fee,
    dap_chain_addr_t *a_seller_addr, 
    compose_config_t *a_config);

dap_json_t* dap_tx_create_xchange_compose(
    const char *l_net_name, 
    const char *l_token_buy, 
    const char *l_token_sell, 
    dap_chain_addr_t *l_wallet_addr, 
    const char *l_value_str, 
    const char *l_rate_str, 
    const char *l_fee_str, 
    const char *l_url_str, 
    uint16_t l_port, 
    const char *l_cert_path);

dap_json_t *dap_cli_xchange_order_remove_compose(
    const char *l_net_str, 
    const char *l_order_hash_str, 
    const char *l_fee_str, 
    dap_chain_addr_t *a_wallet_addr, 
    const char *l_url_str, 
    uint16_t l_port, 
    const char *l_cert_path);

dap_json_t *dap_tx_create_xchange_purchase_compose(
    const char *a_net_name, 
    const char *a_order_hash, 
    const char* a_value,
    const char* a_fee, 
    dap_chain_addr_t* a_wallet_addr, 
    const char *l_url_str, 
    uint16_t l_port, 
    const char *l_cert_path);

dap_chain_tx_out_cond_t* dap_find_last_xchange_tx(
    dap_hash_fast_t *a_order_hash,  
    dap_chain_addr_t *a_seller_addr,  
    compose_config_t * a_config, 
    const char **a_ts_created_str, 
    const char **a_token_ticker, 
    uint32_t *a_prev_cond_idx, 
    dap_hash_fast_t *a_hash_out);

dap_chain_datum_tx_t* dap_chain_net_srv_xchange_purchase_compose(
    dap_hash_fast_t *a_order_hash, 
    uint256_t a_value,
    uint256_t a_fee, 
    dap_chain_addr_t *a_wallet_addr, 
    char **a_hash_out, 
    compose_config_t *a_config);

dap_chain_datum_tx_t *dap_xchange_tx_create_exchange_compose(
    dap_chain_net_srv_xchange_price_t *a_price, 
    dap_chain_addr_t *a_buyer_addr, 
    uint256_t a_datoshi_buy,
    uint256_t a_datoshi_fee, 
    dap_chain_tx_out_cond_t* a_cond_tx, 
    uint32_t a_prev_cond_idx, 
    compose_config_t *a_config);
