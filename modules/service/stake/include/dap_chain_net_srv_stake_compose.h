/*
 * Authors:
 * Dmitrii Gerasimov <ceo@cellframe.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
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

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_tx_compose.h"
#include "dap_json.h"
#include "dap_hash.h"

// Forward declarations
typedef struct dap_pkey dap_pkey_t;

// Error codes enum (used by xchange service too)
typedef enum {
    SRV_STAKE_ORDER_REMOVE_COMPOSE_OK = 0,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PARAMS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_WALLET_NOT_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_KEY_NOT_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_FEE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ORDER_HASH,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_RPC_RESPONSE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_ADDR,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TAX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_COND_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TOKEN_TICKER,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TS_CREATED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_PRICE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_ENOUGH_FUNDS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_SIGN,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_REMOTE_NODE_UNREACHABLE,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INVALID_RESPONSE_FORMAT,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_ITEMS_FOUND,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_COND_TX,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_TOKEN_TICKER,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NO_TIMESTAMP,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_INSUFFICIENT_FUNDS,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_COMPOSE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_COIN_RETURN_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NET_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_COINBACK_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_FEE_TOO_HIGH,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_VALIDATOR_FEE_FAILED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_TX_ALREADY_USED,
    SRV_STAKE_ORDER_REMOVE_COMPOSE_ERR_NOT_OWNER
} srv_stake_order_remove_compose_error_t;

dap_json_t *dap_chain_tx_compose_stake_lock_take(
    dap_chain_net_id_t a_net_id,
    const char *a_net_name,
    const char *a_native_ticker,
    const char *a_url_str,
    uint16_t a_port,
    const char *a_enc_cert_path,
    dap_chain_addr_t *a_wallet_addr,
    const char *a_tx_str,
    const char *a_value_fee_str);

/**
 * @brief Create stake lock datum transaction
 */
dap_chain_datum_tx_t *dap_chain_tx_compose_datum_stake_lock_hold(
    dap_chain_addr_t *a_wallet_addr,
    const char *a_main_ticker,
    uint256_t a_value,
    uint256_t a_value_fee,
    dap_time_t a_time_staking,
    uint256_t a_reinvest_percent,
    const char *a_delegated_ticker_str,
    uint256_t a_delegated_value,
    dap_chain_id_t a_chain_id,
    dap_chain_tx_compose_config_t *a_config);

/**
 * @brief Create stake unlock datum transaction
 */
dap_chain_datum_tx_t *dap_chain_tx_compose_datum_stake_lock_take(
    dap_chain_addr_t *a_wallet_addr,
    dap_hash_fast_t *a_stake_tx_hash,
    uint32_t a_prev_cond_idx,
    const char *a_main_ticker,
    uint256_t a_value,
    uint256_t a_value_fee,
    const char *a_delegated_ticker_str,
    uint256_t a_delegated_value,
    dap_chain_tx_compose_config_t *a_config);

/**
 * @brief Create stake transaction
 */
dap_chain_datum_tx_t *dap_chain_tx_compose_datum_srv_stake_delegate(
    dap_chain_addr_t *a_wallet_addr,
    uint256_t a_value,
    uint256_t a_fee,
    dap_chain_addr_t *a_signing_addr,
    dap_chain_node_addr_t *a_node_addr,
    dap_chain_addr_t *a_sovereign_addr,
    uint256_t a_sovereign_tax,
    dap_chain_datum_tx_t *a_prev_tx,
    dap_pkey_t *a_pkey,
    dap_chain_tx_compose_config_t *a_config);

/**
 * @brief Invalidate stake transaction
 */
dap_chain_datum_tx_t *dap_chain_tx_compose_datum_srv_stake_invalidate(
    dap_hash_fast_t *a_tx_hash,
    uint256_t a_fee,
    dap_chain_addr_t *a_wallet_addr,
    dap_chain_tx_compose_config_t *a_config);

/**
 * @brief CLI wrapper for stake order creation (staker)
 */
dap_json_t *dap_chain_tx_compose_stake_order_create_staker(
    dap_chain_net_id_t a_net_id,
    const char *a_net_name,
    const char *a_native_ticker,
    const char *a_url_str,
    uint16_t a_port,
    const char *a_enc_cert_path,
    const char *a_value_str,
    const char *a_fee_str,
    const char *a_tax_str,
    const char *a_addr_str,
    dap_chain_addr_t *a_wallet_addr);

/**
 * @brief CLI wrapper for stake delegation
 */
dap_json_t *dap_chain_tx_compose_srv_stake_delegate(
    dap_chain_net_id_t a_net_id,
    const char *a_net_name,
    const char *a_native_ticker,
    const char *a_url_str,
    uint16_t a_port,
    const char *a_enc_cert_path,
    dap_chain_addr_t *a_wallet_addr,
    const char* a_cert_str,
    const char* a_pkey_full_str,
    const char* a_value_str,
    const char* a_node_addr_str,
    const char* a_order_hash_str,
    const char* a_sovereign_addr_str,
    const char* a_fee_str);

/**
 * @brief CLI wrapper for stake invalidation
 */
dap_json_t *dap_chain_tx_compose_srv_stake_invalidate(
    dap_chain_net_id_t a_net_id,
    const char *a_net_name,
    const char *a_native_ticker,
    const char *a_url_str,
    uint16_t a_port,
    const char *a_enc_cert_path,
    const char *a_tx_hash_str,
    dap_chain_addr_t *a_wallet_addr,
    const char *a_cert_str,
    const char *a_fee_str);
/**
 * @brief CLI wrapper for stake hold operation
 */
dap_json_t *dap_chain_tx_compose_stake_lock_hold(
    dap_chain_net_id_t a_net_id,
    const char *a_net_name,
    const char *a_native_ticker,
    const char *a_url_str,
    uint16_t a_port,
    const char *a_enc_cert_path,
    dap_chain_id_t a_chain_id,
    const char *a_ticker_str,
    dap_chain_addr_t *a_wallet_addr,
    const char *a_coins_str,
    const char *a_time_staking_str,
    const char *a_cert_str,
    const char *a_value_fee_str,
    const char *a_reinvest_percent_str);
