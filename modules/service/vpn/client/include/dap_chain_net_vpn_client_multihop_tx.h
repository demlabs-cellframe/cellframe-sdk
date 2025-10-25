/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 *    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file dap_chain_net_vpn_client_multihop_tx.h
 * @brief VPN Client Multi-hop Payment Transaction Management
 * @details Functions for creating and managing payment transactions for multi-hop VPN routes
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#pragma once

#include <stdint.h>
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_srv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get price for a specific hop in multi-hop route
 * @param a_net Network context
 * @param a_node_addr Node address to query price for
 * @param a_unit_type Service unit type (bytes, seconds, etc.)
 * @param a_price Output: price in datoshi
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_multihop_get_hop_price(
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_node_addr,
    dap_chain_net_srv_price_unit_uid_t a_unit_type,
    uint256_t *a_price);

/**
 * @brief Create payment transaction set for multi-hop VPN route
 * @param a_wallet Wallet to create transactions from
 * @param a_net Network context
 * @param a_route Array of node addresses (complete route)
 * @param a_hop_count Number of hops in route
 * @param a_tunnel_count Number of parallel tunnels per hop
 * @param a_service_units Amount of service units to purchase
 * @param a_unit_type Service unit type (bytes, seconds, etc.)
 * @param a_token_ticker Token ticker for payment (e.g., "KEL")
 * @param a_session_id Multi-hop session ID
 * @return Array of payment TX hashes (one per hop) or NULL on error
 */
dap_chain_hash_fast_t* dap_chain_net_vpn_client_multihop_tx_set_create(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    uint8_t a_tunnel_count,
    uint64_t a_service_units,
    dap_chain_net_srv_price_unit_uid_t a_unit_type,
    const char *a_token_ticker,
    uint32_t a_session_id);

/**
 * @brief Free payment transaction set
 * @param a_tx_hashes Array of payment TX hashes to free
 */
void dap_chain_net_vpn_client_multihop_tx_set_free(dap_chain_hash_fast_t *a_tx_hashes);

#ifdef __cplusplus
}
#endif
