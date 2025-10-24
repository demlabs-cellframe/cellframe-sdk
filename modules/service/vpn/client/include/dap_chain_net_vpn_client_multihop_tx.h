/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2021-2025
 * All rights reserved.
 *
 * This file is part of DAP SDK the open source project
 *
 *    DAP SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_chain_common.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a set of independent conditional transactions for multi-hop VPN route
 * 
 * Creates one conditional transaction for EACH relay node in the route.
 * Each transaction is INDEPENDENT (not a chain) - pays directly to its relay node.
 * Each transaction includes multi-hop specific TSD data (hop_index, session_id, etc).
 * 
 * @param a_wallet Client wallet for signing transactions
 * @param a_net Network to create transactions on
 * @param a_route Array of node addresses for the route
 * @param a_hop_count Number of hops in the route
 * @param a_tunnel_count Number of parallel tunnels per hop
 * @param a_service_units Service units to purchase (bytes or seconds)
 * @param a_unit_type Unit type (SERV_UNIT_B or SERV_UNIT_SEC)
 * @param a_token_ticker Token ticker for payment (e.g., "KEL", "CELL")
 * @param a_session_id Multi-hop session ID
 * @return Array of transaction hashes (caller must free with DAP_DELETE), or NULL on error
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
 * @brief Get service price for a specific hop node
 * 
 * Queries GDB for the VPN service price published by the node.
 * 
 * @param a_net Network
 * @param a_node_addr Node address
 * @param a_unit_type Unit type to query price for
 * @param[out] a_price Output: price value in datoshi
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_multihop_get_hop_price(
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_node_addr,
    dap_chain_net_srv_price_unit_uid_t a_unit_type,
    uint256_t *a_price);

/**
 * @brief Free transaction hash array
 * 
 * @param a_tx_hashes Array of transaction hashes
 */
void dap_chain_net_vpn_client_multihop_tx_set_free(dap_chain_hash_fast_t *a_tx_hashes);

#ifdef __cplusplus
}
#endif

