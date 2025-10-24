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

#include "dap_chain_wallet.h"
#include "dap_chain_net.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_net_vpn_client_receipt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Multi-hop payment finalization
 * 
 * After collecting all receipts from relay nodes, finalize payment by creating
 * a transaction that spends the conditional outputs using collected receipts as proof.
 */

/**
 * @brief Finalize multi-hop payment
 * 
 * Creates a finalization transaction with IN_COND for each hop's conditional transaction.
 * Includes all collected receipts as proof of service delivery.
 * 
 * @param a_wallet Client wallet for signing
 * @param a_net Network
 * @param a_collector Receipt collector with all collected receipts
 * @param[out] a_tx_hash Output: finalization transaction hash
 * @return 0 on success, negative on error
 */
int dap_vpn_client_payment_finalize_multihop(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    dap_vpn_client_receipt_collector_t *a_collector,
    dap_chain_hash_fast_t *a_tx_hash);

/**
 * @brief Estimate payment for multi-hop route
 * 
 * @param a_net Network
 * @param a_route Route (array of node addresses)
 * @param a_hop_count Number of hops
 * @param a_service_units Service units (bytes or seconds)
 * @param a_unit_type Unit type
 * @param[out] a_total_cost Output: total cost in datoshi
 * @return 0 on success, negative on error
 */
int dap_vpn_client_payment_estimate_multihop(
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    uint64_t a_service_units,
    dap_chain_net_srv_price_unit_uid_t a_unit_type,
    uint256_t *a_total_cost);

/**
 * @brief Check if wallet has sufficient balance for multi-hop route
 * 
 * @param a_wallet Wallet
 * @param a_net Network
 * @param a_token_ticker Token ticker
 * @param a_total_cost Required amount
 * @return true if balance sufficient, false otherwise
 */
bool dap_vpn_client_payment_check_balance(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token_ticker,
    uint256_t a_total_cost);

#ifdef __cplusplus
}
#endif

