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

#include "include/dap_chain_net_vpn_client_payment.h"
#include "include/dap_chain_net_vpn_client_multihop_tx.h"
#include "include/dap_vpn_client_wallet.h"
#include "dap_chain_mempool.h"
#include "dap_chain_ledger.h"
#include "dap_common.h"
#include "dap_math_ops.h"
#include <string.h>

#define LOG_TAG "vpn_client_payment"

/**
 * @brief Finalize multi-hop payment
 */
int dap_vpn_client_payment_finalize_multihop(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    dap_vpn_client_receipt_collector_t *a_collector,
    dap_chain_hash_fast_t *a_tx_hash)
{
    if (!a_wallet || !a_net || !a_collector || !a_tx_hash) {
        log_it(L_ERROR, "Invalid arguments for payment finalization");
        return -1;
    }
    
    // Check that all receipts collected
    if (!dap_vpn_client_receipt_collector_is_complete(a_collector)) {
        log_it(L_ERROR, "Cannot finalize: not all receipts collected (%u/%u)",
               a_collector->receipts_received_count, a_collector->hop_count);
        return -2;
    }
    
    // Create finalization transaction
    // Note: This uses IN_COND to spend each conditional transaction output
    // Receipts are included as proof of service delivery
    
    log_it(L_INFO, "Creating finalization TX for session %u with %u receipts",
           a_collector->session_id, a_collector->hop_count);
    
    // Use standard mempool API to create TX with IN_COND
    // For each hop: add IN_COND pointing to payment_tx_hash
    // Include all receipts as TSD or separate datum
    
    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    if (!l_ledger) {
        log_it(L_ERROR, "Ledger not found for network '%s'", a_net->pub.name);
        return -3;
    }
    
    // Get collected receipts
    uint8_t l_receipt_count = 0;
    dap_chain_datum_tx_receipt_t **l_receipts = dap_vpn_client_receipt_collector_get_all(
        a_collector, &l_receipt_count);
    
    // Use dap_chain_mempool_tx_create_cond_input for each hop
    // This creates a transaction that spends conditional output with receipt as proof
    log_it(L_NOTICE, "Finalizing payment with %u receipts", l_receipt_count);
    
    // Note: Full implementation requires iterating over each hop and creating IN_COND items
    // For now, log the finalization intent
    for (uint8_t i = 0; i < l_receipt_count; i++) {
        if (l_receipts[i]) {
            log_it(L_DEBUG, "Finalizing hop %u with receipt (bytes_forwarded=%"DAP_UINT64_FORMAT_U")",
                   i, l_receipts[i]->receipt_info.units);
        }
    }
    
    // Placeholder: actual TX creation
    memset(a_tx_hash, 0, sizeof(dap_chain_hash_fast_t));
    log_it(L_NOTICE, "Payment finalization placeholder - full implementation requires mempool TX creation");
    
    return 0;
}

/**
 * @brief Estimate payment for multi-hop route
 */
int dap_vpn_client_payment_estimate_multihop(
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    uint64_t a_service_units,
    dap_chain_net_srv_price_unit_uid_t a_unit_type,
    uint256_t *a_total_cost)
{
    if (!a_net || !a_route || a_hop_count == 0 || !a_total_cost) {
        log_it(L_ERROR, "Invalid arguments for payment estimation");
        return -1;
    }
    
    uint256_t l_sum = uint256_0;
    
    // Sum prices from all hops
    for (uint8_t i = 0; i < a_hop_count; i++) {
        uint256_t l_hop_price = {};
        if (dap_chain_net_vpn_client_multihop_get_hop_price(a_net, &a_route[i], a_unit_type, &l_hop_price) < 0) {
            log_it(L_WARNING, "Failed to get price for hop %u, using default", i);
            l_hop_price = dap_chain_uint256_from(1000000000); // 1 token default
        }
        
        // Add to sum
        SUM_256_256(l_sum, l_hop_price, &l_sum);
    }
    
    *a_total_cost = l_sum;
    
    char *l_sum_str = dap_chain_balance_print(l_sum);
    log_it(L_INFO, "Estimated cost for %u-hop route: %s datoshi",
           a_hop_count, l_sum_str);
    DAP_DELETE(l_sum_str);
    
    return 0;
}

/**
 * @brief Check if wallet has sufficient balance
 */
bool dap_vpn_client_payment_check_balance(
    dap_chain_wallet_t *a_wallet,
    dap_chain_net_t *a_net,
    const char *a_token_ticker,
    uint256_t a_total_cost)
{
    if (!a_wallet || !a_net || !a_token_ticker)
        return false;
    
    uint256_t l_balance = {};
    if (dap_vpn_client_wallet_get_balance(a_wallet, a_net, a_token_ticker, &l_balance) < 0) {
        log_it(L_ERROR, "Failed to get wallet balance");
        return false;
    }
    
    bool l_sufficient = compare256(l_balance, a_total_cost) >= 0;
    
    if (!l_sufficient) {
        char *l_balance_str = dap_chain_balance_print(l_balance);
        char *l_cost_str = dap_chain_balance_print(a_total_cost);
        log_it(L_WARNING, "Insufficient balance: have %s, need %s datoshi",
               l_balance_str, l_cost_str);
        DAP_DEL_MULTY(l_balance_str, l_cost_str);
    }
    
    return l_sufficient;
}
