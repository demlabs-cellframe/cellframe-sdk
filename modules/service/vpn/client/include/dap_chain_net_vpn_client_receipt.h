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

#include "dap_chain_datum_tx.h"
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Multi-hop receipt collection and verification for VPN client
 * 
 * Manages collection of receipts from all relay nodes in multi-hop route.
 * Uses standard dap_chain_datum_tx_receipt_t from dap_chain_net_srv module.
 */

/**
 * @brief Receipt collector context for multi-hop session
 */
typedef struct dap_vpn_client_receipt_collector {
    uint32_t session_id;                        // Multi-hop session ID
    uint8_t hop_count;                          // Total hops in route
    dap_chain_node_addr_t *route;              // Route (for verification)
    dap_chain_hash_fast_t *payment_tx_hashes;  // Payment TX hashes for each hop
    
    dap_chain_datum_tx_receipt_t **receipts;   // Collected receipts (one per hop)
    bool *receipt_received;                     // Flags for received receipts
    uint8_t receipts_received_count;            // Number of receipts collected
    
    time_t created_at;                          // Collector creation time
    dap_chain_net_t *net;                       // Network for verification
} dap_vpn_client_receipt_collector_t;

/**
 * @brief Create receipt collector for multi-hop session
 * 
 * @param a_session_id Multi-hop session ID
 * @param a_net Network
 * @param a_route Route (array of node addresses)
 * @param a_hop_count Number of hops
 * @param a_payment_tx_hashes Payment transaction hashes for each hop
 * @return Receipt collector or NULL on error
 */
dap_vpn_client_receipt_collector_t* dap_vpn_client_receipt_collector_create(
    uint32_t a_session_id,
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    const dap_chain_hash_fast_t *a_payment_tx_hashes);

/**
 * @brief Delete receipt collector and free all receipts
 * 
 * @param a_collector Receipt collector
 */
void dap_vpn_client_receipt_collector_delete(dap_vpn_client_receipt_collector_t *a_collector);

/**
 * @brief Add received receipt to collector and verify it
 * 
 * Verifies receipt signature, hop_index, payment_tx_hash, and other parameters.
 * 
 * @param a_collector Receipt collector
 * @param a_receipt Receipt to add (ownership transferred to collector)
 * @param a_hop_index Expected hop index for this receipt
 * @return 0 on success, negative on error (invalid receipt, wrong hop, etc)
 */
int dap_vpn_client_receipt_collector_add(
    dap_vpn_client_receipt_collector_t *a_collector,
    dap_chain_datum_tx_receipt_t *a_receipt,
    uint8_t a_hop_index);

/**
 * @brief Check if all receipts have been collected
 * 
 * @param a_collector Receipt collector
 * @return true if all receipts received and verified
 */
bool dap_vpn_client_receipt_collector_is_complete(
    const dap_vpn_client_receipt_collector_t *a_collector);

/**
 * @brief Get receipt for specific hop
 * 
 * @param a_collector Receipt collector
 * @param a_hop_index Hop index
 * @return Receipt pointer (do not free - owned by collector), or NULL if not received
 */
dap_chain_datum_tx_receipt_t* dap_vpn_client_receipt_collector_get(
    const dap_vpn_client_receipt_collector_t *a_collector,
    uint8_t a_hop_index);

/**
 * @brief Get all collected receipts
 * 
 * @param a_collector Receipt collector
 * @param[out] a_count Output: number of receipts
 * @return Array of receipts (do not free - owned by collector), or NULL
 */
dap_chain_datum_tx_receipt_t** dap_vpn_client_receipt_collector_get_all(
    const dap_vpn_client_receipt_collector_t *a_collector,
    uint8_t *a_count);

/**
 * @brief Verify receipt signature and parameters
 * 
 * @param a_receipt Receipt to verify
 * @param a_net Network
 * @param a_expected_hop_index Expected hop index
 * @param a_expected_payment_tx Expected payment TX hash
 * @param a_node_addr Node address (for signature verification)
 * @return true if valid, false otherwise
 */
bool dap_vpn_client_receipt_verify(
    const dap_chain_datum_tx_receipt_t *a_receipt,
    dap_chain_net_t *a_net,
    uint8_t a_expected_hop_index,
    const dap_chain_hash_fast_t *a_expected_payment_tx,
    const dap_chain_node_addr_t *a_node_addr);

#ifdef __cplusplus
}
#endif

