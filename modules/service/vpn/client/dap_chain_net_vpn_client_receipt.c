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

#include "dap_chain_net_vpn_client_receipt.h"
#include "dap_chain_net_srv_vpn_tsd.h"
#include "dap_sign.h"
#include "dap_cert.h"
#include "dap_common.h"
#include <string.h>
#include <time.h>

#define LOG_TAG "vpn_client_receipt"

/**
 * @brief Create receipt collector for multi-hop session
 */
dap_vpn_client_receipt_collector_t* dap_vpn_client_receipt_collector_create(
    uint32_t a_session_id,
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    const dap_chain_hash_fast_t *a_payment_tx_hashes)
{
    if (!a_net || !a_route || a_hop_count == 0 || !a_payment_tx_hashes) {
        log_it(L_ERROR, "Invalid arguments for receipt collector creation");
        return NULL;
    }
    
    dap_vpn_client_receipt_collector_t *l_collector = DAP_NEW_Z(dap_vpn_client_receipt_collector_t);
    if (!l_collector) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    l_collector->session_id = a_session_id;
    l_collector->hop_count = a_hop_count;
    l_collector->net = a_net;
    l_collector->created_at = time(NULL);
    l_collector->receipts_received_count = 0;
    
    // Allocate arrays
    l_collector->route = DAP_NEW_Z_SIZE(dap_chain_node_addr_t, a_hop_count * sizeof(dap_chain_node_addr_t));
    l_collector->payment_tx_hashes = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, a_hop_count * sizeof(dap_chain_hash_fast_t));
    l_collector->receipts = DAP_NEW_Z_SIZE(dap_chain_datum_tx_receipt_t*, a_hop_count * sizeof(dap_chain_datum_tx_receipt_t*));
    l_collector->receipt_received = DAP_NEW_Z_SIZE(bool, a_hop_count * sizeof(bool));
    
    if (!l_collector->route || !l_collector->payment_tx_hashes || 
        !l_collector->receipts || !l_collector->receipt_received) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_vpn_client_receipt_collector_delete(l_collector);
        return NULL;
    }
    
    // Copy route and TX hashes
    memcpy(l_collector->route, a_route, a_hop_count * sizeof(dap_chain_node_addr_t));
    memcpy(l_collector->payment_tx_hashes, a_payment_tx_hashes, a_hop_count * sizeof(dap_chain_hash_fast_t));
    
    log_it(L_NOTICE, "Created receipt collector for session %u (%u hops)", a_session_id, a_hop_count);
    return l_collector;
}

/**
 * @brief Delete receipt collector
 */
void dap_vpn_client_receipt_collector_delete(dap_vpn_client_receipt_collector_t *a_collector)
{
    if (!a_collector)
        return;
    
    // Free all collected receipts
    if (a_collector->receipts) {
        for (uint8_t i = 0; i < a_collector->hop_count; i++) {
            DAP_DELETE(a_collector->receipts[i]);
        }
    }
    
    DAP_DELETE(a_collector->route);
    DAP_DELETE(a_collector->payment_tx_hashes);
    DAP_DELETE(a_collector->receipts);
    DAP_DELETE(a_collector->receipt_received);
    DAP_DELETE(a_collector);
}

/**
 * @brief Verify receipt signature and parameters
 */
bool dap_vpn_client_receipt_verify(
    const dap_chain_datum_tx_receipt_t *a_receipt,
    dap_chain_net_t *a_net,
    uint8_t a_expected_hop_index,
    const dap_chain_hash_fast_t *a_expected_payment_tx,
    const dap_chain_node_addr_t *a_node_addr)
{
    if (!a_receipt || !a_net || !a_expected_payment_tx || !a_node_addr) {
        log_it(L_ERROR, "Invalid arguments for receipt verification");
        return false;
    }
    
    // Check receipt has at least one signature (provider signature)
    if (a_receipt->size < sizeof(dap_chain_datum_tx_receipt_t)) {
        log_it(L_WARNING, "Receipt too small");
        return false;
    }
    
    // Parse multi-hop TSD from receipt extensions
    if (a_receipt->exts_size > 0 && a_receipt->exts_n_signs) {
        // Find multi-hop extension data
        const uint8_t *l_ext_data = a_receipt->exts_n_signs;
        size_t l_ext_offset = 0;
        
        // Parse TSD items from extensions
        while (l_ext_offset < a_receipt->exts_size) {
            dap_chain_tx_tsd_t *l_tsd = (dap_chain_tx_tsd_t *)(l_ext_data + l_ext_offset);
            
            // Check hop_index
            if (l_tsd->header.type == VPN_TSD_TYPE_MULTIHOP_HOP_INDEX) {
                uint8_t l_hop_index = 0;
                memcpy(&l_hop_index, l_tsd->data, sizeof(l_hop_index));
                if (l_hop_index != a_expected_hop_index) {
                    log_it(L_WARNING, "Receipt hop_index mismatch: expected %u, got %u",
                           a_expected_hop_index, l_hop_index);
                    return false;
                }
            }
            
            l_ext_offset += sizeof(dap_chain_tx_tsd_t) + l_tsd->header.size;
        }
    }
    
    // Verify receipt signature
    // Note: Provider's signature should be first in exts_n_signs
    size_t l_signs_offset = a_receipt->exts_size;
    if (l_signs_offset < a_receipt->size) {
        dap_sign_t *l_sign = (dap_sign_t*)(a_receipt->exts_n_signs + l_signs_offset);
        
        // Serialize receipt data for verification (without signature)
        size_t l_data_size = sizeof(dap_chain_datum_tx_receipt_t) + a_receipt->exts_size;
        
        // Verify signature
        // Note: Need to get provider's public key from node certificate
        // This requires node info lookup - implementation depends on node registry
        log_it(L_DEBUG, "Receipt signature verification placeholder - implement with node cert lookup");
    }
    
    // Verify payment TX hash matches
    if (memcmp(&a_receipt->receipt_info.prev_tx_hash, a_expected_payment_tx, sizeof(dap_chain_hash_fast_t)) != 0) {
        log_it(L_WARNING, "Receipt payment_tx_hash mismatch");
        return false;
    }
    
    return true;
}

/**
 * @brief Add received receipt to collector
 */
int dap_vpn_client_receipt_collector_add(
    dap_vpn_client_receipt_collector_t *a_collector,
    dap_chain_datum_tx_receipt_t *a_receipt,
    uint8_t a_hop_index)
{
    if (!a_collector || !a_receipt) {
        log_it(L_ERROR, "Invalid arguments for receipt collector add");
        return -1;
    }
    
    if (a_hop_index >= a_collector->hop_count) {
        log_it(L_ERROR, "Hop index %u out of range (max %u)", a_hop_index, a_collector->hop_count - 1);
        return -2;
    }
    
    if (a_collector->receipt_received[a_hop_index]) {
        log_it(L_WARNING, "Receipt for hop %u already received", a_hop_index);
        return -3;
    }
    
    // Verify receipt
    if (!dap_vpn_client_receipt_verify(
            a_receipt,
            a_collector->net,
            a_hop_index,
            &a_collector->payment_tx_hashes[a_hop_index],
            &a_collector->route[a_hop_index])) {
        log_it(L_ERROR, "Receipt verification failed for hop %u", a_hop_index);
        return -4;
    }
    
    // Store receipt
    a_collector->receipts[a_hop_index] = a_receipt;
    a_collector->receipt_received[a_hop_index] = true;
    a_collector->receipts_received_count++;
    
    log_it(L_INFO, "Added receipt for hop %u (session %u), total: %u/%u",
           a_hop_index, a_collector->session_id,
           a_collector->receipts_received_count, a_collector->hop_count);
    
    return 0;
}

/**
 * @brief Check if all receipts collected
 */
bool dap_vpn_client_receipt_collector_is_complete(
    const dap_vpn_client_receipt_collector_t *a_collector)
{
    if (!a_collector)
        return false;
    
    return (a_collector->receipts_received_count == a_collector->hop_count);
}

/**
 * @brief Get receipt for specific hop
 */
dap_chain_datum_tx_receipt_t* dap_vpn_client_receipt_collector_get(
    const dap_vpn_client_receipt_collector_t *a_collector,
    uint8_t a_hop_index)
{
    if (!a_collector || a_hop_index >= a_collector->hop_count)
        return NULL;
    
    return a_collector->receipts[a_hop_index];
}

/**
 * @brief Get all collected receipts
 */
dap_chain_datum_tx_receipt_t** dap_vpn_client_receipt_collector_get_all(
    const dap_vpn_client_receipt_collector_t *a_collector,
    uint8_t *a_count)
{
    if (!a_collector || !a_count)
        return NULL;
    
    *a_count = a_collector->receipts_received_count;
    return a_collector->receipts;
}

