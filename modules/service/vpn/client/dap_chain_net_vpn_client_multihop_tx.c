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

#include "include/dap_chain_net_vpn_client_multihop_tx.h"
#include "dap_chain_net_srv_vpn_common.h"
#include "dap_chain_net_srv_vpn_tsd.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_order.h"
#include "dap_global_db.h"
#include "dap_common.h"
#include <string.h>

#define LOG_TAG "vpn_client_multihop_tx"

/**
 * @brief Get service price for a specific hop node
 */
int dap_chain_net_vpn_client_multihop_get_hop_price(
    dap_chain_net_t *a_net,
    const dap_chain_node_addr_t *a_node_addr,
    dap_chain_net_srv_price_unit_uid_t a_unit_type,
    uint256_t *a_price)
{
    if (!a_net || !a_node_addr || !a_price) {
        log_it(L_ERROR, "Invalid arguments for get_hop_price");
        return -1;
    }
    
    // Find service orders for VPN service with SELL direction
    dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    dap_list_t *l_orders = NULL;
    size_t l_orders_count = 0;
    
    // Search for SELL orders matching VPN service and unit type
    int l_ret = dap_chain_net_srv_order_find_all_by(
        a_net,
        SERV_DIR_SELL,
        l_srv_uid,
        a_unit_type,
        NULL,  // any token ticker
        uint256_0,  // min price
        dap_chain_uint256_from(UINT64_MAX),  // max price
        &l_orders,
        &l_orders_count);
    
    if (l_ret != 0 || !l_orders || l_orders_count == 0) {
        log_it(L_WARNING, "No VPN service orders found for node "NODE_ADDR_FP_STR", using default price",
               NODE_ADDR_FP_ARGS_S(*a_node_addr));
        *a_price = dap_chain_uint256_from(1000000000); // 1 token default
        return 0;
    }
    
    // Find order matching node_addr
    dap_chain_net_srv_order_t *l_matching_order = NULL;
    for (dap_list_t *l_iter = l_orders; l_iter; l_iter = l_iter->next) {
        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_iter->data;
        if (l_order && memcmp(&l_order->node_addr, a_node_addr, sizeof(dap_chain_node_addr_t)) == 0) {
            l_matching_order = l_order;
            break;
        }
    }
    
    if (!l_matching_order) {
        log_it(L_WARNING, "No order found for specific node "NODE_ADDR_FP_STR", using first available order",
               NODE_ADDR_FP_ARGS_S(*a_node_addr));
        l_matching_order = (dap_chain_net_srv_order_t *)l_orders->data;
    }
    
    // Extract price from order
    *a_price = l_matching_order->price;
    
    log_it(L_INFO, "Found price for node "NODE_ADDR_FP_STR": %s datoshi",
           NODE_ADDR_FP_ARGS_S(*a_node_addr),
           dap_chain_balance_print(*a_price));
    
    // Clean up order list
    dap_list_free(l_orders);
    
    return 0;
}

/**
 * @brief Serialize multi-hop TSD data for a specific hop
 */
static uint8_t* s_serialize_multihop_tsd(
    uint8_t a_hop_index,
    uint8_t a_total_hops,
    uint8_t a_tunnel_count,
    const dap_chain_node_addr_t *a_route,
    const dap_chain_hash_fast_t *a_prev_tx_hash,
    uint32_t a_session_id,
    size_t *a_out_size)
{
    if (!a_out_size) {
        log_it(L_ERROR, "Output size pointer is NULL");
        return NULL;
    }
    
    // Calculate buffer size for all TSD items
    size_t l_tsd_count = 3; // hop_index, tunnel_count, session_id (always)
    if (a_hop_index == 0 && a_route && a_total_hops > 0) {
        l_tsd_count++; // +route for first hop
    }
    if (a_hop_index > 0 && a_prev_tx_hash) {
        l_tsd_count++; // +prev_hop_tx for hops 2+
    }
    
    // Allocate buffer (rough estimate, will reallocate if needed)
    size_t l_buffer_size = l_tsd_count * (sizeof(dap_chain_tx_tsd_t) + 128);
    uint8_t *l_buffer = DAP_NEW_Z_SIZE(uint8_t, l_buffer_size);
    if (!l_buffer) {
        log_it(L_CRITICAL, "Memory allocation failed for TSD buffer");
        return NULL;
    }
    
    size_t l_offset = 0;
    
    // Add hop_index TSD
    dap_chain_tx_tsd_t *l_tsd_hop = dap_chain_datum_tx_item_tsd_create(
        &a_hop_index, VPN_TSD_TYPE_MULTIHOP_HOP_INDEX, sizeof(a_hop_index));
    if (l_tsd_hop) {
        size_t l_tsd_size = sizeof(dap_chain_tx_tsd_t) + l_tsd_hop->header.size;
        memcpy(l_buffer + l_offset, l_tsd_hop, l_tsd_size);
        l_offset += l_tsd_size;
        DAP_DELETE(l_tsd_hop);
    }
    
    // Add tunnel_count TSD
    dap_chain_tx_tsd_t *l_tsd_tunnels = dap_chain_datum_tx_item_tsd_create(
        &a_tunnel_count, VPN_TSD_TYPE_MULTIHOP_TUNNEL_COUNT, sizeof(a_tunnel_count));
    if (l_tsd_tunnels) {
        size_t l_tsd_size = sizeof(dap_chain_tx_tsd_t) + l_tsd_tunnels->header.size;
        memcpy(l_buffer + l_offset, l_tsd_tunnels, l_tsd_size);
        l_offset += l_tsd_size;
        DAP_DELETE(l_tsd_tunnels);
    }
    
    // Add session_id TSD
    dap_chain_tx_tsd_t *l_tsd_session = dap_chain_datum_tx_item_tsd_create(
        &a_session_id, VPN_TSD_TYPE_MULTIHOP_SESSION_ID, sizeof(a_session_id));
    if (l_tsd_session) {
        size_t l_tsd_size = sizeof(dap_chain_tx_tsd_t) + l_tsd_session->header.size;
        memcpy(l_buffer + l_offset, l_tsd_session, l_tsd_size);
        l_offset += l_tsd_size;
        DAP_DELETE(l_tsd_session);
    }
    
    // For first hop: add full route
    if (a_hop_index == 0 && a_route && a_total_hops > 0) {
        size_t l_route_size = a_total_hops * sizeof(dap_chain_node_addr_t);
        dap_chain_tx_tsd_t *l_tsd_route = dap_chain_datum_tx_item_tsd_create(
            a_route, VPN_TSD_TYPE_MULTIHOP_ROUTE, l_route_size);
        if (l_tsd_route) {
            size_t l_tsd_size = sizeof(dap_chain_tx_tsd_t) + l_tsd_route->header.size;
            if (l_offset + l_tsd_size > l_buffer_size) {
                // Reallocate if needed
                l_buffer = DAP_REALLOC(l_buffer, l_offset + l_tsd_size);
                l_buffer_size = l_offset + l_tsd_size;
            }
            memcpy(l_buffer + l_offset, l_tsd_route, l_tsd_size);
            l_offset += l_tsd_size;
            DAP_DELETE(l_tsd_route);
        }
    }
    
    // For hops 2+: add previous hop TX hash
    // No prev_tx_hash needed - transactions are independent (not a chain)
    
    *a_out_size = l_offset;
    return l_buffer;
}

/**
 * @brief Create a set of independent conditional transactions for multi-hop VPN route
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
    uint32_t a_session_id)
{
    if (!a_wallet || !a_net || !a_route || a_hop_count == 0 || !a_token_ticker) {
        log_it(L_ERROR, "Invalid arguments for multihop TX chain creation");
        return NULL;
    }
    
    // Allocate array for transaction hashes
    dap_chain_hash_fast_t *l_tx_hashes = DAP_NEW_Z_SIZE(dap_chain_hash_fast_t, 
                                                         a_hop_count * sizeof(dap_chain_hash_fast_t));
    if (!l_tx_hashes) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Get wallet key and pkey
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(a_wallet, 0);
    if (!l_key) {
        log_it(L_ERROR, "Failed to get wallet key");
        DAP_DELETE(l_tx_hashes);
        return NULL;
    }
    
    dap_pkey_t *l_pkey = dap_pkey_from_enc_key(l_key);
    if (!l_pkey) {
        log_it(L_ERROR, "Failed to create pkey from wallet key");
        DAP_DELETE(l_tx_hashes);
        return NULL;
    }
    
    dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    uint256_t l_zero_fee = {};
    
    log_it(L_INFO, "Creating TX set for %u-hop route with %u tunnels per hop (each relay gets independent TX)",
           a_hop_count, a_tunnel_count);
    
    // Create independent conditional transaction for each relay node
    for (uint8_t i = 0; i < a_hop_count; i++) {
        // Get price for this hop
        uint256_t l_hop_price = {};
        if (dap_chain_net_vpn_client_multihop_get_hop_price(a_net, &a_route[i], a_unit_type, &l_hop_price) < 0) {
            log_it(L_ERROR, "Failed to get price for hop %u", i);
            goto error_cleanup;
        }
        
        // Serialize multi-hop TSD data for this hop
        size_t l_tsd_size = 0;
        uint8_t *l_tsd_data = s_serialize_multihop_tsd(
            i,                      // hop_index
            a_hop_count,            // total_hops
            a_tunnel_count,         // tunnel_count
            a_route,                // full route (for all hops to know complete path)
            NULL,                   // no prev_tx_hash (transactions are independent)
            a_session_id,           // session_id
            &l_tsd_size
        );
        
        if (!l_tsd_data) {
            log_it(L_ERROR, "Failed to serialize TSD data for hop %u", i);
            goto error_cleanup;
        }
        
        // Create conditional transaction
        char *l_tx_hash_str = dap_chain_mempool_tx_create_cond(
            a_net,
            l_key,
            l_pkey,
            a_token_ticker,
            l_hop_price,            // value for this hop
            l_zero_fee,             // value_per_unit_max (not used for flat-rate)
            a_unit_type,            // price unit (SERV_UNIT_B or SERV_UNIT_SEC)
            l_srv_uid,              // VPN service UID
            l_zero_fee,             // transaction fee
            l_tsd_data,             // multi-hop TSD data
            l_tsd_size,             // TSD data size
            "hex"                   // output format
        );
        
        DAP_DELETE(l_tsd_data);
        
        if (!l_tx_hash_str) {
            log_it(L_ERROR, "Failed to create conditional TX for hop %u", i);
            goto error_cleanup;
        }
        
        // Convert hash string to hash_fast_t and store
        if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hashes[i]) < 0) {
            log_it(L_ERROR, "Failed to parse TX hash for hop %u: %s", i, l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
            goto error_cleanup;
        }
        
        log_it(L_INFO, "Created conditional TX for hop %u (relay "NODE_ADDR_FP_STR"): %s",
               i, NODE_ADDR_FP_ARGS_S(a_route[i]), l_tx_hash_str);
        DAP_DELETE(l_tx_hash_str);
    }
    
    DAP_DELETE(l_pkey);
    
    log_it(L_NOTICE, "Successfully created %u conditional transactions for multi-hop route", a_hop_count);
    return l_tx_hashes;
    
error_cleanup:
    DAP_DELETE(l_pkey);
    DAP_DELETE(l_tx_hashes);
    return NULL;
}

/**
 * @brief Free transaction hash array
 */
void dap_chain_net_vpn_client_multihop_tx_set_free(dap_chain_hash_fast_t *a_tx_hashes)
{
    DAP_DELETE(a_tx_hashes);
}

