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

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_chain_net.h"
#include "dap_chain_datum_tx.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DAP_CHAIN_NET_SRV_VPN_MULTIHOP_MAX_HOPS 10

/**
 * @brief Multi-hop packet header
 * Used for onion routing with layered encryption
 */
typedef struct dap_chain_net_srv_vpn_multihop_hdr {
    uint8_t version;                    // Protocol version
    uint8_t hop_count;                  // Total number of hops
    uint8_t current_hop;                // Current hop index (0-based)
    uint8_t flags;                      // Flags (e.g., last hop, receipt request)
    uint32_t session_id;                // Multi-hop session ID
    uint32_t packet_id;                 // Packet sequence number
    uint32_t payload_size;              // Size of encrypted payload
    uint8_t next_hop_addr[32];          // Next hop node address (hashed)
} DAP_ALIGN_PACKED dap_chain_net_srv_vpn_multihop_hdr_t;

// Flags for multihop header
#define DAP_VPN_MULTIHOP_FLAG_LAST_HOP      0x01  // This is the last hop
#define DAP_VPN_MULTIHOP_FLAG_RECEIPT_REQ   0x02  // Conditional receipt requested
#define DAP_VPN_MULTIHOP_FLAG_PARALLEL      0x04  // Part of parallel tunnel set

/**
 * @brief Multi-hop session state
 * Tracks active multi-hop sessions
 */
typedef struct dap_chain_net_srv_vpn_multihop_session {
    uint32_t session_id;                // Unique session ID
    dap_chain_hash_fast_t client_pkey_hash;  // Client public key hash
    
    // Route information
    uint8_t hop_count;                  // Total hops in route
    uint8_t current_hop_index;          // Current position in route
    dap_chain_node_addr_t *route;       // Array of node addresses in route
    
    // Parallel tunnels (for load balancing)
    uint8_t tunnel_count;               // Number of parallel tunnels
    uint8_t active_tunnel_index;        // Currently active tunnel
    
    // Encryption keys for layered decryption
    uint8_t **layer_keys;               // Array of decryption keys (one per hop)
    size_t *layer_key_sizes;            // Sizes of decryption keys
    
    // Forward connection (if intermediate hop)
    dap_stream_t *forward_stream;       // Stream to next hop
    dap_stream_ch_t *forward_ch;        // Channel to next hop
    dap_chain_node_addr_t next_hop_addr;// Next hop address
    
    // Receipt tracking
    dap_chain_hash_fast_t payment_tx_hash;  // Original payment transaction
    uint64_t hop_price;                 // Price for this hop
    bool receipt_issued;                // Receipt already issued
    
    // Statistics
    uint64_t bytes_forwarded;           // Bytes forwarded through this hop
    uint64_t packets_forwarded;         // Packets forwarded
    time_t created_at;                  // Session creation time
    time_t last_activity;               // Last packet forwarded
    
    UT_hash_handle hh;                  // Hash table handle
} dap_chain_net_srv_vpn_multihop_session_t;

// Note: Use standard dap_chain_datum_tx_receipt_t from dap_chain_net_srv_issue_receipt()
// Multi-hop data is passed via TSD in the receipt's a_ext parameter

/**
 * @brief Initialize multi-hop module
 * @param a_net Network
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_vpn_multihop_init(dap_chain_net_t *a_net);

/**
 * @brief Deinitialize multi-hop module
 */
void dap_chain_net_srv_vpn_multihop_deinit(void);

/**
 * @brief Create multi-hop session
 * @param a_session_id Unique session ID
 * @param a_client_pkey_hash Client public key hash
 * @param a_route Array of node addresses
 * @param a_hop_count Number of hops
 * @param a_tunnel_count Number of parallel tunnels
 * @param a_payment_tx_hash Payment transaction hash
 * @return Multi-hop session or NULL on error
 */
dap_chain_net_srv_vpn_multihop_session_t* dap_chain_net_srv_vpn_multihop_session_create(
    uint32_t a_session_id,
    dap_chain_hash_fast_t *a_client_pkey_hash,
    dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    uint8_t a_tunnel_count,
    dap_chain_hash_fast_t *a_payment_tx_hash);

/**
 * @brief Find multi-hop session by ID
 * @param a_session_id Session ID
 * @return Multi-hop session or NULL if not found
 */
dap_chain_net_srv_vpn_multihop_session_t* dap_chain_net_srv_vpn_multihop_session_find(
    uint32_t a_session_id);

/**
 * @brief Delete multi-hop session
 * @param a_session Multi-hop session
 */
void dap_chain_net_srv_vpn_multihop_session_delete(
    dap_chain_net_srv_vpn_multihop_session_t *a_session);

/**
 * @brief Process incoming multi-hop packet
 * Decrypts one layer and forwards to next hop (or delivers if last hop)
 * @param a_session Multi-hop session
 * @param a_packet Encrypted packet data
 * @param a_packet_size Packet size
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_vpn_multihop_packet_process(
    dap_chain_net_srv_vpn_multihop_session_t *a_session,
    const void *a_packet,
    size_t a_packet_size);

/**
 * @brief Forward packet to next hop
 * @param a_session Multi-hop session
 * @param a_packet Packet data (already decrypted one layer)
 * @param a_packet_size Packet size
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_vpn_multihop_packet_forward(
    dap_chain_net_srv_vpn_multihop_session_t *a_session,
    const void *a_packet,
    size_t a_packet_size);

// Note: Use dap_chain_net_srv_issue_receipt() for receipt creation
// Use standard receipt verification from dap_chain_net_srv module
// Multi-hop data passed via TSD in a_ext parameter

/**
 * @brief Establish forward connection to next hop
 * @param a_session Multi-hop session
 * @param a_net Network
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_vpn_multihop_establish_forward_connection(
    dap_chain_net_srv_vpn_multihop_session_t *a_session,
    dap_chain_net_t *a_net);

/**
 * @brief Select best tunnel from parallel set
 * Uses load balancing and performance metrics
 * @param a_session Multi-hop session
 * @return Tunnel index
 */
uint8_t dap_chain_net_srv_vpn_multihop_select_tunnel(
    dap_chain_net_srv_vpn_multihop_session_t *a_session);

#ifdef __cplusplus
}
#endif

