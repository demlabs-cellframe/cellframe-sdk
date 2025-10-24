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

#include <string.h>
#include <stdlib.h>
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_net_srv_vpn_multihop.h"
#include "dap_chain_node_client.h"
#include "dap_enc_key.h"
#include "dap_enc.h"
#include "dap_sign.h"
#include "dap_hash.h"

#define LOG_TAG "dap_chain_net_srv_vpn_multihop"

// Global state
static dap_chain_net_srv_vpn_multihop_session_t *s_sessions = NULL;  // Active sessions hash table
static pthread_rwlock_t s_sessions_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static dap_chain_net_t *s_net = NULL;

/**
 * @brief Initialize multi-hop module
 */
int dap_chain_net_srv_vpn_multihop_init(dap_chain_net_t *a_net)
{
    if (!a_net) {
        log_it(L_ERROR, "Network is NULL");
        return -1;
    }
    
    s_net = a_net;
    pthread_rwlock_init(&s_sessions_rwlock, NULL);
    
    log_it(L_NOTICE, "Multi-hop VPN module initialized for network %s", a_net->pub.name);
    return 0;
}

/**
 * @brief Deinitialize multi-hop module
 */
void dap_chain_net_srv_vpn_multihop_deinit(void)
{
    pthread_rwlock_wrlock(&s_sessions_rwlock);
    
    dap_chain_net_srv_vpn_multihop_session_t *l_session, *l_tmp;
    HASH_ITER(hh, s_sessions, l_session, l_tmp) {
        HASH_DEL(s_sessions, l_session);
        dap_chain_net_srv_vpn_multihop_session_delete(l_session);
    }
    
    pthread_rwlock_unlock(&s_sessions_rwlock);
    pthread_rwlock_destroy(&s_sessions_rwlock);
    
    log_it(L_NOTICE, "Multi-hop VPN module deinitialized");
}

/**
 * @brief Create multi-hop session
 */
dap_chain_net_srv_vpn_multihop_session_t* dap_chain_net_srv_vpn_multihop_session_create(
    uint32_t a_session_id,
    dap_chain_hash_fast_t *a_client_pkey_hash,
    dap_chain_node_addr_t *a_route,
    uint8_t a_hop_count,
    uint8_t a_tunnel_count,
    dap_chain_hash_fast_t *a_payment_tx_hash)
{
    if (!a_client_pkey_hash || !a_route || a_hop_count == 0 || 
        a_hop_count > DAP_CHAIN_NET_SRV_VPN_MULTIHOP_MAX_HOPS) {
        log_it(L_ERROR, "Invalid multi-hop session parameters");
        return NULL;
    }
    
    dap_chain_net_srv_vpn_multihop_session_t *l_session = DAP_NEW_Z(dap_chain_net_srv_vpn_multihop_session_t);
    if (!l_session) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    l_session->session_id = a_session_id;
    l_session->client_pkey_hash = *a_client_pkey_hash;
    l_session->hop_count = a_hop_count;
    l_session->current_hop_index = 0;  // Will be set by caller based on position in route
    l_session->tunnel_count = a_tunnel_count > 0 ? a_tunnel_count : 1;
    l_session->active_tunnel_index = 0;
    
    // Copy route
    l_session->route = DAP_NEW_Z_SIZE(dap_chain_node_addr_t, a_hop_count * sizeof(dap_chain_node_addr_t));
    if (!l_session->route) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_session);
        return NULL;
    }
    memcpy(l_session->route, a_route, a_hop_count * sizeof(dap_chain_node_addr_t));
    
    // Allocate space for layer keys (will be populated during handshake)
    l_session->layer_keys = DAP_NEW_Z_SIZE(uint8_t*, a_hop_count * sizeof(uint8_t*));
    l_session->layer_key_sizes = DAP_NEW_Z_SIZE(size_t, a_hop_count * sizeof(size_t));
    
    if (!l_session->layer_keys || !l_session->layer_key_sizes) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_session->route);
        DAP_DELETE(l_session->layer_keys);
        DAP_DELETE(l_session->layer_key_sizes);
        DAP_DELETE(l_session);
        return NULL;
    }
    
    // Copy payment transaction hash
    if (a_payment_tx_hash) {
        l_session->payment_tx_hash = *a_payment_tx_hash;
    }
    
    // Initialize timestamps
    l_session->created_at = time(NULL);
    l_session->last_activity = l_session->created_at;
    
    // Add to hash table
    pthread_rwlock_wrlock(&s_sessions_rwlock);
    HASH_ADD(hh, s_sessions, session_id, sizeof(l_session->session_id), l_session);
    pthread_rwlock_unlock(&s_sessions_rwlock);
    
    log_it(L_INFO, "Created multi-hop session %u: %u hops, %u tunnels",
           a_session_id, a_hop_count, a_tunnel_count);
    
    return l_session;
}

/**
 * @brief Find multi-hop session by ID
 */
dap_chain_net_srv_vpn_multihop_session_t* dap_chain_net_srv_vpn_multihop_session_find(
    uint32_t a_session_id)
{
    dap_chain_net_srv_vpn_multihop_session_t *l_session = NULL;
    
    pthread_rwlock_rdlock(&s_sessions_rwlock);
    HASH_FIND(hh, s_sessions, &a_session_id, sizeof(a_session_id), l_session);
    pthread_rwlock_unlock(&s_sessions_rwlock);
    
    return l_session;
}

/**
 * @brief Delete multi-hop session
 */
void dap_chain_net_srv_vpn_multihop_session_delete(
    dap_chain_net_srv_vpn_multihop_session_t *a_session)
{
    if (!a_session)
        return;
    
    log_it(L_INFO, "Deleting multi-hop session %u (forwarded %"DAP_UINT64_FORMAT_U" bytes)",
           a_session->session_id, a_session->bytes_forwarded);
    
    // Close forward connection if any
    if (a_session->forward_ch) {
        dap_stream_ch_set_ready_to_read_unsafe(a_session->forward_ch, false);
        dap_stream_ch_set_ready_to_write_unsafe(a_session->forward_ch, false);
    }
    
    // Free layer keys
    if (a_session->layer_keys) {
        for (size_t i = 0; i < a_session->hop_count; i++) {
            DAP_DELETE(a_session->layer_keys[i]);
        }
        DAP_DELETE(a_session->layer_keys);
    }
    DAP_DELETE(a_session->layer_key_sizes);
    
    // Free route
    DAP_DELETE(a_session->route);
    
    DAP_DELETE(a_session);
}

/**
 * @brief Process incoming multi-hop packet
 * Decrypts one layer and forwards to next hop
 */
int dap_chain_net_srv_vpn_multihop_packet_process(
    dap_chain_net_srv_vpn_multihop_session_t *a_session,
    const void *a_packet,
    size_t a_packet_size)
{
    if (!a_session || !a_packet || a_packet_size == 0) {
        log_it(L_ERROR, "Invalid packet processing parameters");
        return -1;
    }
    
    // Parse multi-hop header
    if (a_packet_size < sizeof(dap_chain_net_srv_vpn_multihop_hdr_t)) {
        log_it(L_WARNING, "Packet too small for multi-hop header");
        return -2;
    }
    
    const dap_chain_net_srv_vpn_multihop_hdr_t *l_hdr = (const dap_chain_net_srv_vpn_multihop_hdr_t*)a_packet;
    
    // Verify session ID
    if (l_hdr->session_id != a_session->session_id) {
        log_it(L_ERROR, "Session ID mismatch: expected %u, got %u",
               a_session->session_id, l_hdr->session_id);
        return -3;
    }
    
    // Update current hop
    a_session->current_hop_index = l_hdr->current_hop;
    
    // Check if we have decryption key for this layer
    if (a_session->current_hop_index >= a_session->hop_count ||
        !a_session->layer_keys[a_session->current_hop_index]) {
        log_it(L_ERROR, "No decryption key for hop %u", a_session->current_hop_index);
        return -4;
    }
    
    // Decrypt one layer (onion routing style)
    const uint8_t *l_encrypted_payload = (const uint8_t*)a_packet + sizeof(dap_chain_net_srv_vpn_multihop_hdr_t);
    size_t l_encrypted_size = l_hdr->payload_size;
    
    uint8_t *l_decrypted_payload = DAP_NEW_Z_SIZE(uint8_t, l_encrypted_size);
    if (!l_decrypted_payload) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -5;
    }
    
    // Perform decryption using layer key
    // Each hop has its own encryption key, algorithm is determined by key type
    dap_enc_key_t *l_layer_key = (dap_enc_key_t *)a_session->layer_keys[a_session->current_hop_index];
    
    size_t l_decrypted_size = dap_enc_decode(
        l_layer_key,
        l_encrypted_payload,
        l_encrypted_size,
        l_decrypted_payload,
        l_encrypted_size,
        DAP_ENC_DATA_TYPE_RAW
    );
    
    if (l_decrypted_size == 0) {
        log_it(L_ERROR, "Decryption failed for hop %u, session %u",
               a_session->current_hop_index, a_session->session_id);
        DAP_DELETE(l_decrypted_payload);
        return -7;
    }
    
    debug_if(g_debug_level >= L_DEBUG, L_DEBUG,
             "Decrypted %zu bytes (from %zu) at hop %u using key type %d",
             l_decrypted_size, l_encrypted_size, a_session->current_hop_index, l_layer_key->type);
    
    // Update statistics
    a_session->bytes_forwarded += a_packet_size;
    a_session->packets_forwarded++;
    a_session->last_activity = time(NULL);
    
    // Check if this is the last hop
    if (l_hdr->flags & DAP_VPN_MULTIHOP_FLAG_LAST_HOP) {
        log_it(L_DEBUG, "Reached last hop for session %u, delivering packet", a_session->session_id);
        // Deliver to local TUN device
        // Implementation depends on integration with VPN service
        DAP_DELETE(l_decrypted_payload);
        return 0;
    }
    
    // Forward to next hop
    int l_ret = dap_chain_net_srv_vpn_multihop_packet_forward(a_session, l_decrypted_payload, l_decrypted_size);
    DAP_DELETE(l_decrypted_payload);
    
    // Generate conditional receipt if requested
    // Note: Receipt generation now uses standard dap_chain_net_srv_issue_receipt()
    // This should be called from VPN service layer when forwarding thresholds are reached
    // (e.g., every 100MB or 10 minutes), not here in the packet processing loop
    
    return l_ret;
}

/**
 * @brief Forward packet to next hop
 */
int dap_chain_net_srv_vpn_multihop_packet_forward(
    dap_chain_net_srv_vpn_multihop_session_t *a_session,
    const void *a_packet,
    size_t a_packet_size)
{
    if (!a_session || !a_packet || a_packet_size == 0) {
        log_it(L_ERROR, "Invalid forward parameters");
        return -1;
    }
    
    // Check if forward connection is established
    if (!a_session->forward_stream || !a_session->forward_ch) {
        log_it(L_WARNING, "Forward connection not established, establishing now");
        int l_ret = dap_chain_net_srv_vpn_multihop_establish_forward_connection(a_session, s_net);
        if (l_ret < 0) {
            log_it(L_ERROR, "Failed to establish forward connection");
            return -2;
        }
    }
    
    // Select tunnel (load balancing across parallel tunnels)
    uint8_t l_tunnel_idx = dap_chain_net_srv_vpn_multihop_select_tunnel(a_session);
    
    // Forward packet through selected tunnel
    size_t l_written = dap_stream_ch_pkt_write_unsafe(a_session->forward_ch,
                                                        DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA,
                                                        a_packet, a_packet_size);
    
    if (l_written < a_packet_size) {
        log_it(L_WARNING, "Incomplete forward: wrote %zu of %zu bytes", l_written, a_packet_size);
        return -3;
    }
    
    debug_if(g_debug_level >= L_DEBUG, L_DEBUG, "Forwarded %zu bytes to next hop (tunnel %u)",
             a_packet_size, l_tunnel_idx);
    
    return 0;
}

// Note: Receipt creation, verification and freeing now use standard
// dap_chain_net_srv_issue_receipt() and related API from dap_chain_net_srv module.
// Multi-hop specific data is passed via TSD in the a_ext parameter.

/**
 * @brief Establish forward connection to next hop
 */
int dap_chain_net_srv_vpn_multihop_establish_forward_connection(
    dap_chain_net_srv_vpn_multihop_session_t *a_session,
    dap_chain_net_t *a_net)
{
    if (!a_session || !a_net) {
        log_it(L_ERROR, "Invalid forward connection parameters");
        return -1;
    }
    
    // Get next hop address from route
    if (a_session->current_hop_index + 1 >= a_session->hop_count) {
        log_it(L_ERROR, "No next hop in route");
        return -2;
    }
    
    a_session->next_hop_addr = a_session->route[a_session->current_hop_index + 1];
    
    // Create node info for next hop
    dap_chain_node_info_t *l_node_info = dap_chain_node_info_read(a_net, &a_session->next_hop_addr);
    if (!l_node_info) {
        log_it(L_ERROR, "Failed to get node info for next hop");
        return -3;
    }
    
    // Connect to next hop
    dap_chain_node_client_t *l_node_client = dap_chain_node_client_connect_channels(a_net, l_node_info, "R");
    if (!l_node_client) {
        log_it(L_ERROR, "Failed to connect to next hop");
        DAP_DELETE(l_node_info);
        return -4;
    }
    
    a_session->forward_stream = l_node_client->client->stream;
    a_session->forward_ch = a_session->forward_stream->channel[DAP_CHAIN_NET_SRV_VPN_ID];
    
    if (!a_session->forward_ch) {
        log_it(L_ERROR, "VPN channel not available on forward connection");
        dap_chain_node_client_close(l_node_client);
        DAP_DELETE(l_node_info);
        return -5;
    }
    
    log_it(L_INFO, "Established forward connection to next hop");
    DAP_DELETE(l_node_info);
    return 0;
}

/**
 * @brief Select best tunnel from parallel set
 */
uint8_t dap_chain_net_srv_vpn_multihop_select_tunnel(
    dap_chain_net_srv_vpn_multihop_session_t *a_session)
{
    if (!a_session || a_session->tunnel_count == 0)
        return 0;
    
    // Simple round-robin for now
    // Can be enhanced with performance metrics
    a_session->active_tunnel_index = (a_session->active_tunnel_index + 1) % a_session->tunnel_count;
    
    return a_session->active_tunnel_index;
}

