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
 *    DAP is free software: you can redistribute it and/or modify
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

#include "tun_device.h"
#include "dap_events_socket.h"
#include "dap_stream_ch.h"
#include "uthash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TUN socket for VPN server
 * Manages TUN device integrated with event loop
 */
typedef struct dap_chain_net_srv_vpn_tun_socket {
    dap_events_socket_t *es;                // Event socket for TUN device
    dap_tun_device_t *tun_device;          // TUN device handle
    dap_worker_t *worker;                   // Worker thread
    uint32_t worker_id;                     // Worker ID
    
    // Client routing table (IP -> VPN channel info)
    struct dap_chain_net_srv_ch_vpn_info *clients;  // Hash table of connected clients
    
    // Inter-worker communication
    dap_events_socket_t **queue_tun_msg_input;  // Input queues from other workers
    
    // Statistics
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    
    // Buffer management
    size_t buf_size_aux;                    // Auxiliary buffer size
} dap_chain_net_srv_vpn_tun_socket_t;

/**
 * @brief VPN channel info for routing
 */
typedef struct dap_chain_net_srv_ch_vpn_info {
    struct in_addr addr_ipv4;               // Client IPv4 address
    struct dap_chain_net_srv_ch_vpn *ch_vpn;  // VPN channel
    dap_worker_t *worker;                   // Worker where channel is active
    dap_events_socket_t *queue_msg;         // Message queue to worker
    dap_events_socket_t *esocket;           // Event socket
    dap_events_socket_uuid_t esocket_uuid;  // Event socket UUID
    uint32_t usage_id;                      // Usage ID
    bool is_on_this_worker;                 // Channel is on this worker
    bool is_reassigned_once;                // Channel was reassigned
    UT_hash_handle hh;                      // Hash table handle
} dap_chain_net_srv_ch_vpn_info_t;

/**
 * @brief TUN socket message types
 */
typedef enum {
    DAP_TUN_MSG_NONE = 0,
    DAP_TUN_MSG_IP_ASSIGNED,                // IP assigned to client
    DAP_TUN_MSG_IP_UNASSIGNED,              // IP unassigned from client
    DAP_TUN_MSG_CH_VPN_SEND,                // Send data to VPN channel
    DAP_TUN_MSG_ESOCKET_REASSIGNED          // Event socket reassigned to another worker
} dap_tun_msg_type_t;

/**
 * @brief TUN socket message
 */
typedef struct dap_tun_socket_msg {
    dap_tun_msg_type_t type;
    struct dap_chain_net_srv_ch_vpn *ch_vpn;
    dap_events_socket_t *esocket;
    dap_events_socket_uuid_t esocket_uuid;
    bool is_reassigned_once;
    
    union {
        struct {  // IP assignment
            uint32_t worker_id;
            struct in_addr addr;
            uint32_t usage_id;
        } ip_assignment;
        
        struct {  // IP unassignment
            uint32_t worker_id;
            struct in_addr addr;
        } ip_unassignment;
        
        struct {  // VPN channel send
            struct dap_stream_ch_vpn_pkt *pkt;
        } ch_vpn_send;
        
        struct {  // Esocket reassignment
            uint32_t worker_id;
            struct in_addr addr;
        } esocket_reassignment;
    };
} dap_tun_socket_msg_t;

/**
 * @brief Initialize TUN device for VPN server
 * @param a_config TUN device configuration
 * @param a_worker_count Number of worker threads
 * @return Array of TUN sockets (one per worker) or NULL on error
 */
dap_chain_net_srv_vpn_tun_socket_t** dap_tun_device_server_init(
    const dap_tun_device_config_t *a_config,
    uint32_t a_worker_count);

/**
 * @brief Deinitialize TUN device for VPN server
 * @param a_tun_sockets Array of TUN sockets
 * @param a_count Number of sockets
 */
void dap_tun_device_server_deinit(
    dap_chain_net_srv_vpn_tun_socket_t **a_tun_sockets,
    uint32_t a_count);

/**
 * @brief Send data to client via TUN device
 * @param a_ch_vpn_info Client VPN channel info
 * @param a_data Data to send
 * @param a_data_size Data size
 * @return true on success, false on error
 */
bool dap_tun_device_server_send_to_client(
    dap_chain_net_srv_ch_vpn_info_t *a_ch_vpn_info,
    const void *a_data,
    size_t a_data_size);

/**
 * @brief Register client IP address
 * @param a_tun_sockets Array of TUN sockets
 * @param a_count Number of sockets
 * @param a_ch_vpn VPN channel
 * @param a_addr Client IP address
 * @param a_usage_id Usage ID
 */
void dap_tun_device_server_register_client(
    dap_chain_net_srv_vpn_tun_socket_t **a_tun_sockets,
    uint32_t a_count,
    struct dap_chain_net_srv_ch_vpn *a_ch_vpn,
    struct in_addr a_addr,
    uint32_t a_usage_id);

/**
 * @brief Unregister client IP address
 * @param a_tun_sockets Array of TUN sockets
 * @param a_count Number of sockets
 * @param a_ch_vpn VPN channel
 * @param a_addr Client IP address
 */
void dap_tun_device_server_unregister_client(
    dap_chain_net_srv_vpn_tun_socket_t **a_tun_sockets,
    uint32_t a_count,
    struct dap_chain_net_srv_ch_vpn *a_ch_vpn,
    struct in_addr a_addr);

#define CH_SF_TUN_SOCKET(a) ((dap_chain_net_srv_vpn_tun_socket_t *)(a)->_inheritor)

#ifdef __cplusplus
}
#endif

