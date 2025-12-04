/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024
 * All rights reserved.

 This file is part of CellFrame SDK

 CellFrame SDK is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 CellFrame SDK is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <pthread.h>
#include <stdbool.h>

#include "dap_client.h"
#include "dap_chain_net.h"
#include "dap_stream_ch.h"
#include "dap_stream_worker.h"

typedef struct dap_chain_net_vpn_conn dap_chain_net_vpn_conn_t;

// Callbacks for VPN connection events
typedef void (*dap_chain_net_vpn_conn_callback_t)(dap_chain_net_vpn_conn_t *a_conn, void *a_arg);

typedef struct dap_chain_net_vpn_conn_callbacks {
    dap_chain_net_vpn_conn_callback_t connected;
    dap_chain_net_vpn_conn_callback_t disconnected;
    dap_chain_net_vpn_conn_callback_t error;
} dap_chain_net_vpn_conn_callbacks_t;

// VPN connection state
typedef enum dap_chain_net_vpn_conn_state {
    VPN_CONN_STATE_DISCONNECTED = 0,
    VPN_CONN_STATE_CONNECTING,
    VPN_CONN_STATE_CONNECTED,
    VPN_CONN_STATE_ERROR
} dap_chain_net_vpn_conn_state_t;

// VPN connection structure - async client for long-lived VPN connections
struct dap_chain_net_vpn_conn {
    dap_client_t                       *client;          // Underlying async client
    dap_chain_net_t                    *net;             // Network context
    
    // Connection state
    pthread_mutex_t                     state_mutex;
    pthread_cond_t                      state_cond;
    volatile dap_chain_net_vpn_conn_state_t state;
    
    // Stream references (set after connection)
    dap_stream_worker_t                *stream_worker;
    dap_events_socket_uuid_t            esocket_uuid;
    
    // Channel UUIDs for service and VPN channels
    dap_stream_ch_uuid_t                ch_srv_uuid;     // Channel 'R'
    dap_stream_ch_uuid_t                ch_vpn_uuid;     // Channel 'S'
    
    // Callbacks
    dap_chain_net_vpn_conn_callbacks_t  callbacks;
    void                               *callbacks_arg;
    
    // Host info
    char                                host[DAP_HOSTADDR_STRLEN + 1];
    uint16_t                            port;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create VPN connection and connect to server
 * @param a_net Network
 * @param a_host Server host
 * @param a_port Server port
 * @param a_callbacks Optional callbacks
 * @param a_callbacks_arg Callbacks argument
 * @return VPN connection or NULL on error
 */
dap_chain_net_vpn_conn_t *dap_chain_net_vpn_conn_create(
    dap_chain_net_t *a_net,
    const char *a_host,
    uint16_t a_port,
    dap_chain_net_vpn_conn_callbacks_t *a_callbacks,
    void *a_callbacks_arg
);

/**
 * @brief Wait for connection to be established
 * @param a_conn VPN connection
 * @param a_timeout_ms Timeout in milliseconds
 * @return 0 on success, -1 on timeout, -2 on error
 */
int dap_chain_net_vpn_conn_wait(dap_chain_net_vpn_conn_t *a_conn, int a_timeout_ms);

/**
 * @brief Get stream channel by ID
 * @param a_conn VPN connection
 * @param a_ch_id Channel ID
 * @return Stream channel or NULL
 */
dap_stream_ch_t *dap_chain_net_vpn_conn_get_ch(dap_chain_net_vpn_conn_t *a_conn, uint8_t a_ch_id);

/**
 * @brief Get stream worker
 * @param a_conn VPN connection
 * @return Stream worker or NULL
 */
DAP_STATIC_INLINE dap_stream_worker_t *dap_chain_net_vpn_conn_get_stream_worker(dap_chain_net_vpn_conn_t *a_conn)
{
    return a_conn ? a_conn->stream_worker : NULL;
}

/**
 * @brief Check if connected
 * @param a_conn VPN connection
 * @return true if connected
 */
DAP_STATIC_INLINE bool dap_chain_net_vpn_conn_is_connected(dap_chain_net_vpn_conn_t *a_conn)
{
    return a_conn && a_conn->state == VPN_CONN_STATE_CONNECTED;
}

/**
 * @brief Close VPN connection
 * @param a_conn VPN connection
 */
void dap_chain_net_vpn_conn_close(dap_chain_net_vpn_conn_t *a_conn);

#ifdef __cplusplus
}
#endif

