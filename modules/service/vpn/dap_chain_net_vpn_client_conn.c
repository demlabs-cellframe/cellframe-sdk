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

#include <string.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_client_pvt.h"
#include "dap_stream_ch_pkt.h"
#include "dap_chain_net_srv_ch.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_vpn_client_conn.h"

#define LOG_TAG "dap_chain_net_vpn_conn"

// Forward declarations
static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg);
static void s_stage_error_callback(dap_client_t *a_client, void *a_arg);

/**
 * @brief Create VPN connection and connect to server
 */
dap_chain_net_vpn_conn_t *dap_chain_net_vpn_conn_create(
    dap_chain_net_t *a_net,
    const char *a_host,
    uint16_t a_port,
    dap_chain_net_vpn_conn_callbacks_t *a_callbacks,
    void *a_callbacks_arg)
{
    if (!a_net || !a_host || !a_port) {
        log_it(L_ERROR, "Invalid arguments for VPN connection");
        return NULL;
    }
    
    dap_chain_net_vpn_conn_t *l_conn = DAP_NEW_Z(dap_chain_net_vpn_conn_t);
    if (!l_conn) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    l_conn->net = a_net;
    l_conn->port = a_port;
    dap_strncpy(l_conn->host, a_host, DAP_HOSTADDR_STRLEN);
    
    if (a_callbacks)
        l_conn->callbacks = *a_callbacks;
    l_conn->callbacks_arg = a_callbacks_arg;
    
    // Init synchronization
    pthread_mutex_init(&l_conn->state_mutex, NULL);
    pthread_cond_init(&l_conn->state_cond, NULL);
    l_conn->state = VPN_CONN_STATE_CONNECTING;
    
    // Create underlying client
    l_conn->client = dap_client_new(s_stage_connected_callback, s_stage_error_callback);
    if (!l_conn->client) {
        log_it(L_ERROR, "Failed to create dap_client for VPN connection");
        pthread_mutex_destroy(&l_conn->state_mutex);
        pthread_cond_destroy(&l_conn->state_cond);
        DAP_DELETE(l_conn);
        return NULL;
    }
    
    // Store back reference
    l_conn->client->_inheritor = l_conn;
    
    // Set active channels: R (service) and S (vpn)
    const char l_channels[] = { DAP_CHAIN_NET_SRV_CH_ID, DAP_CHAIN_NET_SRV_VPN_CH_ID, '\0' };
    l_conn->client->active_channels = dap_strdup(l_channels);
    
    // Connect
    log_it(L_INFO, "Connecting VPN to %s:%u", a_host, a_port);
    dap_client_set_uplink_unsafe(l_conn->client, NULL, a_host, a_port);
    dap_client_go_stage(l_conn->client, STAGE_STREAM_STREAMING, NULL);
    
    return l_conn;
}

/**
 * @brief Callback when connection is established
 */
static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg)
{
    UNUSED(a_arg);
    dap_chain_net_vpn_conn_t *l_conn = (dap_chain_net_vpn_conn_t *)a_client->_inheritor;
    if (!l_conn)
        return;
    
    log_it(L_NOTICE, "VPN connection to %s:%u established", l_conn->host, l_conn->port);
    
    // Get stream references
    dap_client_pvt_t *l_client_pvt = DAP_CLIENT_PVT(a_client);
    if (l_client_pvt && l_client_pvt->stream_es) {
        l_conn->esocket_uuid = l_client_pvt->stream_es->uuid;
        l_conn->stream_worker = dap_client_get_stream_worker(a_client);
    }
    
    // Get channel UUIDs
    dap_stream_ch_t *l_ch_srv = dap_client_get_stream_ch_unsafe(a_client, DAP_CHAIN_NET_SRV_CH_ID);
    if (l_ch_srv)
        l_conn->ch_srv_uuid = l_ch_srv->uuid;
    
    dap_stream_ch_t *l_ch_vpn = dap_client_get_stream_ch_unsafe(a_client, DAP_CHAIN_NET_SRV_VPN_CH_ID);
    if (l_ch_vpn)
        l_conn->ch_vpn_uuid = l_ch_vpn->uuid;
    
    // Update state and signal waiters
    pthread_mutex_lock(&l_conn->state_mutex);
    l_conn->state = VPN_CONN_STATE_CONNECTED;
    pthread_cond_broadcast(&l_conn->state_cond);
    pthread_mutex_unlock(&l_conn->state_mutex);
    
    // Call user callback
    if (l_conn->callbacks.connected)
        l_conn->callbacks.connected(l_conn, l_conn->callbacks_arg);
}

/**
 * @brief Callback on connection error
 */
static void s_stage_error_callback(dap_client_t *a_client, void *a_arg)
{
    UNUSED(a_arg);
    dap_chain_net_vpn_conn_t *l_conn = (dap_chain_net_vpn_conn_t *)a_client->_inheritor;
    if (!l_conn)
        return;
    
    log_it(L_ERROR, "VPN connection error to %s:%u", l_conn->host, l_conn->port);
    
    // Update state and signal waiters
    pthread_mutex_lock(&l_conn->state_mutex);
    bool l_was_connected = (l_conn->state == VPN_CONN_STATE_CONNECTED);
    l_conn->state = VPN_CONN_STATE_ERROR;
    pthread_cond_broadcast(&l_conn->state_cond);
    pthread_mutex_unlock(&l_conn->state_mutex);
    
    // Call appropriate callback
    if (l_was_connected && l_conn->callbacks.disconnected)
        l_conn->callbacks.disconnected(l_conn, l_conn->callbacks_arg);
    else if (l_conn->callbacks.error)
        l_conn->callbacks.error(l_conn, l_conn->callbacks_arg);
}

/**
 * @brief Wait for connection to be established
 */
int dap_chain_net_vpn_conn_wait(dap_chain_net_vpn_conn_t *a_conn, int a_timeout_ms)
{
    if (!a_conn)
        return -2;
    
    pthread_mutex_lock(&a_conn->state_mutex);
    
    // Already connected or errored?
    if (a_conn->state == VPN_CONN_STATE_CONNECTED) {
        pthread_mutex_unlock(&a_conn->state_mutex);
        return 0;
    }
    if (a_conn->state == VPN_CONN_STATE_ERROR || a_conn->state == VPN_CONN_STATE_DISCONNECTED) {
        pthread_mutex_unlock(&a_conn->state_mutex);
        return -2;
    }
    
    // Wait with timeout
    struct timespec l_ts;
    clock_gettime(CLOCK_REALTIME, &l_ts);
    l_ts.tv_sec += a_timeout_ms / 1000;
    l_ts.tv_nsec += (a_timeout_ms % 1000) * 1000000;
    if (l_ts.tv_nsec >= 1000000000) {
        l_ts.tv_sec++;
        l_ts.tv_nsec -= 1000000000;
    }
    
    int l_ret = 0;
    while (a_conn->state == VPN_CONN_STATE_CONNECTING) {
        int l_rc = pthread_cond_timedwait(&a_conn->state_cond, &a_conn->state_mutex, &l_ts);
        if (l_rc == ETIMEDOUT) {
            l_ret = -1;  // Timeout
            break;
        }
    }
    
    if (l_ret == 0 && a_conn->state != VPN_CONN_STATE_CONNECTED)
        l_ret = -2;  // Error
    
    pthread_mutex_unlock(&a_conn->state_mutex);
    return l_ret;
}

/**
 * @brief Get stream channel by ID
 */
dap_stream_ch_t *dap_chain_net_vpn_conn_get_ch(dap_chain_net_vpn_conn_t *a_conn, uint8_t a_ch_id)
{
    if (!a_conn || !a_conn->client || a_conn->state != VPN_CONN_STATE_CONNECTED)
        return NULL;
    
    return dap_client_get_stream_ch_unsafe(a_conn->client, a_ch_id);
}

/**
 * @brief Close VPN connection
 */
void dap_chain_net_vpn_conn_close(dap_chain_net_vpn_conn_t *a_conn)
{
    if (!a_conn)
        return;
    
    log_it(L_INFO, "Closing VPN connection to %s:%u", a_conn->host, a_conn->port);
    
    pthread_mutex_lock(&a_conn->state_mutex);
    a_conn->state = VPN_CONN_STATE_DISCONNECTED;
    pthread_cond_broadcast(&a_conn->state_cond);
    pthread_mutex_unlock(&a_conn->state_mutex);
    
    if (a_conn->client) {
        a_conn->client->_inheritor = NULL;
        dap_client_delete_unsafe(a_conn->client);
        a_conn->client = NULL;
    }
    
    pthread_mutex_destroy(&a_conn->state_mutex);
    pthread_cond_destroy(&a_conn->state_cond);
    
    DAP_DELETE(a_conn);
}

