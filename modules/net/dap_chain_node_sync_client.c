/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

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

#include <time.h>
#include <errno.h>
#include <string.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "dap_common.h"
#include "dap_config.h"
#include "dap_timerfd.h"
#include "dap_client.h"
#include "dap_client_pvt.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_chain_node_sync_client.h"

#define LOG_TAG "dap_chain_node_sync_client"

// Forward declarations
static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg);
static void s_stage_error_callback(dap_client_t *a_client, void *a_arg);
static void s_universal_packet_in_callback(dap_stream_ch_t *a_ch, uint8_t a_type, 
                                           const void *a_data, size_t a_data_size, void *a_arg);

/**
 * @brief Initialize sync client module
 */
int dap_chain_node_sync_client_init(void)
{
    log_it(L_NOTICE, "Node sync client module initialized");
    return 0;
}

/**
 * @brief Deinitialize sync client module
 */
void dap_chain_node_sync_client_deinit(void)
{
    log_it(L_NOTICE, "Node sync client module deinitialized");
}

/**
 * @brief Get error description string
 */
const char *dap_chain_node_sync_error_str(dap_chain_node_sync_error_t a_error)
{
    switch (a_error) {
        case DAP_SYNC_ERROR_NONE:               return "No error";
        case DAP_SYNC_ERROR_MEMORY:             return "Memory allocation failed";
        case DAP_SYNC_ERROR_INVALID_ARGS:       return "Invalid arguments";
        case DAP_SYNC_ERROR_CONNECT_FAILED:     return "Connection failed";
        case DAP_SYNC_ERROR_CONNECT_TIMEOUT:    return "Connection timeout";
        case DAP_SYNC_ERROR_DISCONNECTED:       return "Disconnected";
        case DAP_SYNC_ERROR_SEND_FAILED:        return "Send failed";
        case DAP_SYNC_ERROR_REQUEST_TIMEOUT:    return "Request timeout";
        case DAP_SYNC_ERROR_CHANNEL_NOT_FOUND:  return "Channel not found";
        case DAP_SYNC_ERROR_INTERNAL:           return "Internal error";
        default:                                return "Unknown error";
    }
}

/**
 * @brief Try to match incoming packet to pending requests
 */
static void s_try_match_response(dap_chain_node_sync_client_t *a_sync_client,
                                  uint8_t a_channel_id,
                                  uint8_t a_pkt_type,
                                  const void *a_pkt_data,
                                  size_t a_pkt_size)
{
    if (!a_sync_client)
        return;
    
    pthread_rwlock_rdlock(&a_sync_client->requests_lock);
    
    dap_chain_node_sync_request_t *l_request, *l_tmp;
    HASH_ITER(hh, a_sync_client->pending_requests, l_request, l_tmp) {
        // Check channel match
        if (l_request->channel_id != a_channel_id)
            continue;
        
        // Use matcher for response correlation (required)
        if (!l_request->matcher)
            continue;
            
        bool l_matched = l_request->matcher(l_request, a_pkt_type,
                                            a_pkt_data, a_pkt_size,
                                            l_request->matcher_arg);
        
        if (l_matched) {
            pthread_mutex_lock(&l_request->mutex);
            // Copy response data
            if (a_pkt_data && a_pkt_size > 0) {
                l_request->response_data = DAP_DUP_SIZE((void *)a_pkt_data, a_pkt_size);
                l_request->response_size = a_pkt_size;
            }
            l_request->status = SYNC_REQUEST_STATUS_COMPLETED;
            pthread_cond_signal(&l_request->cond);
            pthread_mutex_unlock(&l_request->mutex);
            break;
        }
    }
    
    pthread_rwlock_unlock(&a_sync_client->requests_lock);
}

/**
 * @brief Universal packet in callback for any channel
 * Uses dap_stream_ch notifier mechanism
 */
static void s_universal_packet_in_callback(dap_stream_ch_t *a_ch, uint8_t a_type, 
                                           const void *a_data, size_t a_data_size, void *a_arg)
{
    dap_chain_node_sync_client_t *l_sync_client = (dap_chain_node_sync_client_t *)a_arg;
    if (!l_sync_client || !a_ch || !a_ch->proc)
        return;
    
    uint8_t l_channel_id = a_ch->proc->id;
    s_try_match_response(l_sync_client, l_channel_id, a_type, a_data, a_data_size);
}

/**
 * @brief Add universal notifier for all active channels
 */
static void s_add_channel_notifiers(dap_chain_node_sync_client_t *a_sync_client)
{
    if (!a_sync_client || !a_sync_client->client || !a_sync_client->client->active_channels)
        return;
    
    dap_stream_node_addr_t *l_addr = (dap_stream_node_addr_t *)&a_sync_client->node_info->address;
    const char *l_channels = a_sync_client->client->active_channels;
    
    for (size_t i = 0; l_channels[i]; i++) {
        uint8_t l_ch_id = l_channels[i];
        int l_ret = dap_stream_ch_add_notifier(l_addr, l_ch_id, DAP_STREAM_PKT_DIR_IN,
                                               s_universal_packet_in_callback, a_sync_client);
        if (l_ret == 0)
            log_it(L_DEBUG, "Added sync notifier for channel '%c'", l_ch_id);
        else
            log_it(L_WARNING, "Failed to add sync notifier for channel '%c': %d", l_ch_id, l_ret);
    }
}

/**
 * @brief Remove universal notifier from all active channels
 */
static void s_del_channel_notifiers(dap_chain_node_sync_client_t *a_sync_client)
{
    if (!a_sync_client || !a_sync_client->client || !a_sync_client->client->active_channels)
        return;
    
    dap_stream_node_addr_t *l_addr = (dap_stream_node_addr_t *)&a_sync_client->node_info->address;
    const char *l_channels = a_sync_client->client->active_channels;
    
    for (size_t i = 0; l_channels[i]; i++) {
        uint8_t l_ch_id = l_channels[i];
        dap_stream_ch_del_notifier(l_addr, l_ch_id, DAP_STREAM_PKT_DIR_IN,
                                   s_universal_packet_in_callback, a_sync_client);
    }
}

/**
 * @brief Connection established callback
 */
static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg)
{
    dap_chain_node_sync_client_t *l_sync_client = (dap_chain_node_sync_client_t *)a_arg;
    if (!l_sync_client)
        return;
    
    log_it(L_NOTICE, "Sync client connected to %s:%u",
           l_sync_client->node_info->ext_host, l_sync_client->node_info->ext_port);
    
    l_sync_client->esocket_uuid = DAP_CLIENT_PVT(a_client)->stream_es->uuid;
    l_sync_client->stream_worker = DAP_CLIENT_PVT(a_client)->stream_worker;
    
    // Add universal notifier for all active channels
    s_add_channel_notifiers(l_sync_client);
    
    // Signal connection established
    pthread_mutex_lock(&l_sync_client->conn_mutex);
    l_sync_client->is_connected = true;
    l_sync_client->is_connecting = false;
    l_sync_client->conn_error = 0;
    pthread_cond_signal(&l_sync_client->conn_cond);
    pthread_mutex_unlock(&l_sync_client->conn_mutex);
}

/**
 * @brief Connection error callback
 */
static void s_stage_error_callback(dap_client_t *a_client, void *a_arg)
{
    dap_chain_node_sync_client_t *l_sync_client = (dap_chain_node_sync_client_t *)a_arg;
    if (!l_sync_client)
        return;
    
    bool l_is_last_attempt = a_arg ? true : false;
    
    log_it(L_WARNING, "Sync client connection error%s", l_is_last_attempt ? " (last attempt)" : "");
    
    if (l_is_last_attempt) {
        pthread_mutex_lock(&l_sync_client->conn_mutex);
        l_sync_client->is_connected = false;
        l_sync_client->is_connecting = false;
        l_sync_client->conn_error = DAP_SYNC_ERROR_CONNECT_FAILED;
        pthread_cond_signal(&l_sync_client->conn_cond);
        pthread_mutex_unlock(&l_sync_client->conn_mutex);
        
        // Wake up all pending requests with error
        pthread_rwlock_rdlock(&l_sync_client->requests_lock);
        dap_chain_node_sync_request_t *l_request, *l_tmp;
        HASH_ITER(hh, l_sync_client->pending_requests, l_request, l_tmp) {
            pthread_mutex_lock(&l_request->mutex);
            l_request->status = SYNC_REQUEST_STATUS_ERROR;
            l_request->error_code = DAP_SYNC_ERROR_DISCONNECTED;
            pthread_cond_signal(&l_request->cond);
            pthread_mutex_unlock(&l_request->mutex);
        }
        pthread_rwlock_unlock(&l_sync_client->requests_lock);
    }
}

/**
 * @brief Create and connect sync client
 */
dap_chain_node_sync_client_t *dap_chain_node_sync_client_connect(
    dap_chain_net_t *a_net,
    dap_chain_node_info_t *a_node_info,
    const char *a_channels,
    int a_timeout_ms)
{
    if (!a_net || !a_node_info) {
        log_it(L_ERROR, "Invalid arguments for sync client connect");
        return NULL;
    }
    
    if (!a_node_info->ext_host[0] || !a_node_info->ext_port) {
        log_it(L_ERROR, "Node info has no valid address");
        return NULL;
    }
    
    // Allocate sync client
    dap_chain_node_sync_client_t *l_sync_client = DAP_NEW_Z(dap_chain_node_sync_client_t);
    if (!l_sync_client) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Copy node info
    l_sync_client->node_info = DAP_DUP_SIZE(a_node_info, 
                                             sizeof(dap_chain_node_info_t) + a_node_info->ext_host_len + 1);
    if (!l_sync_client->node_info) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_sync_client);
        return NULL;
    }
    
    l_sync_client->net = a_net;
    l_sync_client->is_connecting = true;
    atomic_init(&l_sync_client->request_id_counter, 1);
    
    // Initialize synchronization primitives
    pthread_mutex_init(&l_sync_client->conn_mutex, NULL);
    pthread_rwlock_init(&l_sync_client->requests_lock, NULL);
    
    pthread_condattr_t l_condattr;
    pthread_condattr_init(&l_condattr);
#ifndef DAP_OS_DARWIN
    pthread_condattr_setclock(&l_condattr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&l_sync_client->conn_cond, &l_condattr);
    pthread_condattr_destroy(&l_condattr);
    
    // Create underlying async client
    l_sync_client->client = dap_client_new(s_stage_error_callback, l_sync_client);
    if (!l_sync_client->client) {
        log_it(L_ERROR, "Failed to create dap_client");
        pthread_mutex_destroy(&l_sync_client->conn_mutex);
        pthread_cond_destroy(&l_sync_client->conn_cond);
        pthread_rwlock_destroy(&l_sync_client->requests_lock);
        DAP_DEL_MULTY(l_sync_client->node_info, l_sync_client);
        return NULL;
    }
    
    dap_client_set_is_always_reconnect(l_sync_client->client, false);
    dap_client_set_active_channels_unsafe(l_sync_client->client, a_channels);
    
    // Set auth cert if configured
    const char *l_auth_cert_name = dap_config_get_item_str(a_net->pub.config, "general", "auth_cert");
    if (l_auth_cert_name)
        dap_client_set_auth_cert(l_sync_client->client, l_auth_cert_name);
    
    // Setup uplink and start connection
    dap_client_set_uplink_unsafe(l_sync_client->client, 
                                  &a_node_info->address,
                                  a_node_info->ext_host, 
                                  a_node_info->ext_port);
    
    log_it(L_INFO, "Sync client connecting to %s:%u", 
           a_node_info->ext_host, a_node_info->ext_port);
    
    dap_client_go_stage(l_sync_client->client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
    
    // Wait for connection with timeout
    struct timespec l_timeout;
    clock_gettime(CLOCK_MONOTONIC, &l_timeout);
    l_timeout.tv_sec += a_timeout_ms / 1000;
    l_timeout.tv_nsec += (a_timeout_ms % 1000) * 1000000;
    if (l_timeout.tv_nsec >= 1000000000) {
        l_timeout.tv_sec++;
        l_timeout.tv_nsec -= 1000000000;
    }
    
    pthread_mutex_lock(&l_sync_client->conn_mutex);
    while (l_sync_client->is_connecting) {
        int l_wait_ret = pthread_cond_timedwait(&l_sync_client->conn_cond,
                                                 &l_sync_client->conn_mutex,
                                                 &l_timeout);
        if (l_wait_ret == ETIMEDOUT) {
            log_it(L_WARNING, "Sync client connection timeout");
            l_sync_client->is_connecting = false;
            l_sync_client->conn_error = DAP_SYNC_ERROR_CONNECT_TIMEOUT;
            break;
        } else if (l_wait_ret != 0 && l_wait_ret != EINTR) {
            log_it(L_ERROR, "pthread_cond_timedwait error: %d", l_wait_ret);
            l_sync_client->is_connecting = false;
            l_sync_client->conn_error = DAP_SYNC_ERROR_INTERNAL;
            break;
        }
    }
    pthread_mutex_unlock(&l_sync_client->conn_mutex);
    
    // Check if connected
    if (!l_sync_client->is_connected) {
        log_it(L_ERROR, "Sync client failed to connect: %s",
               dap_chain_node_sync_error_str(l_sync_client->conn_error));
        dap_chain_node_sync_client_close(l_sync_client);
        return NULL;
    }
    
    return l_sync_client;
}

/**
 * @brief Simple handshake - connect and disconnect
 */
int dap_chain_node_sync_handshake(
    dap_chain_net_t *a_net,
    dap_chain_node_info_t *a_node_info,
    const char *a_channels,
    int a_timeout_ms)
{
    dap_chain_node_sync_client_t *l_client = dap_chain_node_sync_client_connect(
        a_net, a_node_info, a_channels, a_timeout_ms);
    
    if (!l_client)
        return DAP_SYNC_ERROR_CONNECT_FAILED;
    
    dap_chain_node_sync_client_close(l_client);
    return DAP_SYNC_ERROR_NONE;
}

// Simple matcher that checks expected response type
static bool s_simple_response_matcher(dap_chain_node_sync_request_t *a_request, uint8_t a_pkt_type,
                                       const void *a_pkt_data, size_t a_pkt_size, void *a_arg)
{
    UNUSED(a_pkt_data);
    UNUSED(a_pkt_size);
    uint8_t l_expected = (uint8_t)(uintptr_t)a_arg;
    return a_pkt_type == l_expected;
}

/**
 * @brief Universal synchronous request
 */
int dap_chain_node_sync_request(
    dap_chain_node_sync_client_t *a_client,
    uint8_t a_channel_id,
    uint8_t a_request_type,
    const void *a_request_data,
    size_t a_request_size,
    uint8_t a_expected_response,
    void **a_out_data,
    size_t *a_out_size,
    int a_timeout_ms)
{
    return dap_chain_node_sync_request_ex(a_client, a_channel_id, a_request_type,
                                           a_request_data, a_request_size,
                                           s_simple_response_matcher, 
                                           (void *)(uintptr_t)a_expected_response,
                                           a_out_data, a_out_size, a_timeout_ms);
}

/**
 * @brief Extended synchronous request with custom matcher
 */
int dap_chain_node_sync_request_ex(
    dap_chain_node_sync_client_t *a_client,
    uint8_t a_channel_id,
    uint8_t a_request_type,
    const void *a_request_data,
    size_t a_request_size,
    dap_chain_node_sync_matcher_t a_matcher,
    void *a_matcher_arg,
    void **a_out_data,
    size_t *a_out_size,
    int a_timeout_ms)
{
    if (!a_client) {
        log_it(L_ERROR, "Sync request: NULL client");
        return DAP_SYNC_ERROR_INVALID_ARGS;
    }
    
    if (!a_client->is_connected) {
        log_it(L_ERROR, "Sync request: client not connected");
        return DAP_SYNC_ERROR_DISCONNECTED;
    }
    
    // Find channel
    dap_stream_ch_t *l_ch = dap_client_get_stream_ch_unsafe(a_client->client, a_channel_id);
    if (!l_ch) {
        log_it(L_ERROR, "Sync request: channel '%c' not found", a_channel_id);
        return DAP_SYNC_ERROR_CHANNEL_NOT_FOUND;
    }
    
    // Create request context
    dap_chain_node_sync_request_t *l_request = DAP_NEW_Z(dap_chain_node_sync_request_t);
    if (!l_request) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return DAP_SYNC_ERROR_MEMORY;
    }
    
    l_request->request_id = atomic_fetch_add(&a_client->request_id_counter, 1);
    l_request->channel_id = a_channel_id;
    l_request->request_type = a_request_type;
    l_request->status = SYNC_REQUEST_STATUS_PENDING;
    l_request->matcher = a_matcher;
    l_request->matcher_arg = a_matcher_arg;
    l_request->sync_client = a_client;
    
    pthread_mutex_init(&l_request->mutex, NULL);
    
    pthread_condattr_t l_condattr;
    pthread_condattr_init(&l_condattr);
#ifndef DAP_OS_DARWIN
    pthread_condattr_setclock(&l_condattr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&l_request->cond, &l_condattr);
    pthread_condattr_destroy(&l_condattr);
    
    // Add to pending requests hash table
    pthread_rwlock_wrlock(&a_client->requests_lock);
    HASH_ADD(hh, a_client->pending_requests, request_id, sizeof(uint64_t), l_request);
    pthread_rwlock_unlock(&a_client->requests_lock);
    
    // Send request packet
    ssize_t l_sent = dap_stream_ch_pkt_write_unsafe(l_ch, a_request_type, 
                                                     (void *)a_request_data, a_request_size);
    if (l_sent <= 0) {
        log_it(L_ERROR, "Sync request: failed to send packet");
        pthread_rwlock_wrlock(&a_client->requests_lock);
        HASH_DEL(a_client->pending_requests, l_request);
        pthread_rwlock_unlock(&a_client->requests_lock);
        pthread_mutex_destroy(&l_request->mutex);
        pthread_cond_destroy(&l_request->cond);
        DAP_DELETE(l_request);
        return DAP_SYNC_ERROR_SEND_FAILED;
    }
    
    dap_stream_ch_set_ready_to_write_unsafe(l_ch, true);
    
    // Wait for response with timeout
    struct timespec l_timeout;
    clock_gettime(CLOCK_MONOTONIC, &l_timeout);
    l_timeout.tv_sec += a_timeout_ms / 1000;
    l_timeout.tv_nsec += (a_timeout_ms % 1000) * 1000000;
    if (l_timeout.tv_nsec >= 1000000000) {
        l_timeout.tv_sec++;
        l_timeout.tv_nsec -= 1000000000;
    }
    
    int l_ret = DAP_SYNC_ERROR_NONE;
    
    pthread_mutex_lock(&l_request->mutex);
    while (l_request->status == SYNC_REQUEST_STATUS_PENDING) {
        int l_wait_ret = pthread_cond_timedwait(&l_request->cond,
                                                 &l_request->mutex,
                                                 &l_timeout);
        if (l_wait_ret == ETIMEDOUT) {
            log_it(L_WARNING, "Sync request timeout (id=%"DAP_UINT64_FORMAT_U")", l_request->request_id);
            l_request->status = SYNC_REQUEST_STATUS_TIMEOUT;
            break;
        } else if (l_wait_ret != 0 && l_wait_ret != EINTR) {
            log_it(L_ERROR, "pthread_cond_timedwait error: %d", l_wait_ret);
            l_request->status = SYNC_REQUEST_STATUS_ERROR;
            l_request->error_code = DAP_SYNC_ERROR_INTERNAL;
            break;
        }
    }
    pthread_mutex_unlock(&l_request->mutex);
    
    // Extract result
    switch (l_request->status) {
        case SYNC_REQUEST_STATUS_COMPLETED:
            if (a_out_data) {
                *a_out_data = l_request->response_data;
                l_request->response_data = NULL;  // Ownership transferred
            }
            if (a_out_size)
                *a_out_size = l_request->response_size;
            l_ret = DAP_SYNC_ERROR_NONE;
            break;
            
        case SYNC_REQUEST_STATUS_TIMEOUT:
            l_ret = DAP_SYNC_ERROR_REQUEST_TIMEOUT;
            break;
            
        case SYNC_REQUEST_STATUS_ERROR:
            l_ret = l_request->error_code ? l_request->error_code : DAP_SYNC_ERROR_INTERNAL;
            break;
            
        default:
            l_ret = DAP_SYNC_ERROR_INTERNAL;
            break;
    }
    
    // Cleanup request
    pthread_rwlock_wrlock(&a_client->requests_lock);
    HASH_DEL(a_client->pending_requests, l_request);
    pthread_rwlock_unlock(&a_client->requests_lock);
    
    pthread_mutex_destroy(&l_request->mutex);
    pthread_cond_destroy(&l_request->cond);
    DAP_DEL_Z(l_request->response_data);
    DAP_DELETE(l_request);
    
    return l_ret;
}

/**
 * @brief Close sync client and free resources
 */
void dap_chain_node_sync_client_close(dap_chain_node_sync_client_t *a_client)
{
    if (!a_client)
        return;
    
    log_it(L_INFO, "Closing sync client to %s:%u",
           a_client->node_info ? a_client->node_info->ext_host : "?",
           a_client->node_info ? a_client->node_info->ext_port : 0);
    
    // Remove channel notifiers
    s_del_channel_notifiers(a_client);
    
    // Cancel all pending requests
    pthread_rwlock_wrlock(&a_client->requests_lock);
    dap_chain_node_sync_request_t *l_request, *l_tmp;
    HASH_ITER(hh, a_client->pending_requests, l_request, l_tmp) {
        pthread_mutex_lock(&l_request->mutex);
        l_request->status = SYNC_REQUEST_STATUS_ERROR;
        l_request->error_code = DAP_SYNC_ERROR_DISCONNECTED;
        pthread_cond_signal(&l_request->cond);
        pthread_mutex_unlock(&l_request->mutex);
        HASH_DEL(a_client->pending_requests, l_request);
    }
    pthread_rwlock_unlock(&a_client->requests_lock);
    
    // Close underlying client
    if (a_client->client)
        dap_client_delete_unsafe(a_client->client);
    
    // Destroy sync primitives
    pthread_mutex_destroy(&a_client->conn_mutex);
    pthread_cond_destroy(&a_client->conn_cond);
    pthread_rwlock_destroy(&a_client->requests_lock);
    
    // Free memory
    DAP_DEL_Z(a_client->node_info);
    DAP_DELETE(a_client);
}

