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

#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>

#include "uthash.h"
#include "dap_client.h"
#include "dap_chain_node.h"
#include "dap_chain_net.h"
#include "dap_stream_ch_pkt.h"

// Error codes for sync client operations
typedef enum dap_chain_node_sync_error {
    DAP_SYNC_ERROR_NONE             = 0,
    DAP_SYNC_ERROR_MEMORY           = -1,
    DAP_SYNC_ERROR_INVALID_ARGS     = -2,
    DAP_SYNC_ERROR_CONNECT_FAILED   = -3,
    DAP_SYNC_ERROR_CONNECT_TIMEOUT  = -4,
    DAP_SYNC_ERROR_DISCONNECTED     = -5,
    DAP_SYNC_ERROR_SEND_FAILED      = -6,
    DAP_SYNC_ERROR_REQUEST_TIMEOUT  = -7,
    DAP_SYNC_ERROR_CHANNEL_NOT_FOUND = -8,
    DAP_SYNC_ERROR_INTERNAL         = -9
} dap_chain_node_sync_error_t;

// Request status
typedef enum dap_sync_request_status {
    SYNC_REQUEST_STATUS_PENDING,
    SYNC_REQUEST_STATUS_COMPLETED,
    SYNC_REQUEST_STATUS_ERROR,
    SYNC_REQUEST_STATUS_TIMEOUT
} dap_sync_request_status_t;

typedef struct dap_chain_node_sync_request dap_chain_node_sync_request_t;
typedef struct dap_chain_node_sync_client dap_chain_node_sync_client_t;

/**
 * @brief Custom matcher function for request-response correlation
 * @param a_request The pending request
 * @param a_pkt_type Received packet type
 * @param a_pkt_data Received packet data
 * @param a_pkt_size Received packet size
 * @param a_arg User-provided argument
 * @return true if response matches the request, false otherwise
 */
typedef bool (*dap_chain_node_sync_matcher_t)(
    dap_chain_node_sync_request_t *a_request,
    uint8_t a_pkt_type,
    const void *a_pkt_data,
    size_t a_pkt_size,
    void *a_arg
);

// Request context - one per synchronous request
struct dap_chain_node_sync_request {
    uint64_t                        request_id;         // Unique request ID
    uint8_t                         channel_id;         // Channel where request was sent
    uint8_t                         request_type;       // Sent packet type
    
    // Synchronization primitives
    pthread_mutex_t                 mutex;
    pthread_cond_t                  cond;
    
    // Response storage
    dap_sync_request_status_t       status;
    void                           *response_data;      // Response data (caller must free)
    size_t                          response_size;
    int                             error_code;
    
    // Optional custom matcher
    dap_chain_node_sync_matcher_t   matcher;
    void                           *matcher_arg;
    
    // Reference to parent client
    dap_chain_node_sync_client_t   *sync_client;
    
    UT_hash_handle                  hh;                 // For hash table
};

// Sync client - wrapper around async dap_client
struct dap_chain_node_sync_client {
    dap_client_t                   *client;             // Underlying async client
    dap_chain_net_t                *net;                // Network context
    dap_chain_node_info_t          *node_info;          // Remote node info
    
    // Connection state
    pthread_mutex_t                 conn_mutex;
    pthread_cond_t                  conn_cond;
    volatile bool                   is_connected;
    volatile bool                   is_connecting;
    volatile int                    conn_error;
    
    // Request management
    pthread_rwlock_t                requests_lock;      // Protects pending_requests
    dap_chain_node_sync_request_t  *pending_requests;   // Hash table by request_id
    atomic_uint_fast64_t            request_id_counter; // For generating unique IDs
    
    // Stream worker reference
    dap_stream_worker_t            *stream_worker;
    dap_events_socket_uuid_t        esocket_uuid;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize sync client module
 * @return 0 on success
 */
int dap_chain_node_sync_client_init(void);

/**
 * @brief Deinitialize sync client module
 */
void dap_chain_node_sync_client_deinit(void);

/**
 * @brief Create sync client and connect to remote node
 * @param a_net Network context
 * @param a_node_info Remote node info (will be copied)
 * @param a_channels Active channels string (e.g., "NR")
 * @param a_timeout_ms Connection timeout in milliseconds
 * @return Sync client on success, NULL on error
 */
dap_chain_node_sync_client_t *dap_chain_node_sync_client_connect(
    dap_chain_net_t *a_net,
    dap_chain_node_info_t *a_node_info,
    const char *a_channels,
    int a_timeout_ms
);

/**
 * @brief Create sync client and connect using node address (resolves via GDB)
 * @param a_net Network context
 * @param a_node_addr Remote node address
 * @param a_channels Active channels string
 * @param a_timeout_ms Connection timeout
 * @return Sync client on success, NULL on error
 */
dap_chain_node_sync_client_t *dap_chain_node_sync_client_connect_addr(
    dap_chain_net_t *a_net,
    dap_chain_node_addr_t *a_node_addr,
    const char *a_channels,
    int a_timeout_ms
);

/**
 * @brief Simple handshake - just connect and verify connection is established
 * @param a_net Network context
 * @param a_node_info Remote node info
 * @param a_channels Active channels
 * @param a_timeout_ms Connection timeout
 * @return 0 on success, negative error code on failure
 */
int dap_chain_node_sync_handshake(
    dap_chain_net_t *a_net,
    dap_chain_node_info_t *a_node_info,
    const char *a_channels,
    int a_timeout_ms
);

/**
 * @brief Universal synchronous request-response
 * @param a_client Sync client
 * @param a_channel_id Channel to send request ('N', 'R', etc.)
 * @param a_request_type Request packet type
 * @param a_request_data Request data (can be NULL)
 * @param a_request_size Request data size
 * @param a_expected_response Expected response packet type
 * @param a_out_data Output: response data (caller frees with DAP_DELETE)
 * @param a_out_size Output: response data size
 * @param a_timeout_ms Request timeout in milliseconds
 * @return 0 on success, negative error code on failure
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
    int a_timeout_ms
);

/**
 * @brief Sync request with custom response matcher
 * @param a_client Sync client
 * @param a_channel_id Channel ID
 * @param a_request_type Request packet type
 * @param a_request_data Request data
 * @param a_request_size Request size
 * @param a_matcher Custom matcher function
 * @param a_matcher_arg Matcher argument
 * @param a_out_data Output response data
 * @param a_out_size Output response size
 * @param a_timeout_ms Request timeout
 * @return 0 on success, negative error code on failure
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
    int a_timeout_ms
);

/**
 * @brief Close sync client and free all resources
 * @param a_client Sync client to close
 */
void dap_chain_node_sync_client_close(dap_chain_node_sync_client_t *a_client);

/**
 * @brief Check if sync client is connected
 * @param a_client Sync client
 * @return true if connected
 */
DAP_STATIC_INLINE bool dap_chain_node_sync_client_is_connected(dap_chain_node_sync_client_t *a_client)
{
    return a_client && a_client->is_connected;
}

/**
 * @brief Get error description string
 * @param a_error Error code
 * @return Error description
 */
const char *dap_chain_node_sync_error_str(dap_chain_node_sync_error_t a_error);

#ifdef __cplusplus
}
#endif

