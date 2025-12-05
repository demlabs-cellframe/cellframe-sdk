/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2024
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

#include <stdint.h>

#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_node_sync_client.h"

typedef struct dap_chain_net_srv_client {
    dap_chain_node_sync_client_t   *sync_client;        // Underlying sync client
    dap_chain_net_t                *net;                // Network context
    void                           *_inheritor;         // For Python bindings compatibility
} dap_chain_net_srv_client_t;

// Error codes
typedef enum dap_chain_net_srv_client_error {
    DAP_SRV_CLIENT_ERROR_NONE           = 0,
    DAP_SRV_CLIENT_ERROR_MEMORY         = -1,
    DAP_SRV_CLIENT_ERROR_INVALID_ARGS   = -2,
    DAP_SRV_CLIENT_ERROR_CONNECT        = -3,
    DAP_SRV_CLIENT_ERROR_TIMEOUT        = -4,
    DAP_SRV_CLIENT_ERROR_DISCONNECTED   = -5,
    DAP_SRV_CLIENT_ERROR_SEND           = -6,
    DAP_SRV_CLIENT_ERROR_WRONG_RESPONSE = -7,
    DAP_SRV_CLIENT_ERROR_REMOTE         = -8
} dap_chain_net_srv_client_error_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Connect to service provider
 * @param a_net Network
 * @param a_addr Host address
 * @param a_port Port
 * @param a_timeout_ms Connection timeout
 * @return Service client or NULL on error
 */
dap_chain_net_srv_client_t *dap_chain_net_srv_client_connect(
    dap_chain_net_t *a_net,
    const char *a_addr,
    uint16_t a_port,
    int a_timeout_ms
);

/**
 * @brief Check service (synchronous)
 * @param a_client Service client
 * @param a_net_id Network ID
 * @param a_srv_uid Service UID
 * @param a_data Test data to send
 * @param a_data_size Test data size
 * @param a_out_response Output: response (caller frees)
 * @param a_timeout_ms Request timeout
 * @return 0 on success, negative error code on failure
 */
int dap_chain_net_srv_client_check(
    dap_chain_net_srv_client_t *a_client,
    dap_chain_net_id_t a_net_id,
    dap_chain_srv_uid_t a_srv_uid,
    const void *a_data,
    size_t a_data_size,
    dap_chain_net_srv_ch_pkt_test_t **a_out_response,
    int a_timeout_ms
);

/**
 * @brief Request service (synchronous)
 * @param a_client Service client
 * @param a_net_id Network ID
 * @param a_srv_uid Service UID
 * @param a_tx_cond Conditional transaction hash
 * @param a_out_success Output: success response (caller frees)
 * @param a_out_size Output: response size
 * @param a_timeout_ms Request timeout
 * @return 0 on success, negative error code on failure
 */
int dap_chain_net_srv_client_request(
    dap_chain_net_srv_client_t *a_client,
    dap_chain_net_id_t a_net_id,
    dap_chain_srv_uid_t a_srv_uid,
    dap_chain_hash_fast_t *a_tx_cond,
    dap_chain_net_srv_ch_pkt_success_t **a_out_success,
    size_t *a_out_size,
    int a_timeout_ms
);

/**
 * @brief Write raw packet to service channel
 * @param a_client Service client
 * @param a_type Packet type
 * @param a_data Packet data
 * @param a_data_size Data size
 * @param a_expected_response Expected response type
 * @param a_out_data Output response data
 * @param a_out_size Output response size
 * @param a_timeout_ms Timeout
 * @return 0 on success, negative on error
 */
int dap_chain_net_srv_client_write(
    dap_chain_net_srv_client_t *a_client,
    uint8_t a_type,
    const void *a_data,
    size_t a_data_size,
    uint8_t a_expected_response,
    void **a_out_data,
    size_t *a_out_size,
    int a_timeout_ms
);

/**
 * @brief Close service client
 * @param a_client Service client
 */
void dap_chain_net_srv_client_close(dap_chain_net_srv_client_t *a_client);

/**
 * @brief Check if client is connected
 * @param a_client Service client
 * @return true if connected
 */
DAP_STATIC_INLINE bool dap_chain_net_srv_client_is_connected(dap_chain_net_srv_client_t *a_client)
{
    return a_client && a_client->sync_client && 
           dap_chain_node_sync_client_is_connected(a_client->sync_client);
}

/**
 * @brief Get error description
 * @param a_error Error code
 * @return Error string
 */
const char *dap_chain_net_srv_client_error_str(dap_chain_net_srv_client_error_t a_error);

#ifdef __cplusplus
}
#endif
