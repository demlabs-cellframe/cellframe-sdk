/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Roman Khlopkov <roman.khlopkov@demlabs.net>
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

#include "dap_chain_net_srv_ch.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_client.h"
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"

#define LOG_TAG "dap_chain_net_srv_client"

/**
 * @brief Get error description
 */
const char *dap_chain_net_srv_client_error_str(dap_chain_net_srv_client_error_t a_error)
{
    switch (a_error) {
        case DAP_SRV_CLIENT_ERROR_NONE:           return "No error";
        case DAP_SRV_CLIENT_ERROR_MEMORY:         return "Memory allocation failed";
        case DAP_SRV_CLIENT_ERROR_INVALID_ARGS:   return "Invalid arguments";
        case DAP_SRV_CLIENT_ERROR_CONNECT:        return "Connection failed";
        case DAP_SRV_CLIENT_ERROR_TIMEOUT:        return "Request timeout";
        case DAP_SRV_CLIENT_ERROR_DISCONNECTED:   return "Disconnected";
        case DAP_SRV_CLIENT_ERROR_SEND:           return "Send failed";
        case DAP_SRV_CLIENT_ERROR_WRONG_RESPONSE: return "Wrong response format";
        case DAP_SRV_CLIENT_ERROR_REMOTE:         return "Remote error";
        default:                                   return "Unknown error";
    }
}

/**
 * @brief Connect to service provider
 */
dap_chain_net_srv_client_t *dap_chain_net_srv_client_connect(
    dap_chain_net_t *a_net,
    const char *a_addr,
    uint16_t a_port,
    int a_timeout_ms)
{
    if (!a_net || !a_addr || !a_port) {
        log_it(L_ERROR, "Invalid arguments for service client connect");
        return NULL;
    }
    
    dap_chain_net_srv_client_t *l_client = DAP_NEW_Z(dap_chain_net_srv_client_t);
    if (!l_client) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    l_client->net = a_net;
    
    // Prepare node info
    size_t l_addr_len = dap_strlen(a_addr);
    dap_chain_node_info_t *l_node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t,
                                                         sizeof(dap_chain_node_info_t) + l_addr_len + 1);
    if (!l_node_info) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_client);
        return NULL;
    }
    
    l_node_info->ext_port = a_port;
    l_node_info->ext_host_len = dap_strncpy(l_node_info->ext_host, a_addr, l_addr_len) - l_node_info->ext_host;
    
    // Connect using sync client with 'R' channel for services
    const char l_channels[] = { DAP_CHAIN_NET_SRV_CH_ID, '\0' };
    l_client->sync_client = dap_chain_node_sync_client_connect(a_net, l_node_info, l_channels, a_timeout_ms);
    
    DAP_DELETE(l_node_info);
    
    if (!l_client->sync_client) {
        log_it(L_ERROR, "Failed to connect to service at %s:%u", a_addr, a_port);
        DAP_DELETE(l_client);
        return NULL;
    }
    
    log_it(L_INFO, "Service client connected to %s:%u", a_addr, a_port);
    return l_client;
}

/**
 * @brief Check service (synchronous)
 */
int dap_chain_net_srv_client_check(
    dap_chain_net_srv_client_t *a_client,
    dap_chain_net_id_t a_net_id,
    dap_chain_srv_uid_t a_srv_uid,
    const void *a_data,
    size_t a_data_size,
    dap_chain_net_srv_ch_pkt_test_t **a_out_response,
    int a_timeout_ms)
{
    if (!a_client || !a_client->sync_client) {
        log_it(L_ERROR, "Service client check: invalid client");
        return DAP_SRV_CLIENT_ERROR_INVALID_ARGS;
    }
    
    if (!dap_chain_node_sync_client_is_connected(a_client->sync_client)) {
        log_it(L_ERROR, "Service client check: not connected");
        return DAP_SRV_CLIENT_ERROR_DISCONNECTED;
    }
    
    // Build check request
    size_t l_request_size = sizeof(dap_chain_net_srv_ch_pkt_test_t) + a_data_size;
    dap_chain_net_srv_ch_pkt_test_t *l_request = DAP_NEW_Z_SIZE(dap_chain_net_srv_ch_pkt_test_t, l_request_size);
    if (!l_request) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return DAP_SRV_CLIENT_ERROR_MEMORY;
    }
    
    l_request->net_id = a_net_id;
    l_request->srv_uid = a_srv_uid;
    l_request->data_size_send = a_data_size;
    l_request->data_size_recv = a_data_size;
    l_request->data_size = a_data_size;
    l_request->send_time1 = dap_nanotime_now();
    
    if (a_data && a_data_size > 0) {
        memcpy(l_request->data, a_data, a_data_size);
        dap_hash_fast(l_request->data, l_request->data_size, &l_request->data_hash);
    }
    
    // Send request and wait for response
    void *l_response_data = NULL;
    size_t l_response_size = 0;
    
    int l_ret = dap_chain_node_sync_request(
        a_client->sync_client,
        DAP_CHAIN_NET_SRV_CH_ID,
        DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_REQUEST,
        l_request, l_request_size,
        DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE,
        &l_response_data, &l_response_size,
        a_timeout_ms
    );
    
    DAP_DELETE(l_request);
    
    if (l_ret != DAP_SYNC_ERROR_NONE) {
        log_it(L_WARNING, "Service check request failed: %s", dap_chain_node_sync_error_str(l_ret));
        return l_ret == DAP_SYNC_ERROR_REQUEST_TIMEOUT ? DAP_SRV_CLIENT_ERROR_TIMEOUT : DAP_SRV_CLIENT_ERROR_SEND;
    }
    
    // Validate response
    if (!l_response_data || l_response_size < sizeof(dap_chain_net_srv_ch_pkt_test_t)) {
        log_it(L_WARNING, "Service check: wrong response size");
        DAP_DEL_Z(l_response_data);
        return DAP_SRV_CLIENT_ERROR_WRONG_RESPONSE;
    }
    
    dap_chain_net_srv_ch_pkt_test_t *l_response = (dap_chain_net_srv_ch_pkt_test_t *)l_response_data;
    
    // Verify hash
    dap_chain_hash_fast_t l_data_hash;
    dap_hash_fast(l_response->data, l_response->data_size, &l_data_hash);
    if (!dap_hash_fast_compare(&l_data_hash, &l_response->data_hash)) {
        log_it(L_WARNING, "Service check: response hash mismatch");
        DAP_DELETE(l_response_data);
        return DAP_SRV_CLIENT_ERROR_WRONG_RESPONSE;
    }
    
    l_response->recv_time1 = dap_nanotime_now();
    
    if (a_out_response)
        *a_out_response = l_response;
    else
        DAP_DELETE(l_response_data);
    
    return DAP_SRV_CLIENT_ERROR_NONE;
}

/**
 * @brief Request service (synchronous)
 */
int dap_chain_net_srv_client_request(
    dap_chain_net_srv_client_t *a_client,
    dap_chain_net_id_t a_net_id,
    dap_chain_srv_uid_t a_srv_uid,
    dap_chain_hash_fast_t *a_tx_cond,
    dap_chain_net_srv_ch_pkt_success_t **a_out_success,
    size_t *a_out_size,
    int a_timeout_ms)
{
    if (!a_client || !a_client->sync_client) {
        log_it(L_ERROR, "Service client request: invalid client");
        return DAP_SRV_CLIENT_ERROR_INVALID_ARGS;
    }
    
    if (!dap_chain_node_sync_client_is_connected(a_client->sync_client)) {
        log_it(L_ERROR, "Service client request: not connected");
        return DAP_SRV_CLIENT_ERROR_DISCONNECTED;
    }
    
    // Build request
    dap_chain_net_srv_ch_pkt_request_hdr_t l_request = {0};
    l_request.net_id = a_net_id;
    l_request.srv_uid = a_srv_uid;
    if (a_tx_cond)
        l_request.tx_cond = *a_tx_cond;
    
    // Send request and wait for response
    void *l_response_data = NULL;
    size_t l_response_size = 0;
    
    int l_ret = dap_chain_node_sync_request(
        a_client->sync_client,
        DAP_CHAIN_NET_SRV_CH_ID,
        DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST,
        &l_request, sizeof(l_request),
        DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS,
        &l_response_data, &l_response_size,
        a_timeout_ms
    );
    
    if (l_ret != DAP_SYNC_ERROR_NONE) {
        log_it(L_WARNING, "Service request failed: %s", dap_chain_node_sync_error_str(l_ret));
        return l_ret == DAP_SYNC_ERROR_REQUEST_TIMEOUT ? DAP_SRV_CLIENT_ERROR_TIMEOUT : DAP_SRV_CLIENT_ERROR_SEND;
    }
    
    if (a_out_success)
        *a_out_success = (dap_chain_net_srv_ch_pkt_success_t *)l_response_data;
    else
        DAP_DEL_Z(l_response_data);
    
    if (a_out_size)
        *a_out_size = l_response_size;
    
    return DAP_SRV_CLIENT_ERROR_NONE;
}

/**
 * @brief Write raw packet to service channel
 */
int dap_chain_net_srv_client_write(
    dap_chain_net_srv_client_t *a_client,
    uint8_t a_type,
    const void *a_data,
    size_t a_data_size,
    uint8_t a_expected_response,
    void **a_out_data,
    size_t *a_out_size,
    int a_timeout_ms)
{
    if (!a_client || !a_client->sync_client) {
        log_it(L_ERROR, "Service client write: invalid client");
        return DAP_SRV_CLIENT_ERROR_INVALID_ARGS;
    }
    
    if (!dap_chain_node_sync_client_is_connected(a_client->sync_client)) {
        log_it(L_ERROR, "Service client write: not connected");
        return DAP_SRV_CLIENT_ERROR_DISCONNECTED;
    }
    
    int l_ret = dap_chain_node_sync_request(
        a_client->sync_client,
        DAP_CHAIN_NET_SRV_CH_ID,
        a_type,
        a_data, a_data_size,
        a_expected_response,
        a_out_data, a_out_size,
        a_timeout_ms
    );
    
    if (l_ret != DAP_SYNC_ERROR_NONE) {
        log_it(L_WARNING, "Service client write failed: %s", dap_chain_node_sync_error_str(l_ret));
        return l_ret == DAP_SYNC_ERROR_REQUEST_TIMEOUT ? DAP_SRV_CLIENT_ERROR_TIMEOUT : DAP_SRV_CLIENT_ERROR_SEND;
    }
    
    return DAP_SRV_CLIENT_ERROR_NONE;
}

/**
 * @brief Close service client
 */
void dap_chain_net_srv_client_close(dap_chain_net_srv_client_t *a_client)
{
    if (!a_client)
        return;
    
    log_it(L_INFO, "Closing service client");
    
    if (a_client->sync_client)
        dap_chain_node_sync_client_close(a_client->sync_client);
    
    DAP_DELETE(a_client);
}
