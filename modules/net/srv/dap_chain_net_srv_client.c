/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2022
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

#include "dap_stream_ch_chain_net_srv.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_client.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_net_srv_client"

static void s_srv_client_pkt_in(dap_stream_ch_chain_net_srv_t *a_ch_chain, uint8_t a_pkt_type, dap_stream_ch_pkt_t *a_pkt, void *a_arg);
static void s_srv_client_callback_connected(dap_chain_node_client_t *a_node_client, void *a_arg);
static void s_srv_client_callback_disconnected(dap_chain_node_client_t *a_node_client, void *a_arg);
static void s_srv_client_callback_deleted(dap_chain_node_client_t *a_node_client, void *a_arg);

dap_chain_net_srv_client_t *dap_chain_net_srv_client_create_n_connect(dap_chain_net_t *a_net, char *a_addr, uint16_t a_port,
                                                                      dap_chain_net_srv_client_callbacks_t *a_callbacks,
                                                                      void *a_callbacks_arg)
{
    dap_chain_net_srv_client_t *l_ret = DAP_NEW_Z(dap_chain_net_srv_client_t);
    if (a_callbacks)
        memcpy(&l_ret->callbacks, a_callbacks, sizeof(*a_callbacks));
    l_ret->callbacks_arg = a_callbacks_arg;
    dap_chain_node_client_callbacks_t l_callbacks = {
        .connected = s_srv_client_callback_connected,
        .disconnected = s_srv_client_callback_disconnected,
        .delete = s_srv_client_callback_deleted
    };
    if (a_callbacks && a_callbacks->pkt_in)
        l_callbacks.srv_pkt_in = a_callbacks->pkt_in;
    else
        l_callbacks.srv_pkt_in = (dap_stream_ch_callback_packet_t)s_srv_client_pkt_in;
    dap_chain_node_info_t *l_info = DAP_NEW_Z(dap_chain_node_info_t);
    inet_pton(AF_INET, a_addr, &l_info->hdr.ext_addr_v4);
    l_info->hdr.ext_port = a_port;
    l_ret->node_client = dap_chain_node_client_create_n_connect(a_net, l_info, "R", &l_callbacks, l_ret);
    DAP_DELETE(l_info);
    return l_ret;
}

ssize_t dap_chain_net_srv_client_write(dap_chain_net_srv_client_t *a_client, uint8_t a_type, void *a_pkt_data, size_t a_pkt_data_size)
{
    if (!a_client || !a_client->net_client || dap_client_get_stage(a_client->net_client) != STAGE_STREAM_STREAMING)
        return -1;
    dap_stream_worker_t *l_stream_worker = dap_client_get_stream_worker(a_client->net_client);
    return dap_stream_ch_pkt_write_mt(l_stream_worker, a_client->ch_uuid, a_type, a_pkt_data, a_pkt_data_size);
}

static void s_srv_client_callback_connected(dap_chain_node_client_t *a_node_client, void *a_arg)
{
    log_it(L_INFO, "Service client connected well");
    dap_chain_net_srv_client_t *l_srv_client = (dap_chain_net_srv_client_t *)a_arg;
    memcpy(&l_srv_client->ch_uuid, &a_node_client->ch_chain_net_srv_uuid, sizeof(l_srv_client->ch_uuid));
    l_srv_client->net_client = a_node_client->client;
    if (l_srv_client->callbacks.connected)
        l_srv_client->callbacks.connected(l_srv_client, l_srv_client->callbacks_arg);
    /*const char *l_test_data = "Sevice test custom data example";
    int l_test_size = strlen(l_test_data) + 1;
    size_t l_request_size = l_test_size + sizeof(dap_stream_ch_chain_net_srv_pkt_data_t);
    dap_stream_ch_chain_net_srv_pkt_data_t *l_request = DAP_NEW_Z_SIZE(dap_stream_ch_chain_net_srv_pkt_data_t, l_request_size);
    l_request->hdr.version = 1;
    l_request->hdr.data_size = l_test_size;
    l_request->hdr.srv_uid.uint64 = 156;
    memcpy(l_request->data, l_test_data, l_test_size);
    // dap_hash_fast(l_request->data, l_request->data_size, &l_request->data_hash);
    dap_chain_net_srv_client_write(l_srv_client, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA, l_request, l_request_size);
    DAP_DELETE(l_request);*/
}

static void s_srv_client_callback_disconnected(dap_chain_node_client_t *a_node_client, void *a_arg)
{
    UNUSED(a_node_client);
    log_it(L_INFO, "Service client disconnected");
    dap_chain_net_srv_client_t *l_srv_client = (dap_chain_net_srv_client_t *)a_arg;
    if (l_srv_client->callbacks.disconnected)
        l_srv_client->callbacks.disconnected(l_srv_client, l_srv_client->callbacks_arg);
}

static void s_srv_client_callback_deleted(dap_chain_node_client_t *a_node_client, void *a_arg)
{
    UNUSED(a_node_client);
    log_it(L_INFO, "Service client deleted");
    dap_chain_net_srv_client_t *l_srv_client = (dap_chain_net_srv_client_t *)a_arg;
    if (l_srv_client->callbacks.deleted)
        l_srv_client->callbacks.deleted(l_srv_client, l_srv_client->callbacks_arg);
    DAP_DELETE(l_srv_client);
}

static void s_srv_client_pkt_in(dap_stream_ch_chain_net_srv_t *a_ch_chain, uint8_t a_pkt_type, dap_stream_ch_pkt_t *a_pkt, void *a_arg)
{
    UNUSED(a_ch_chain);
    dap_chain_net_srv_client_t *l_srv_client = (dap_chain_net_srv_client_t *)a_arg;
    UNUSED(l_srv_client);
    switch (a_pkt_type) {
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE: {
            dap_stream_ch_chain_net_srv_pkt_test_t *l_request = (dap_stream_ch_chain_net_srv_pkt_test_t *)a_pkt->data;
            size_t l_request_size = l_request->data_size + sizeof(dap_stream_ch_chain_net_srv_pkt_test_t);
            if(a_pkt->hdr.size != l_request_size) {
                log_it(L_WARNING, "Wrong request size, less or more than required");
                break;
            }
            log_it(L_INFO, "Service client check request success!");
        } break;
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE:
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS:
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR:
        break;
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA: {
        dap_stream_ch_chain_net_srv_pkt_data_t *l_response = (dap_stream_ch_chain_net_srv_pkt_data_t *)a_pkt->data;
        log_it(L_INFO, "Service client respose with data '%s'", l_response->data);
    }
    default:
        break;
    }
}
