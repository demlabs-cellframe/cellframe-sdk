/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Roman Padenkov <roman.padenkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2023
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

static bool s_timer_node_reconnect(void *a_arg)
{
    if (!a_arg)
        return false;
    dap_chain_node_client_t *l_me = a_arg;
    if (l_me->keep_connection && l_me->state == NODE_CLIENT_STATE_DISCONNECTED) {
        if (dap_client_get_stage(l_me->client) == STAGE_BEGIN) {
            log_it(L_INFO, "Reconnecting node client with peer "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_me->remote_node_addr));
            l_me->state = NODE_CLIENT_STATE_CONNECTING ;
            dap_client_go_stage(l_me->client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
        }
    }
    return false;
}

/**
 * @brief a_stage_end_callback
 * @param a_client
 * @param a_arg
 */
static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg)
{

    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    UNUSED(a_arg);
    if(l_node_client) {
        char l_ip_addr_str[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &l_node_client->info->hdr.ext_addr_v4, l_ip_addr_str, INET_ADDRSTRLEN);
        log_it(L_NOTICE, "Stream connection with node "NODE_ADDR_FP_STR" (%s:%hu) established",
               NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr),
               l_ip_addr_str, l_node_client->info->hdr.ext_port);

        if(l_node_client->callbacks.connected)
            l_node_client->callbacks.connected(l_node_client, l_node_client->callbacks_arg);
        dap_stream_ch_chain_net_pkt_hdr_t l_announce = { .version = DAP_STREAM_CH_CHAIN_NET_PKT_VERSION,
                                                        .net_id  = l_node_client->net->pub.id };
        dap_client_write_unsafe(a_client, 'N', DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE,
                                &l_announce, sizeof(l_announce));
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_ESTABLISHED;
        if (s_stream_ch_chain_debug_more)
            log_it(L_DEBUG, "Wakeup all who waits");
        dap_cond_signal(l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);

        dap_stream_t * l_stream  = dap_client_get_stream(a_client);
        if (l_stream) {
            l_node_client->esocket_uuid = l_stream->esocket->uuid;
            l_node_client->stream_worker = l_stream->stream_worker;
            if (l_node_client->keep_connection) {
                if(l_node_client->stream_worker){
                    s_timer_update_states_callback(l_node_client);
                    l_node_client->sync_timer = dap_timerfd_start_on_worker(l_stream->esocket->worker,
                                                                            s_timer_update_states * 1000,
                                                                            s_timer_update_states_callback,
                                                                            l_node_client);
                }else{
                    log_it(L_ERROR,"After NODE_CLIENT_STATE_ESTABLISHED: Node client has no worker, too dangerous to run update states in alien context");
                }
            }
        }
        // set callbacks for C and N channels; for R and S it is not needed
        if (a_client->active_channels) {
            size_t l_channels_count = dap_strlen(a_client->active_channels);
            for(size_t i = 0; i < l_channels_count; i++) {
                if(s_node_client_set_notify_callbacks(a_client, a_client->active_channels[i]) == -1) {
                    log_it(L_WARNING, "No ch_chain channel, can't init notify callback for pkt type CH_CHAIN");
                }
            }
        }
    }
}


/**
 * @brief dap_chain_node_client_connect
 * Create new dap_client, setup it, and send it in adventure trip
 * @param a_node_client dap_chain_node_client_t
 * @param a_active_channels a_active_channels
 * @return true
 * @return false
 */
bool dap_chain_node_client_connect(dap_chain_node_client_t *a_node_client, const char *a_active_channels)
{
    if (!a_node_client)
        return false;
    a_node_client->client = dap_client_new(s_client_delete_callback, s_stage_status_error_callback, a_node_client);
    dap_client_set_is_always_reconnect(a_node_client->client, false);
    a_node_client->client->_inheritor = a_node_client;
    dap_client_set_active_channels_unsafe(a_node_client->client, a_active_channels);

    dap_client_set_auth_cert(a_node_client->client, a_node_client->net->pub.name);

    char l_host_addr[INET6_ADDRSTRLEN] = { '\0' };
    if(a_node_client->info->hdr.ext_addr_v4.s_addr){
        struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = a_node_client->info->hdr.ext_addr_v4 };
        inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), l_host_addr, INET6_ADDRSTRLEN);
    } else {
        struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = a_node_client->info->hdr.ext_addr_v6 };
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), l_host_addr, INET6_ADDRSTRLEN);
    }
    if(!strlen(l_host_addr) || !strcmp(l_host_addr, "::") || !a_node_client->info->hdr.ext_port) {
        log_it(L_WARNING, "Undefined address of node client");
        return false;
    }
    log_it(L_INFO, "Connecting to addr %s : %d", l_host_addr, a_node_client->info->hdr.ext_port);
    dap_client_set_uplink_unsafe(a_node_client->client, l_host_addr, a_node_client->info->hdr.ext_port);
    a_node_client->state = NODE_CLIENT_STATE_CONNECTING;
    // Handshake & connect
    dap_client_go_stage(a_node_client->client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
    return true;
}
