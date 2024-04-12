/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Demlabs Application Protocol) the open source project

 DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_time.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "json.h"
#include "uthash.h"

#include "dap_common.h"
#include "dap_client.h"
#include "dap_config.h"
#include "dap_events.h"
#include "dap_timerfd.h"
#include "dap_hash.h"
#include "dap_uuid.h"
#include "dap_client.h"
#include "dap_client_pvt.h"
#include "dap_chain.h"
#include "dap_chain_cell.h"
#include "dap_chain_net_srv.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_chain_ch.h"
#include "dap_chain_ch_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_pkt.h"
#include "dap_chain_node_client.h"

#define LOG_TAG "dap_chain_node_client"

static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg);
static bool s_timer_update_states_callback(void *a_arg);
static int s_node_client_set_notify_callbacks(dap_client_t *a_client, uint8_t a_ch_id);
static void s_ch_chain_callback_notify_packet_out(dap_chain_ch_t*, uint8_t a_pkt_type,
        dap_chain_ch_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);
static void s_ch_chain_callback_notify_packet_in(dap_chain_ch_t* a_ch_chain, uint8_t a_pkt_type,
        dap_chain_ch_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);

#ifdef DAP_OS_WINDOWS
#define dap_cond_signal(x) SetEvent(x)
#else
#define dap_cond_signal(x) pthread_cond_broadcast(&x)
#endif

/**
 * @brief dap_chain_node_client_init
 * @return always 0
 */
int dap_chain_node_client_init()
{
    return 0;
}

/**
 * @brief dap_chain_node_client_deinit
 */
void dap_chain_node_client_deinit()
{
    dap_client_deinit();
}

/**
 * @brief s_stage_status_error_callback
 * @param a_client
 * @param a_arg
 */
static void s_stage_status_error_callback(dap_client_t *a_client, void *a_arg)
{
    log_it(L_DEBUG, "s_stage_status_error_callback");

    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    if(!l_node_client)
        return;

    if (l_node_client->sync_timer) {
        // Disable timer, it will be restarted with new connection
        dap_timerfd_delete_unsafe(l_node_client->sync_timer);
        l_node_client->sync_timer = NULL;
    }

    // check for last attempt
    bool l_is_last_attempt = a_arg ? true : false;
    if (l_is_last_attempt) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_DISCONNECTED;
        dap_cond_signal(l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);

        l_node_client->esocket_uuid = 0;

        // dap_chain_net_sync_unlock(l_node_client->net, l_node_client);
        if (l_node_client->callbacks.disconnected) {
            l_node_client->callbacks.disconnected(l_node_client, l_node_client->callbacks_arg);
        }
        if (dap_client_get_stage(l_node_client->client) != STAGE_BEGIN)
            dap_client_go_stage(l_node_client->client, STAGE_BEGIN, NULL);
    } else if(l_node_client->callbacks.error) // TODO make different error codes
        l_node_client->callbacks.error(l_node_client, EINVAL, l_node_client->callbacks_arg);
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
        log_it(L_NOTICE, "Stream connection with node "NODE_ADDR_FP_STR" [ %s : %hu ] established",
                    NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr),
                    l_node_client->info->ext_host,
                    l_node_client->info->ext_port);
        l_node_client->esocket_uuid = DAP_CLIENT_PVT(a_client)->stream_es->uuid;
        // set callbacks for R and N channels
        if (a_client->active_channels) {
            size_t l_channels_count = dap_strlen(a_client->active_channels);
            for(size_t i = 0; i < l_channels_count; i++) {
                if(s_node_client_set_notify_callbacks(a_client, a_client->active_channels[i]) == -1) {
                    log_it(L_WARNING, "No ch_chain channel, can't init notify callback for pkt type CH_CHAIN");
                }
            }
        }
        if(l_node_client->callbacks.connected)
            l_node_client->callbacks.connected(l_node_client, l_node_client->callbacks_arg);
    }
}

/**
 * @brief s_ch_chain_callback_notify_packet_in2 - for dap_stream_ch_chain_net
 * @param a_ch_chain_net
 * @param a_pkt_type
 * @param a_pkt_net
 * @param a_pkt_data_size
 * @param a_arg
 */
static void s_ch_chain_callback_notify_packet_in2(dap_stream_ch_chain_net_t* a_ch_chain_net, uint8_t a_pkt_type,
        dap_stream_ch_chain_net_pkt_t *a_pkt_net, size_t a_pkt_net_data_size, void * a_arg)
{
    dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t *) a_arg;
    switch (a_pkt_type) {
    case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY: {
        if(a_pkt_net_data_size == sizeof(dap_chain_node_addr_t)) {
            l_node_client->remote_node_addr = *(dap_chain_node_addr_t*)a_pkt_net->data;
        }
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->callbacks_arg = DAP_DUP_SIZE(a_pkt_net->data, a_pkt_net_data_size);
        l_node_client->state = NODE_CLIENT_STATE_VALID_READY;
        dap_cond_signal(l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);
        break;

    } break;
    default:;
    }
}

/**
 * @brief s_ch_chain_callback_notify_packet_R - Callback for channel 'R'
 * @param a_ch_chain
 * @param a_pkt_type
 * @param a_pkt
 * @param a_arg
 */
static void s_ch_chain_callback_notify_packet_R(dap_stream_ch_chain_net_srv_t* a_ch_chain, uint8_t a_pkt_type, dap_stream_ch_pkt_t *a_pkt, void * a_arg)
{
    UNUSED(a_ch_chain);
    dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t *) a_arg;
    switch (a_pkt_type) {
    // get new generated current node address
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE: {
            dap_stream_ch_chain_net_srv_pkt_test_t *l_request = (dap_stream_ch_chain_net_srv_pkt_test_t *) a_pkt->data;
            size_t l_request_size = l_request->data_size + sizeof(dap_stream_ch_chain_net_srv_pkt_test_t);
            if(a_pkt->hdr.data_size != l_request_size) {
                log_it(L_WARNING, "Wrong request size, less or more than required");
                break;
            }
            //s_save_stat_to_database(l_request, l_node_client);
            pthread_mutex_lock(&l_node_client->wait_mutex);
            l_node_client->state = NODE_CLIENT_STATE_CHECKED;
            dap_cond_signal(l_node_client->wait_cond);
            pthread_mutex_unlock(&l_node_client->wait_mutex);
            break;
        }
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE:
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS:
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR:
        break;
    default:
        break;
    }
}

/**
 * @brief dap_chain_node_client_create_n_connect
 * @param a_net
 * @param a_node_info
 * @param a_active_channels
 * @param a_callbacks
 * @param a_callback_arg
 * @return
 */
dap_chain_node_client_t *dap_chain_node_client_create_n_connect(dap_chain_net_t *a_net,
                                                                dap_chain_node_info_t *a_node_info,
                                                                const char *a_active_channels,
                                                                const dap_chain_node_client_callbacks_t *a_callbacks,
                                                                void *a_callback_arg)
{
    dap_chain_node_client_t *l_node_client = dap_chain_node_client_create(a_net, a_node_info, a_callbacks, a_callback_arg);
    return dap_chain_node_client_connect(l_node_client, a_active_channels) ? l_node_client : ( DAP_DEL_MULTY(l_node_client->info, l_node_client), NULL );
}

dap_chain_node_client_t *dap_chain_node_client_create(dap_chain_net_t *a_net,
                                                      dap_chain_node_info_t *a_node_info,
                                                      const dap_chain_node_client_callbacks_t *a_callbacks,
                                                      void *a_callback_arg)
{
    if(!a_node_info) {
        log_it(L_ERROR, "Can't connect to the node: null object node_info");
        return NULL;
    }
    dap_chain_node_client_t *l_node_client = DAP_NEW_Z(dap_chain_node_client_t);
    if (!l_node_client) {
        log_it(L_CRITICAL, "%s", g_error_memory_alloc);
        return NULL;
    }

    l_node_client->state = NODE_CLIENT_STATE_DISCONNECTED;
    l_node_client->callbacks_arg = a_callback_arg;
    if (a_callbacks)
        l_node_client->callbacks = *a_callbacks;
    l_node_client->info = DAP_DUP_SIZE(a_node_info, sizeof(dap_chain_node_info_t) + a_node_info->ext_host_len + 1);
    l_node_client->net = a_net;
#ifndef _WIN32
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
#ifndef DAP_OS_DARWIN
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
    pthread_cond_init(&l_node_client->wait_cond, &attr);
#else
    l_node_client->wait_cond = CreateEventA( NULL, FALSE, FALSE, NULL );
#endif

    pthread_mutex_init(&l_node_client->wait_mutex, NULL);
    l_node_client->remote_node_addr.uint64 = a_node_info->address.uint64;
    return l_node_client;
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
    a_node_client->client = dap_client_new(NULL, s_stage_status_error_callback, a_node_client);
    dap_client_set_is_always_reconnect(a_node_client->client, false);
    a_node_client->client->_inheritor = a_node_client;
    dap_client_set_active_channels_unsafe(a_node_client->client, a_active_channels);
    dap_client_set_auth_cert(a_node_client->client, a_node_client->net->pub.name);
    char *l_host_addr = a_node_client->info->ext_host;
    
    if ( !*l_host_addr || !strcmp(l_host_addr, "::") || !a_node_client->info->ext_port ) {
        return log_it(L_WARNING, "Node client address undefined"), false;
    }

    log_it(L_INFO, "Connecting to addr %s : %d", l_host_addr, a_node_client->info->ext_port);
    dap_client_set_uplink_unsafe(a_node_client->client, &a_node_client->info->address, l_host_addr, a_node_client->info->ext_port);
    a_node_client->state = NODE_CLIENT_STATE_CONNECTING;
    // Handshake & connect
    dap_client_go_stage(a_node_client->client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
    return true;
}

/**
 * @brief dap_chain_node_client_close
 * Close connection to server, delete chain_node_client_t *client
 * @param a_client dap_chain_node_client_t
 */
void dap_chain_node_client_close_unsafe(dap_chain_node_client_t *a_node_client)
{
    log_it(L_INFO, "Closing node client to uplink"NODE_ADDR_FP_STR" [ %s : %u ]",
                    NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr),
                    a_node_client->info->ext_host,
                    a_node_client->info->ext_port);

    if (a_node_client->sync_timer)
        dap_timerfd_delete_unsafe(a_node_client->sync_timer);
    if (a_node_client->reconnect_timer)
        dap_timerfd_delete_mt(a_node_client->reconnect_timer->worker, a_node_client->reconnect_timer->esocket_uuid);
    if (a_node_client->callbacks.delete)
        a_node_client->callbacks.delete(a_node_client, a_node_client->net);

    if (a_node_client->stream_worker) {
        dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(a_node_client->stream_worker, a_node_client->ch_chain_net_uuid);
        if (l_ch) {
            dap_stream_ch_chain_net_t *l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(l_ch);
            l_ch_chain_net->notify_callback = NULL;
        }
    }
    // clean client
    if(a_node_client->client){
        a_node_client->client->delete_callback = NULL;
        dap_client_delete_unsafe(a_node_client->client);
    }
#ifndef _WIN32
    pthread_cond_destroy(&a_node_client->wait_cond);
#else
    CloseHandle( a_node_client->wait_cond );
#endif
    pthread_mutex_destroy(&a_node_client->wait_mutex);
    DAP_DEL_Z(a_node_client->info);
    DAP_DELETE(a_node_client);
}

void s_close_on_worker_callback(dap_worker_t UNUSED_ARG *a_worker, void *a_arg)
{
    assert(a_arg);
    dap_chain_node_client_close_unsafe(a_arg);
}

void dap_chain_node_client_close_mt(dap_chain_node_client_t *a_node_client)
{
    if (a_node_client->client)
        dap_worker_exec_callback_on(DAP_CLIENT_PVT(a_node_client->client)->worker, s_close_on_worker_callback, a_node_client);
    else
        dap_chain_node_client_close_unsafe(a_node_client);
}

/**
 * @brief dap_chain_node_client_wait
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample NODE_CLIENT_STATE_CONNECT or NODE_CLIENT_STATE_SENDED
 * @param a_client
 * @param a_waited_state
 * @param a_timeout_ms
 * @return int return -2 false, -1 timeout, 0 end of connection or sending data
 */
int dap_chain_node_client_wait(dap_chain_node_client_t *a_client, int a_waited_state, int a_timeout_ms)
{
    int ret = -1;
    if(!a_client){
        log_it(L_ERROR, "Can't wait for status for (null) object");
        return -3;
    }
    pthread_mutex_lock(&a_client->wait_mutex);
    // have waited
    if(a_client->state == a_waited_state) {
        log_it(L_INFO, "We're already in state %s",dap_chain_node_client_state_to_str(a_client->state));
        pthread_mutex_unlock(&a_client->wait_mutex);
        return 0;
    }

    if (a_client->state < NODE_CLIENT_STATE_ESTABLISHED && a_waited_state > NODE_CLIENT_STATE_ESTABLISHED) {
        log_it(L_WARNING, "Waited state can't be achieved");
        pthread_mutex_unlock(&a_client->wait_mutex);
        return -2;
    }

#ifndef DAP_OS_WINDOWS
    // prepare for signal waiting
    struct timespec l_cond_timeout;
    clock_gettime( CLOCK_MONOTONIC, &l_cond_timeout);
    l_cond_timeout.tv_sec += a_timeout_ms/1000;
    // signal waiting
    dap_chain_node_client_state_t l_clinet_state = a_client->state;
    while (a_client->state == l_clinet_state) {
        int l_ret_wait = pthread_cond_timedwait(&a_client->wait_cond, &a_client->wait_mutex, &l_cond_timeout);
        if(l_ret_wait == 0 && (
                a_client->state == a_waited_state ||
                        (a_client->state == NODE_CLIENT_STATE_ERROR || a_client->state == NODE_CLIENT_STATE_DISCONNECTED))
                ) {
            ret = a_client->state == a_waited_state ? 0 : -2;
            break;
        }
        else if(l_ret_wait == ETIMEDOUT) { // 110 260
            //log_it(L_NOTICE,"Wait for status is stopped by timeout");
            ret = -1;
            break;
        }else if (l_ret_wait != 0 ){
            char l_errbuf[128];
            l_errbuf[0] = '\0';
            strerror_r(l_ret_wait,l_errbuf,sizeof (l_errbuf));
            log_it(L_ERROR, "Pthread condition timed wait returned \"%s\"(code %d)", l_errbuf, l_ret_wait);
        }
    }
    pthread_mutex_unlock(&a_client->wait_mutex);
#else
    pthread_mutex_unlock( &a_client->wait_mutex );
    DWORD wait = WaitForSingleObject( a_client->wait_cond, (uint32_t)a_timeout_ms);
    if ( wait == WAIT_OBJECT_0 && (
             a_client->state == a_waited_state ||
             a_client->state == NODE_CLIENT_STATE_ERROR ||
             a_client->state == NODE_CLIENT_STATE_DISCONNECTED))
    {
        return a_client->state == a_waited_state ? 0 : -2;
    } else if ( wait == WAIT_TIMEOUT || wait == WAIT_FAILED ) {
        return -1;
    }
#endif
    return ret;
}

/**
 * @brief s_node_client_set_notify_callbacks
 *
 * @param a_client dap_client_t
 * @param a_ch_id uint8_t
 * @return int
 */
static int s_node_client_set_notify_callbacks(dap_client_t *a_client, uint8_t a_ch_id)
{
    int l_ret = -1;
    dap_chain_node_client_t *l_node_client = a_client->_inheritor;
    if(l_node_client) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        // find current channel code
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch_unsafe(a_client, a_ch_id);
        if(l_ch) {
            l_ret = 0;
            switch (a_ch_id) {
                //  'N'
            case DAP_STREAM_CH_CHAIN_NET_ID: {
                dap_stream_ch_chain_net_t *l_ch_chain   = DAP_STREAM_CH_CHAIN_NET(l_ch);
                l_ch_chain->notify_callback     = s_ch_chain_callback_notify_packet_in2;
                l_ch_chain->notify_callback_arg = l_node_client;
                l_node_client->ch_chain_net         = l_ch;
                l_node_client->ch_chain_net_uuid    = l_ch->uuid;
                break;
            }
                //  'R'
            case DAP_STREAM_CH_NET_SRV_ID: {
                dap_stream_ch_chain_net_srv_t *l_ch_chain = DAP_STREAM_CH_CHAIN_NET_SRV(l_ch);
                if (l_node_client->notify_callbacks.srv_pkt_in) {
                    l_ch_chain->notify_callback     = (dap_stream_ch_chain_net_srv_callback_packet_t)l_node_client->notify_callbacks.srv_pkt_in;
                    l_ch_chain->notify_callback_arg = l_node_client->callbacks_arg;
                } else {
                    l_ch_chain->notify_callback     = s_ch_chain_callback_notify_packet_R;
                    l_ch_chain->notify_callback_arg = l_node_client;
                }
                l_node_client->ch_chain_net_srv         = l_ch;
                l_node_client->ch_chain_net_srv_uuid    = l_ch->uuid;
                break;
            }
            default: {
                l_ret = -2;
                log_it(L_ERROR, "Unknown channel id %d (%c)", a_ch_id, a_ch_id);
                break;
            }
            }
        }
        pthread_mutex_unlock(&l_node_client->wait_mutex);
    }
    return l_ret;
}
