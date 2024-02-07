/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_voting.h"
#include "dap_stream_pkt.h"
#include "dap_chain_node_client.h"

#define LOG_TAG "dap_chain_node_client"

static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg);
static bool s_timer_update_states_callback(void *a_arg);
static int s_node_client_set_notify_callbacks(dap_client_t *a_client, uint8_t a_ch_id);
static void s_ch_chain_callback_notify_packet_out(dap_stream_ch_chain_t*, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);
static void s_ch_chain_callback_notify_packet_in(dap_stream_ch_chain_t* a_ch_chain, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);

bool s_stream_ch_chain_debug_more = false;
uint32_t s_timer_update_states = 600;

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
    s_stream_ch_chain_debug_more = dap_config_get_item_bool_default(g_config, "stream_ch_chain", "debug_more", false);
    s_timer_update_states = dap_config_get_item_uint32_default(g_config, "node_client", "timer_update_states", s_timer_update_states);
    return 0;
}

/**
 * @brief dap_chain_node_client_deinit
 */
void dap_chain_node_client_deinit()
{
    dap_client_deinit();
}

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
 * @brief s_stage_status_error_callback
 * @param a_client
 * @param a_arg
 */
static void s_stage_status_error_callback(dap_client_t *a_client, void *a_arg)
{
    if (s_stream_ch_chain_debug_more)
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

        dap_chain_net_sync_unlock(l_node_client->net, l_node_client);
        if (l_node_client->callbacks.disconnected) {
            l_node_client->callbacks.disconnected(l_node_client, l_node_client->callbacks_arg);
        }
        if (l_node_client->keep_connection) {
            if (dap_client_get_stage(l_node_client->client) != STAGE_BEGIN)
                dap_client_go_stage(l_node_client->client, STAGE_BEGIN, NULL);
            l_node_client->reconnect_timer = dap_timerfd_start(45 * 1000, s_timer_node_reconnect, l_node_client);
        }
    } else if(l_node_client->callbacks.error) // TODO make different error codes
        l_node_client->callbacks.error(l_node_client, EINVAL, l_node_client->callbacks_arg);
}


/**
 * @brief dap_chain_node_client_start_sync
 * @param a_uuid
 * @param a_wrlock
 * @return
 */
dap_chain_node_sync_status_t dap_chain_node_client_start_sync(dap_chain_node_client_t *a_node_client)
{
    assert(a_node_client);
    // check if esocket still in worker
    dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(a_node_client->stream_worker, a_node_client->ch_chain_uuid);
    if (l_ch) {
        dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
        assert(l_ch_chain);
        dap_chain_net_t * l_net = a_node_client->net;
        assert(l_net);
        // If we do nothing - init sync process

        if (l_ch_chain->state == CHAIN_STATE_IDLE) {
            bool l_trylocked = dap_chain_net_sync_trylock(l_net, a_node_client);
            if (l_trylocked) {
                log_it(L_INFO, "Start synchronization process with "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr));
                dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
                l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                dap_stream_ch_chain_pkt_write_unsafe(a_node_client->ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ,
                                                     l_net->pub.id.uint64, 0, 0,
                                                     &l_sync_gdb, sizeof(l_sync_gdb));
                if (!l_ch_chain->activity_timer)
                    dap_stream_ch_chain_timer_start(l_ch_chain);
                return NODE_SYNC_STATUS_STARTED;
            } else
                return NODE_SYNC_STATUS_WAITING;
        } else
            return NODE_SYNC_STATUS_IN_PROGRESS;
    }
    return NODE_SYNC_STATUS_FAILED;
}

/**
 * @brief s_timer_update_states_callback
 * @param a_arg
 * @return
 */
static bool s_timer_update_states_callback(void *a_arg)
{
    return false;
    dap_chain_node_client_t *l_me = a_arg;
    dap_chain_node_sync_status_t l_status = dap_chain_node_client_start_sync(l_me);
    if (l_status == NODE_SYNC_STATUS_FAILED) {
        l_me->state = NODE_CLIENT_STATE_DISCONNECTED;
        if (l_me->keep_connection) {
            if (dap_client_get_stage(l_me->client) != STAGE_BEGIN) {
                dap_client_go_stage(l_me->client, STAGE_BEGIN, NULL);
                return true;
            }
            if (l_me->is_connected && l_me->callbacks.disconnected)
                l_me->callbacks.disconnected(l_me, l_me->callbacks_arg);
            if (l_me->keep_connection) {
                log_it(L_INFO, "Reconnecting node client with peer "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_me->remote_node_addr));
                l_me->state = NODE_CLIENT_STATE_CONNECTING ;
                dap_client_go_stage(l_me->client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
            }
        }
    }
    return true;
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
 * @brief s_ch_chain_callback_notify_packet_in - for dap_stream_ch_chain
 * @param a_ch_chain
 * @param a_pkt_type
 * @param a_pkt
 * @param a_pkt_data_size
 * @param a_arg
 */
static void s_ch_chain_callback_notify_packet_in(dap_stream_ch_chain_t* a_ch_chain, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg)
{
    UNUSED(a_pkt_data_size);
    dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t *) a_arg;
    dap_chain_net_t *l_net = l_node_client->net;
    assert(l_net);
    bool l_finished = false;
    switch (a_pkt_type) {
        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR:
            snprintf(l_node_client->last_error, sizeof(l_node_client->last_error),
                    "%s", (char*) a_pkt->data);
            log_it(L_WARNING, "In: Received packet DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR with error \"%s\"",
                    l_node_client->last_error);
            l_node_client->state = NODE_CLIENT_STATE_ERROR;
            if (!strcmp(l_node_client->last_error, "ERROR_SYNC_REQUEST_ALREADY_IN_PROCESS")) {
                dap_stream_ch_chain_reset_unsafe(a_ch_chain);
                l_finished = true;
            }
        break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ:{
            l_node_client->state = NODE_CLIENT_STATE_SYNC_GDB_UPDATES;
        }break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_START:{
            l_node_client->state = NODE_CLIENT_STATE_SYNC_GDB_RVRS;
            dap_chain_net_t * l_net = l_node_client->net;
            assert(l_net);
            dap_chain_net_set_state(l_net, NET_STATE_SYNC_GDB);
        }break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB:{
            l_node_client->state = NODE_CLIENT_STATE_SYNC_GDB;
        }break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ:{
            l_node_client->state = NODE_CLIENT_STATE_SYNC_CHAINS_UPDATES;
        }break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_START:{
            l_node_client->state = NODE_CLIENT_STATE_SYNC_CHAINS_RVRS;
            dap_chain_net_t * l_net = l_node_client->net;
            assert(l_net);
            dap_chain_net_set_state(l_net, NET_STATE_SYNC_CHAINS);
        }break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN:{
            l_node_client->state = NODE_CLIENT_STATE_SYNC_CHAINS;
        }break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: {
            dap_chain_id_t  l_chain_id = {};
            dap_chain_cell_id_t l_cell_id = {};
            if (a_pkt_type == DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB) {
                if (dap_chain_net_get_target_state(l_net) != NET_STATE_SYNC_GDB) {
                    if(s_stream_ch_chain_debug_more)
                        log_it(L_INFO,"In: Link %s."NODE_ADDR_FP_STR" synced GDB. Going to update chains", l_net->pub.name, NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr ));
                    l_node_client->cur_chain = l_net->pub.chains;
                    l_node_client->cur_cell = l_node_client->cur_chain ? l_node_client->cur_chain->cells : NULL;
                } else
                    l_node_client->cur_chain = NULL;
            } else {
                // Check if we over with it before
                if ( ! l_node_client->cur_cell ){
                    if(s_stream_ch_chain_debug_more)
                        log_it(L_INFO, "In: No current cell in sync state, anyway we over it");
                }else
                    l_node_client->cur_cell =(dap_chain_cell_t *)  l_node_client->cur_cell->hh.next;

                // If  over with cell, switch on next chain
                if ( l_node_client->cur_cell){
                    // Check if we over with it before
                    if ( !l_node_client->cur_chain ){
                        log_it(L_ERROR, "In: No chain but cell is present, over with it");
                    }
                }else{
                    // Check if we over with it before
                    if ( !l_node_client->cur_chain ){
                        log_it(L_WARNING, "In: No current chain in sync state, anyway we over it");
                    }else{
                        l_node_client->cur_chain = (dap_chain_t *) l_node_client->cur_chain->next;
                        l_node_client->cur_cell = l_node_client->cur_chain ? l_node_client->cur_chain->cells : NULL;
                    }
                }
            }

            if (l_node_client->cur_cell)
                l_cell_id = l_node_client->cur_cell->id;
            // Check if we have some more chains and cells in it to sync
            dap_chain_node_addr_t l_node_addr;
            l_node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
            if( l_node_client->cur_chain ){
                l_chain_id=l_node_client->cur_chain->id;
                if (s_stream_ch_chain_debug_more) {
                    log_it(L_INFO,"In: Link %s."NODE_ADDR_FP_STR" started to sync %s chain",l_net->pub.name,
                           NODE_ADDR_FP_ARGS_S(l_node_addr), l_node_client->cur_chain->name );
                }
                dap_stream_ch_chain_pkt_write_unsafe(l_node_client->ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ,
                                                     l_net->pub.id.uint64 ,
                                                     l_chain_id.uint64,l_cell_id.uint64,NULL,0);
            } else { // If no - over with sync process
                log_it(L_INFO, "In: State node %s."NODE_ADDR_FP_STR" is SYNCED",l_net->pub.name, NODE_ADDR_FP_ARGS_S(l_node_addr) );
                l_finished = true;
            }
        } break;
        default: break;
    }
    if (l_finished) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_SYNCED;
        dap_cond_signal(l_node_client->wait_cond);
        pthread_mutex_unlock(&l_node_client->wait_mutex);
        bool l_have_waiting = dap_chain_net_sync_unlock(l_net, l_node_client);
        if (dap_chain_net_get_target_state(l_net) == NET_STATE_ONLINE) {
            dap_timerfd_reset_unsafe(l_node_client->sync_timer);
            dap_chain_net_set_state(l_net, NET_STATE_ONLINE);
        }
        else if (!l_have_waiting)
        {
            // l_node_client object is not presented after dap_chain_net_state_go_to with NET_STATE_OFFLINE
            dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE);
        }
    }
}



/**
 * @brief s_ch_chain_callback_notify_packet_in
 * @param a_ch_chain
 * @param a_pkt_type
 * @param a_pkt
 * @param a_pkt_data_size
 * @param a_arg
 */
static void s_ch_chain_callback_notify_packet_out(dap_stream_ch_chain_t* a_ch_chain, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg)
{
    (void) a_pkt;
    (void) a_pkt_data_size;
    (void) a_ch_chain;
    dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t *) a_arg;
    assert(a_arg);
    switch (a_pkt_type) {
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB: {
            if(s_stream_ch_chain_debug_more)
                log_it(L_INFO,"Out: global database sent to uplink "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
        } break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: {
            if(s_stream_ch_chain_debug_more)
                log_it(L_INFO,"Out: chain %"DAP_UINT64_FORMAT_x" sent to uplink "NODE_ADDR_FP_STR,l_node_client->cur_chain ? l_node_client->cur_chain->id.uint64 : 0, NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
        } break;
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_TIMEOUT:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_DELETE: {
            dap_chain_net_t *l_net = l_node_client->net;
            assert(l_net);
            log_it(L_DEBUG, "In: State node %s."NODE_ADDR_FP_STR" %s", l_net->pub.name, NODE_ADDR_FP_ARGS_S(g_node_addr),
                            a_pkt_type == DAP_STREAM_CH_CHAIN_PKT_TYPE_TIMEOUT ? "is timeout for sync" : "stream closed");
            l_node_client->state = NODE_CLIENT_STATE_ERROR;
            if (l_node_client->sync_timer)
                dap_timerfd_reset_unsafe(l_node_client->sync_timer);
            bool l_have_waiting = dap_chain_net_sync_unlock(l_net, l_node_client);
            if (!l_have_waiting) {
                if (dap_chain_net_get_target_state(l_net) == NET_STATE_ONLINE)
                    dap_chain_net_set_state(l_net, NET_STATE_ONLINE);
                else
                    dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE);
            }
        } break;
        default:;
    }
}

/**
 * @brief s_save_stat_to_database_callback_set_stat
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_value_ts
 * @param a_is_pinned
 * @param a_arg
 */
static void s_save_stat_to_database_callback_set_stat(dap_global_db_instance_t *a_dbi, int a_rc, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, dap_nanotime_t a_value_ts, bool a_is_pinned, void * a_arg)
{
    if( a_rc != DAP_GLOBAL_DB_RC_SUCCESS)
        log_it(L_ERROR,"Can't save stats to GlobalDB, code %d", a_rc);

    DAP_DELETE(a_arg);
}

/**
 * @brief s_save_stat_to_database_callback_get_last_stat
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_value
 * @param a_value_len
 * @param a_value_ts
 * @param a_is_pinned
 * @param a_arg
 */
static void s_save_stat_to_database_callback_get_last_stat(dap_global_db_instance_t *a_dbi, int a_rc, const char * a_group, const char * a_key, const void * a_value, const size_t a_value_len, dap_nanotime_t a_value_ts, bool a_is_pinned, void * a_arg)
{
    char * l_json_str = (char *) a_arg;
    uint64_t l_key = 0;
    if(a_rc == DAP_GLOBAL_DB_RC_SUCCESS) {
        l_key = strtoll(a_key, NULL, 16);
    }

    char *l_key_str = dap_strdup_printf("%06"DAP_UINT64_FORMAT_x, ++l_key);
    dap_global_db_set(a_group, l_key_str, l_json_str, strlen(l_json_str) + 1,false, s_save_stat_to_database_callback_set_stat, l_json_str);

    DAP_DELETE(l_key_str);

}

/**
 * @brief save_stat_to_database
 *
 * @param a_request
 * @param a_node_client
 * @return int
 */
static int s_save_stat_to_database(dap_stream_ch_chain_net_srv_pkt_test_t *a_request, dap_chain_node_client_t * a_node_client)
{
    UNUSED(a_node_client);
    int l_ret = 0;
    if(!a_request)
        return -1;
    long l_t1_ms = a_request->send_time1 / 1e6;
    long l_t2_ms = a_request->recv_time1 / 1e6;
    struct json_object *jobj = json_object_new_object();
    time_t l_cur_t = time(NULL);
    char buf[1024];
    dap_time_to_str_rfc822( buf, sizeof(buf), l_cur_t );
    json_object_object_add(jobj, "time_save", json_object_new_int64(l_cur_t));
    json_object_object_add(jobj, "time_save_str", json_object_new_string(buf));
    json_object_object_add(jobj, "time_connect", json_object_new_int(a_request->time_connect_ms));
    json_object_object_add(jobj, "time_transmit", json_object_new_int(l_t2_ms-l_t1_ms));
    json_object_object_add(jobj, "ip_send", json_object_new_string((char *)a_request->ip_send));
    json_object_object_add(jobj, "ip_recv", json_object_new_string((char *)a_request->ip_recv));
    json_object_object_add(jobj, "time_len_send", json_object_new_int(a_request->data_size_send));
    json_object_object_add(jobj, "time_len_recv", json_object_new_int(a_request->data_size_recv));
    json_object_object_add(jobj, "err_code", json_object_new_int(a_request->err_code));
    const char* l_json_str = json_object_to_json_string(jobj);
    // save statistics
    char *l_group = NULL;
    dap_chain_net_t * l_net = dap_chain_net_by_id(a_request->net_id);
    if(l_net) {
        l_group = dap_strdup_printf("local.%s.orders-test-stat", l_net->pub.gdb_groups_prefix);
    }
    if(l_group) {
        dap_global_db_get_last( l_group, s_save_stat_to_database_callback_get_last_stat,
                                dap_strdup(l_json_str));
        DAP_DELETE(l_group);
    }
    else
        l_ret = -2;
    json_object_put(jobj);
    return l_ret;
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
            s_save_stat_to_database(l_request, l_node_client);
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
    if (dap_chain_node_client_connect(l_node_client, a_active_channels))
        return l_node_client;
    return NULL;
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
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }

    l_node_client->state = NODE_CLIENT_STATE_DISCONNECTED;
    l_node_client->callbacks_arg = a_callback_arg;
    if (a_callbacks)
        l_node_client->callbacks = *a_callbacks;
    l_node_client->info = DAP_DUP(a_node_info);
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
    l_node_client->remote_node_addr.uint64 = a_node_info->hdr.address.uint64;
    return l_node_client;
}


 void s_client_delete_callback(UNUSED_ARG dap_client_t *a_client, void *a_arg)
 {
     // TODO make decision for possible client replacement
     assert(a_arg);
     ((dap_chain_node_client_t *)a_arg)->client = NULL;
     dap_chain_node_client_close_unsafe(a_arg);
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

/**
 * @brief dap_chain_node_client_reset
 *
 * @param a_client dap_chain_node_client_t
 */
void dap_chain_node_client_reset(dap_chain_node_client_t *a_client)
{
    if (a_client->state > NODE_CLIENT_STATE_ESTABLISHED) {
        a_client->state = NODE_CLIENT_STATE_ESTABLISHED;
    }
}

/**
 * @brief dap_chain_node_client_close
 * Close connection to server, delete chain_node_client_t *client
 * @param a_client dap_chain_node_client_t
 */
void dap_chain_node_client_close_unsafe(dap_chain_node_client_t *a_node_client)
{
    char l_node_addr_str[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a_node_client->info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
    log_it(L_INFO, "Closing node client to uplink %s:%d ["NODE_ADDR_FP_STR"]",
                    l_node_addr_str, a_node_client->info->hdr.ext_port, NODE_ADDR_FP_ARGS_S(a_node_client->remote_node_addr));

    if (a_node_client->sync_timer)
        dap_timerfd_delete_unsafe(a_node_client->sync_timer);
    if (a_node_client->reconnect_timer)
        dap_timerfd_delete_mt(a_node_client->reconnect_timer->worker, a_node_client->reconnect_timer->esocket_uuid);
    if (a_node_client->callbacks.delete)
        a_node_client->callbacks.delete(a_node_client, a_node_client->net);

    if (a_node_client->stream_worker) {
        dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(a_node_client->stream_worker, a_node_client->ch_chain_uuid);
        if (l_ch) {
            dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
            l_ch_chain->callback_notify_packet_in = NULL;
            l_ch_chain->callback_notify_packet_out = NULL;
        }
        l_ch = dap_stream_ch_find_by_uuid_unsafe(a_node_client->stream_worker, a_node_client->ch_chain_net_uuid);
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

void s_close_on_worker_callback(UNUSED_ARG dap_worker_t *a_worker, void *a_arg)
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
 * @brief dap_chain_node_client_send_ch_pkt
 * Send stream request to server
 * @param a_client
 * @param a_ch_id
 * @param a_type
 * @param a_pkt_data
 * @param a_pkt_data_size
 * @return int
 */
int dap_chain_node_client_send_ch_pkt(dap_chain_node_client_t *a_client, uint8_t a_ch_id, uint8_t a_type,
        const void *a_pkt_data, size_t a_pkt_data_size)
{
    if(!a_client || a_client->state < NODE_CLIENT_STATE_ESTABLISHED)
        return -1;

    dap_stream_worker_t *l_stream_worker = dap_client_get_stream_worker(a_client->client);
    dap_stream_ch_pkt_write_mt(l_stream_worker , a_client->ch_chain_uuid , a_type, a_pkt_data, a_pkt_data_size);
    return 0;
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
    a_client->keep_connection = false;
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
    //TODO pass callbacks through stream creation to internal ch structures

    int l_ret = -1;
    dap_chain_node_client_t *l_node_client = a_client->_inheritor;
    if(l_node_client) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        // find current channel code
        dap_stream_ch_t *l_ch = dap_client_get_stream_ch_unsafe(a_client, a_ch_id);
        if(l_ch) {
            l_ret = 0;
            switch (a_ch_id) {
                //  'C'
            case DAP_STREAM_CH_ID: {
                dap_stream_ch_chain_t *l_ch_chain       = DAP_STREAM_CH_CHAIN(l_ch);
                l_ch_chain->callback_notify_packet_out  = s_ch_chain_callback_notify_packet_out;
                l_ch_chain->callback_notify_packet_in   = s_ch_chain_callback_notify_packet_in;
                l_ch_chain->callback_notify_arg         = l_node_client;
                l_node_client->ch_chain         = l_ch;
                l_node_client->ch_chain_uuid    = l_ch->uuid;
                break;
            }
                //  'N'
            case DAP_STREAM_CH_ID_NET: {
                dap_stream_ch_chain_net_t *l_ch_chain   = DAP_STREAM_CH_CHAIN_NET(l_ch);
                l_ch_chain->notify_callback     = s_ch_chain_callback_notify_packet_in2;
                l_ch_chain->notify_callback_arg = l_node_client;
                l_node_client->ch_chain_net         = l_ch;
                l_node_client->ch_chain_net_uuid    = l_ch->uuid;
                break;
            }
                //  'R'
            case DAP_STREAM_CH_ID_NET_SRV: {
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
                // 'V'
            case DAP_STREAM_CH_ID_VOTING: {
                dap_stream_ch_chain_voting_t *l_ch_chain    = DAP_STREAM_CH_CHAIN_VOTING(l_ch);
                // l_ch_chain->callback_notify              = s_ch_chain_callback_notify_voting_packet_in;
                l_ch_chain->callback_notify_arg             = l_node_client;
                l_node_client->ch_chain_net         = l_ch;
                l_node_client->ch_chain_net_uuid    = l_ch->uuid;
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

/**
 * @brief dap_chain_node_client_send_nodelist_req
 * Send nodelist request to server
 * @param a_client
 * @return int
 */
int dap_chain_node_client_send_nodelist_req(dap_chain_node_client_t *a_client)
{
    if(!a_client || !a_client->client || a_client->state < NODE_CLIENT_STATE_ESTABLISHED)
        return -1;
    //dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client->client);

    //TODO send request to get nodelist
    //dap_client_request_enc(a_client->client, DAP_UPLINK_PATH_NODE_LIST, "", "", "", 0,
    //        nodelist_response_callback, nodelist_response_error_callback);
    return 1;
}
