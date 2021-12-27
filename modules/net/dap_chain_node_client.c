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

#include <json-c/json.h>
#include "uthash.h"

#include "dap_common.h"
#include "dap_client.h"
#include "dap_config.h"
#include "dap_events.h"
#include "dap_timerfd.h"
#include "dap_hash.h"
#include "dap_uuid.h"
//#include "dap_http_client_simple.h"
#include "dap_client_pvt.h"
#include "dap_chain_global_db_remote.h"
#include "dap_chain_global_db_hist.h"

#include "dap_chain.h"
#include "dap_chain_cell.h"

#include "dap_chain_net_srv_common.h"
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_pkt.h"

//#include "dap_chain_common.h"
#include "dap_chain_node_client.h"

#define LOG_TAG "dap_chain_node_client"

typedef struct dap_chain_node_client_handle {
    uint64_t uuid;
    dap_chain_node_client_t * client;
    UT_hash_handle hh;
} dap_chain_node_client_handle_t;

static dap_chain_node_client_handle_t * s_clients = NULL;

//static int listen_port_tcp = 8079;

static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg);
static bool s_timer_update_states_callback(void *a_arg);

static void s_ch_chain_callback_notify_packet_out(dap_stream_ch_chain_t*, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);
static void s_ch_chain_callback_notify_packet_in(dap_stream_ch_chain_t* a_ch_chain, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);
static bool dap_chain_node_client_connect_internal(dap_chain_node_client_t *a_node_client, const char *a_active_channels);

bool s_stream_ch_chain_debug_more = false;
uint32_t s_timer_update_states=60;

/**
 * @brief dap_chain_node_client_init
 * @return
 */
int dap_chain_node_client_init(void)
{
    s_stream_ch_chain_debug_more = dap_config_get_item_bool_default(g_config,"stream_ch_chain","debug_more",false);
    s_timer_update_states = dap_config_get_item_uint32_default(g_config,"node_client","timer_update_states",60);
    return 0;
}

/**
 * @brief dap_chain_node_client_deinit
 */
void dap_chain_node_client_deinit()
{
    dap_chain_node_client_handle_t *l_client = NULL, *l_tmp = NULL;
    HASH_ITER(hh, s_clients,l_client, l_tmp){
        HASH_DEL(s_clients,l_client);
        DAP_DELETE(l_client);
    }
    //dap_http_client_simple_deinit();
    dap_client_deinit();
}

/**
 * @brief stage_status_callback
 * @param a_client
 * @param a_arg
 */
static void s_stage_status_callback(dap_client_t *a_client, void *a_arg)
{
    (void) a_client;
    (void) a_arg;

    //printf("* stage_status_callback client=%x data=%x\n", a_client, a_arg);
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
    // check for last attempt
    bool l_is_last_attempt = a_arg ? true : false;
    if (l_is_last_attempt) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_DISCONNECTED;
#ifndef _WIN32
        pthread_cond_broadcast(&l_node_client->wait_cond);
#else
        SetEvent( l_node_client->wait_cond );
#endif
        pthread_mutex_unlock(&l_node_client->wait_mutex);
        l_node_client->esocket_uuid = 0;

        dap_chain_net_sync_unlock(l_node_client->net, l_node_client);
        if (l_node_client->callbacks.disconnected) {
            l_node_client->callbacks.disconnected(l_node_client, l_node_client->callbacks_arg);
        }
        if (l_node_client->keep_connection) {
            dap_events_socket_uuid_t *l_uuid = DAP_DUP(&l_node_client->uuid);
            l_node_client->sync_timer = dap_timerfd_start_on_worker(l_node_client->stream_worker
                                                                         ? l_node_client->stream_worker->worker
                                                                         : dap_events_worker_get_auto(),
                                                                    s_timer_update_states * 1000,
                                                                    s_timer_update_states_callback,
                                                                    l_uuid);
        }
        return;
    }
    // TODO make different error codes
    if(l_node_client->callbacks.error)
        l_node_client->callbacks.error(l_node_client, EINVAL, l_node_client->callbacks_arg);
}

/**
 * @brief s_node_client_connected_synchro_start_callback
 * 
 * @param a_worker dap_worker_t
 * @param a_arg void 
 */
static void s_node_client_connected_synchro_start_callback(dap_worker_t *a_worker, void *a_arg)
{
    UNUSED(a_worker);
    if (s_timer_update_states_callback(a_arg))
        DAP_DELETE(a_arg);
}

/**
 * @brief s_timer_update_states_callback
 * @param a_arg
 * @return
 */
static bool s_timer_update_states_callback(void *a_arg)
{
    dap_chain_node_client_handle_t *l_client_found = NULL;
    dap_events_socket_uuid_t *l_uuid = (dap_events_socket_uuid_t *)a_arg;
    assert(l_uuid);
    HASH_FIND(hh, s_clients, l_uuid, sizeof(*l_uuid), l_client_found);
    if(!l_client_found){
        log_it(L_DEBUG,"Chain node client %p was deleted before timer fired, nothing to do", l_uuid);
        DAP_DELETE(l_uuid);
        return false;
    }

    dap_chain_node_client_t *l_me = l_client_found->client;
    dap_worker_t * l_worker = dap_events_get_current_worker(dap_events_get_default());
    assert(l_worker);
    assert(l_me);
    dap_events_socket_t * l_es = NULL;
    dap_events_socket_uuid_t l_es_uuid = l_me->esocket_uuid;
    // check if esocket still in worker
    if( (l_es = dap_worker_esocket_find_uuid(l_worker, l_es_uuid)) != NULL ) {
        dap_client_t * l_client = dap_client_from_esocket(l_es);
        if (l_client ) {
            dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t*) l_client->_inheritor;
            if (l_node_client && l_node_client->ch_chain && l_node_client->stream_worker && l_node_client->ch_chain_uuid) {
                dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(l_node_client->stream_worker, l_node_client->ch_chain_uuid);
                if (l_ch) {
                    dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
                    assert(l_ch_chain);
                    dap_chain_net_t * l_net = l_node_client->net;
                    assert(l_net);
                    // If we do nothing - init sync process
                    if (l_ch_chain->state == CHAIN_STATE_IDLE && dap_chain_net_sync_trylock(l_net, l_me)) {
                        log_it(L_INFO, "Start synchronization process with "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
                        dap_stream_ch_chain_sync_request_t l_sync_gdb = {};
                        l_sync_gdb.node_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
                        dap_stream_ch_chain_pkt_write_unsafe(l_node_client->ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ,
                                                             l_net->pub.id.uint64, 0, l_net->pub.cell_id.uint64,
                                                             &l_sync_gdb, sizeof(l_sync_gdb));
                    }
                    return true;
                }
            }
        }
    }

    // if we not returned yet
    l_me->state = NODE_CLIENT_STATE_DISCONNECTED;
    if (l_me->keep_connection) {
        if (dap_client_pvt_find(l_me->client->pvt_uuid)) {
            log_it(L_INFO, "Reconnecting node client with peer "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_me->remote_node_addr));
            l_me->state = NODE_CLIENT_STATE_CONNECTING ;
            dap_client_go_stage(l_me->client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
        } else
            dap_chain_node_client_close(l_me);
    }
    DAP_DELETE(l_uuid);
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
        log_it(L_NOTICE, "Stream connection with node " NODE_ADDR_FP_STR " established",
                NODE_ADDR_FP_ARGS_S( l_node_client->remote_node_addr));
        // set callbacks for C and N channels; for R and S it is not needed
        dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
        if(l_client_internal && l_client_internal->active_channels) {
            size_t l_channels_count = dap_strlen(l_client_internal->active_channels);
            for(size_t i = 0; i < l_channels_count; i++) {
                if(dap_chain_node_client_set_callbacks(a_client, l_client_internal->active_channels[i]) == -1) {
                    log_it(L_WARNING, "No ch_chain channel, can't init notify callback for pkt type CH_CHAIN");
                    return;
                }
            }
        }
        if(l_node_client->callbacks.connected)
            l_node_client->callbacks.connected(l_node_client, l_node_client->callbacks_arg);
        if(s_stream_ch_chain_debug_more)
            log_it(L_DEBUG, "Wakeup all who waits");
        l_node_client->state = NODE_CLIENT_STATE_ESTABLISHED;

        dap_stream_t * l_stream  = dap_client_get_stream(a_client);
        if (l_stream) {
            l_node_client->esocket_uuid = l_stream->esocket->uuid;
            l_node_client->stream_worker = l_stream->stream_worker;
            if (l_node_client->keep_connection) {
                dap_events_socket_uuid_t *l_uuid = DAP_DUP(&l_node_client->uuid);
                dap_worker_exec_callback_on(l_stream->esocket->worker, s_node_client_connected_synchro_start_callback, l_uuid);
                dap_events_socket_uuid_t *l_uuid_timer = DAP_DUP(&l_node_client->uuid);
                l_node_client->sync_timer = dap_timerfd_start_on_worker(l_stream->esocket->worker,
                                                                        s_timer_update_states * 1000,
                                                                        s_timer_update_states_callback,
                                                                        l_uuid_timer);
            }
        }
#ifndef _WIN32
        pthread_cond_broadcast(&l_node_client->wait_cond);
#else
        SetEvent( l_node_client->wait_cond );
#endif
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
    // get new generated current node address
    case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE: {
        if(a_pkt_net_data_size == sizeof(dap_chain_node_addr_t)) {
            dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t *) a_pkt_net->data;
            memcpy(&l_node_client->cur_node_addr, l_addr, sizeof(dap_chain_node_addr_t));
        }
        l_node_client->state = NODE_CLIENT_STATE_NODE_ADDR_LEASED;
#ifndef _WIN32
        pthread_cond_broadcast(&l_node_client->wait_cond);
#else
        SetEvent( l_node_client->wait_cond );
#endif
        break;
    }
    // get remote node address
    case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR: {

        if(a_pkt_net_data_size == sizeof(dap_chain_node_addr_t)) {
            dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t *) a_pkt_net->data;
            memcpy(&l_node_client->remote_node_addr, l_addr, sizeof(dap_chain_node_addr_t));
        }
        l_node_client->state = NODE_CLIENT_STATE_GET_NODE_ADDR;
#ifndef _WIN32
        pthread_cond_broadcast(&l_node_client->wait_cond);
#else
            SetEvent( l_node_client->wait_cond );
#endif
            break;
    }
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
    UNUSED(a_ch_chain);
    UNUSED(a_pkt_data_size);
    dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t *) a_arg;

    switch (a_pkt_type) {
        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR:
            dap_snprintf(l_node_client->last_error, sizeof(l_node_client->last_error),
                    "%s", (char*) a_pkt->data);
            log_it(L_WARNING, "In: Received packet DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR with error \"%s\"",
                    l_node_client->last_error);
            l_node_client->state = NODE_CLIENT_STATE_ERROR;

    #ifndef _WIN32
            pthread_cond_broadcast(&l_node_client->wait_cond);
    #else
            SetEvent( l_node_client->wait_cond );
    #endif
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
            dap_chain_net_t *l_net = l_node_client->net;
            assert(l_net);
            dap_chain_id_t  l_chain_id = {};
            dap_chain_cell_id_t l_cell_id = {};
            if (a_pkt_type == DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB) {
                if (dap_chain_net_get_target_state(l_net) != NET_STATE_SYNC_GDB) {
                    if(s_stream_ch_chain_debug_more)
                        log_it(L_INFO,"In: Link %s."NODE_ADDR_FP_STR" synced GDB. Going to update chains", l_net->pub.name, NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr ));
                    l_node_client->cur_chain = l_net->pub.chains;
                    l_node_client->cur_cell = l_node_client->cur_chain ? l_node_client->cur_chain->cells : NULL;
                }
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
            if( l_node_client->cur_chain ){
                l_chain_id=l_node_client->cur_chain->id;
                if (s_stream_ch_chain_debug_more) {
                    dap_chain_node_addr_t * l_node_addr = dap_chain_net_get_cur_addr(l_net);
                    log_it(L_INFO,"In: Link %s."NODE_ADDR_FP_STR" started to sync %s chain",l_net->pub.name,
                           NODE_ADDR_FP_ARGS(l_node_addr), l_node_client->cur_chain->name );
                }
                dap_stream_ch_chain_pkt_write_unsafe(l_node_client->ch_chain, DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ,
                                                     l_net->pub.id.uint64 ,
                                                     l_chain_id.uint64,l_cell_id.uint64,NULL,0);
            }else{ // If no - over with sync process
                dap_chain_node_addr_t * l_node_addr = dap_chain_net_get_cur_addr(l_net);
                log_it(L_INFO, "In: State node %s."NODE_ADDR_FP_STR" is SYNCED",l_net->pub.name, NODE_ADDR_FP_ARGS(l_node_addr) );
                dap_chain_net_sync_unlock(l_net, l_node_client);
                l_node_client->state = NODE_CLIENT_STATE_SYNCED;
                if (dap_chain_net_get_target_state(l_net) == NET_STATE_ONLINE)
                    dap_chain_net_set_state(l_net, NET_STATE_ONLINE);
                else
                    dap_chain_net_state_go_to(l_net, NET_STATE_OFFLINE);
                dap_timerfd_reset(l_node_client->sync_timer);
#ifndef _WIN32
                pthread_cond_broadcast(&l_node_client->wait_cond);
#else
                SetEvent( l_node_client->wait_cond );
#endif
            }
        } break;
        default: break;
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
    dap_stream_ch_t * l_ch = NULL;
    //if((l_ch = dap_stream_ch_find_by_uuid_unsafe(l_node_client->stream_worker, l_node_client->ch_chain_uuid)) != NULL){
        switch (a_pkt_type) {
            case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB: {
                if(s_stream_ch_chain_debug_more)
                    log_it(L_INFO,"Out: global database sent to uplink "NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
            } break;
            case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: {
                if(s_stream_ch_chain_debug_more)
                    log_it(L_INFO,"Out: chain %"DAP_UINT64_FORMAT_x" sent to uplink "NODE_ADDR_FP_STR,l_node_client->cur_chain ? l_node_client->cur_chain->id.uint64 : 0, NODE_ADDR_FP_ARGS_S(l_node_client->remote_node_addr));
            }break;
            default: {
            }
        }
    //}
}

/**
 * @brief save_stat_to_database
 * 
 * @param a_request 
 * @param a_node_client 
 * @return int 
 */
static int save_stat_to_database(dap_stream_ch_chain_net_srv_pkt_test_t *a_request, dap_chain_node_client_t * a_node_client)
{
    UNUSED(a_node_client);
    int l_ret = 0;
    if(!a_request)
        return -1;
    long l_t1_ms = (long) a_request->send_time1.tv_sec * 1000 + a_request->send_time1.tv_usec / 1000;
    long l_t2_ms = (long) a_request->recv_time1.tv_sec * 1000 + a_request->recv_time1.tv_usec / 1000;
    struct json_object *jobj = json_object_new_object();
    time_t l_cur_t = time(NULL);
    char buf[1024];
    dap_time_to_str_rfc822( buf, sizeof(buf), l_cur_t );
    json_object_object_add(jobj, "time_save", json_object_new_int64(l_cur_t));
    json_object_object_add(jobj, "time_save_str", json_object_new_string(buf));
    json_object_object_add(jobj, "time_connect", json_object_new_int(a_request->time_connect_ms));
    json_object_object_add(jobj, "time_transmit", json_object_new_int(l_t2_ms-l_t1_ms));
    json_object_object_add(jobj, "ip_send", json_object_new_string(a_request->ip_send));
    json_object_object_add(jobj, "ip_recv", json_object_new_string(a_request->ip_recv));
    json_object_object_add(jobj, "time_len_send", json_object_new_int(a_request->data_size_send));
    json_object_object_add(jobj, "time_len_recv", json_object_new_int(a_request->data_size_recv));
    json_object_object_add(jobj, "err_code", json_object_new_int(a_request->err_code));
    const char* json_str = json_object_to_json_string(jobj);
    // save statistics
    char *l_group = NULL;
    dap_chain_net_t * l_net = dap_chain_net_by_id(a_request->net_id);
    if(l_net) {
        l_group = dap_strdup_printf("local.%s.orders-test-stat", l_net->pub.gdb_groups_prefix);
    }
    if(l_group) {
        dap_store_obj_t *l_obj = dap_chain_global_db_get_last(l_group);
        int64_t l_key = 0;
        if(l_obj) {
            l_key = strtoll(l_obj->key, NULL, 16);
        }
        char *l_key_str = dap_strdup_printf("%06x", ++l_key);
        if(!dap_chain_global_db_gr_set(dap_strdup(l_key_str), (uint8_t *) json_str, strlen(json_str) + 1, l_group)) {
            l_ret = -1;
        }
        DAP_DELETE(l_key_str);
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
    dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t *) a_arg;
    switch (a_pkt_type) {
    // get new generated current node address
    case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_CHECK_RESPONSE: {
            dap_stream_ch_chain_net_srv_pkt_test_t *l_request = (dap_stream_ch_chain_net_srv_pkt_test_t *) a_pkt->data;
            size_t l_request_size = l_request->data_size + sizeof(dap_stream_ch_chain_net_srv_pkt_test_t);
            if(a_pkt->hdr.size != l_request_size) {
                log_it(L_WARNING, "Wrong request size, less or more than required");
                break;
            }
            // todo to write result to database
            save_stat_to_database(l_request, l_node_client);
            //...
            l_node_client->state = NODE_CLIENT_STATE_CHECKED;
#ifndef _WIN32
            pthread_cond_broadcast(&l_node_client->wait_cond);
#else
            SetEvent( l_node_client->wait_cond );
#endif
            break;
        }
    }
}


/**
 * @brief dap_chain_node_client_connect_channels
 * Create connection to server
 * @param l_net 
 * @param a_node_info 
 * @param a_active_channels 
 * @return dap_chain_node_client_t* return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_node_client_connect_channels(dap_chain_net_t * l_net, dap_chain_node_info_t *a_node_info, const char *a_active_channels)
{
    return dap_chain_net_client_create_n_connect_channels(l_net,a_node_info,a_active_channels);
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
dap_chain_node_client_t* dap_chain_node_client_create_n_connect(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info,
        const char *a_active_channels,dap_chain_node_client_callbacks_t *a_callbacks, void * a_callback_arg )
{
    if(!a_node_info) {
        log_it(L_ERROR, "Can't connect to the node: null object node_info");
        return NULL;
    }
    dap_chain_node_client_t *l_node_client = DAP_NEW_Z(dap_chain_node_client_t);

    l_node_client->state = NODE_CLIENT_STATE_DISCONNECTED;
    l_node_client->callbacks_arg = a_callback_arg;
    if(a_callbacks)
        memcpy(&l_node_client->callbacks,a_callbacks,sizeof (*a_callbacks));
    l_node_client->info = a_node_info;
    l_node_client->uuid = dap_uuid_generate_uint64();
    l_node_client->net = a_net;
    dap_chain_node_client_handle_t * l_client_handle = DAP_NEW_Z(dap_chain_node_client_handle_t);
    l_client_handle->uuid = l_node_client->uuid;
    l_client_handle->client = l_node_client;
    HASH_ADD(hh, s_clients, uuid, sizeof(l_client_handle->uuid), l_client_handle);

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
    l_node_client->events = NULL; //dap_events_new();
    l_node_client->remote_node_addr.uint64 = a_node_info->hdr.address.uint64;
    if (dap_chain_node_client_connect_internal(l_node_client, a_active_channels))
        return l_node_client;
    return NULL;
}

/**
 * @brief dap_chain_node_client_connect_internal
 * Create new dap_client, setup it, and send it in adventure trip
 * @param a_node_client dap_chain_node_client_t
 * @param a_active_channels a_active_channels
 * @return true 
 * @return false 
 */
static bool dap_chain_node_client_connect_internal(dap_chain_node_client_t *a_node_client, const char *a_active_channels)
{
    a_node_client->client = dap_client_new(a_node_client->events, s_stage_status_callback,
            s_stage_status_error_callback);
    dap_client_set_is_always_reconnect(a_node_client->client, false);
    a_node_client->client->_inheritor = a_node_client;
    dap_client_set_active_channels_unsafe(a_node_client->client, a_active_channels);

    //dap_client_set_auth_cert(a_node_client->client, dap_cert_find_by_name("auth")); // TODO provide the certificate choice

    int hostlen = 128;
    char host[hostlen];
    if(a_node_client->info->hdr.ext_addr_v4.s_addr){
        struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = a_node_client->info->hdr.ext_addr_v4 };
        inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host, hostlen);
        log_it(L_INFO, "Connecting to %s address",host);
    } else {
        struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = a_node_client->info->hdr.ext_addr_v6 };
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), host, hostlen);
        log_it(L_INFO, "Connecting to %s address",host);
    }
    // address not defined
    if(!strcmp(host, "::")) {
        dap_chain_node_client_close(a_node_client);
        return false;
    }
    dap_client_set_uplink_unsafe(a_node_client->client, strdup(host), a_node_client->info->hdr.ext_port);
    a_node_client->state = NODE_CLIENT_STATE_CONNECTING ;
    // Handshake & connect
    dap_client_go_stage(a_node_client->client, STAGE_STREAM_STREAMING, s_stage_connected_callback);
    return true;
}

/**
 * @brief dap_chain_node_client_connect
 * Create connection to server
 * @param a_net 
 * @param a_node_info 
 * @return dap_chain_node_client_t* return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_node_client_connect(dap_chain_net_t * a_net,dap_chain_node_info_t *a_node_info)
{
    const char *l_active_channels = "CN";
    return dap_chain_node_client_connect_channels(a_net,a_node_info, l_active_channels);
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
void dap_chain_node_client_close(dap_chain_node_client_t *a_client)
{
    if (!a_client)
        return;
    dap_chain_node_client_handle_t * l_client_found = NULL;
    HASH_FIND(hh,s_clients,&a_client->uuid,sizeof(a_client->uuid),l_client_found);
    if (l_client_found) {
        HASH_DEL(s_clients,l_client_found);
        DAP_DELETE(l_client_found);
        if (a_client->callbacks.delete)
            a_client->callbacks.delete(a_client, a_client->net);
        char l_node_addr_str[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &a_client->info->hdr.ext_addr_v4, l_node_addr_str, INET_ADDRSTRLEN);
        log_it(L_INFO, "Closing node client to uplink %s:%d", l_node_addr_str, a_client->info->hdr.ext_port);
        if (a_client->stream_worker) {
            dap_stream_ch_t *l_ch = dap_stream_ch_find_by_uuid_unsafe(a_client->stream_worker, a_client->ch_chain_uuid);
            if (l_ch) {
                dap_stream_ch_chain_t *l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
                l_ch_chain->callback_notify_packet_in = NULL;
                l_ch_chain->callback_notify_packet_out = NULL;
            }
            l_ch = dap_stream_ch_find_by_uuid_unsafe(a_client->stream_worker, a_client->ch_chain_net_uuid);
            if (l_ch) {
                dap_stream_ch_chain_net_t *l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(l_ch);
                l_ch_chain_net->notify_callback = NULL;
            }
        }
        // clean client
        dap_client_pvt_t *l_client_pvt = dap_client_pvt_find(a_client->client->pvt_uuid);
        if (l_client_pvt) {
            dap_client_delete_mt(a_client->client);
            a_client->client->_inheritor = NULL;
        }
#ifndef _WIN32
        pthread_cond_destroy(&a_client->wait_cond);
#else
        CloseHandle( a_client->wait_cond );
#endif
        pthread_mutex_destroy(&a_client->wait_mutex);
        a_client->client = NULL;
        DAP_DELETE(a_client);
    } else {
        log_it(L_WARNING, "Chain node client was removed from hash table before for some reasons");
    }
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
#else
    pthread_mutex_unlock( &a_client->wait_mutex );
#endif

    // signal waiting


#ifndef DAP_OS_WINDOWS
    do {
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
    } while(1);
#else
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

#ifndef DAP_OS_WINDOWS
    pthread_mutex_unlock(&a_client->wait_mutex);
#endif
    return ret;
}

/**
 * @brief dap_chain_node_client_set_callbacks
 * 
 * @param a_client dap_client_t
 * @param a_ch_id uint8_t
 * @return int 
 */
int dap_chain_node_client_set_callbacks(dap_client_t *a_client, uint8_t a_ch_id)
{
    int l_ret = -1;
    dap_chain_node_client_t *l_node_client = a_client->_inheritor;
    if(l_node_client) {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        // find current channel code
        dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
        dap_stream_ch_t * l_ch = NULL;
        if(l_client_internal)
            l_ch = dap_client_get_stream_ch_unsafe(a_client, a_ch_id);
        if(l_ch) {
            // C
            if(a_ch_id == dap_stream_ch_chain_get_id()) {
                dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
                l_ch_chain->callback_notify_packet_out = s_ch_chain_callback_notify_packet_out;
                l_ch_chain->callback_notify_packet_in = s_ch_chain_callback_notify_packet_in;
                l_ch_chain->callback_notify_arg = l_node_client;
                l_node_client->ch_chain = l_ch;
                memcpy(&l_node_client->ch_chain_uuid, &l_ch->uuid, sizeof(dap_stream_ch_uuid_t));
            }
            // N
            if(a_ch_id == dap_stream_ch_chain_net_get_id()) {
                dap_stream_ch_chain_net_t *l_ch_chain = DAP_STREAM_CH_CHAIN_NET(l_ch);
                l_ch_chain->notify_callback = s_ch_chain_callback_notify_packet_in2;
                l_ch_chain->notify_callback_arg = l_node_client;
                l_node_client->ch_chain_net = l_ch;
                memcpy(&l_node_client->ch_chain_net_uuid, &l_ch->uuid, sizeof(dap_stream_ch_uuid_t));
            }
            // R
            if(a_ch_id == dap_stream_ch_chain_net_srv_get_id()) {
                dap_stream_ch_chain_net_srv_t * l_ch_chain = DAP_STREAM_CH_CHAIN_NET_SRV(l_ch);
                l_ch_chain->notify_callback = s_ch_chain_callback_notify_packet_R;
                l_ch_chain->notify_callback_arg = l_node_client;
            }
            l_ret = 0;
        } else {
        }
        pthread_mutex_unlock(&l_node_client->wait_mutex);
    }
    return l_ret;
}

/*static void nodelist_response_callback(dap_client_t *a_client, void *data, size_t data_len)
{
}

static void nodelist_response_error_callback(dap_client_t *a_client, int a_err)
{
}*/


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
