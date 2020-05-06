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
#endif

#include "dap_common.h"
#include "dap_client.h"
#include "dap_config.h"
#include "dap_events.h"
#include "dap_hash.h"
//#include "dap_http_client_simple.h"
#include "dap_client_pvt.h"
#include "dap_chain_global_db_remote.h"
#include "dap_chain_global_db_hist.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_pkt.h"

//#include "dap_chain_common.h"
#include "dap_chain_node_client.h"

#define LOG_TAG "dap_chain_node_client"


//static int listen_port_tcp = 8079;

static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg);
static void s_ch_chain_callback_notify_packet_out(dap_stream_ch_chain_t*, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);
static void s_ch_chain_callback_notify_packet_in(dap_stream_ch_chain_t* a_ch_chain, uint8_t a_pkt_type,
        dap_stream_ch_chain_pkt_t *a_pkt, size_t a_pkt_data_size,
        void * a_arg);

/**
 * @brief dap_chain_node_client_init
 * @return
 */
int dap_chain_node_client_init(void)
{
    return 0;
}

/**
 * @brief dap_chain_node_client_deinit
 */
void dap_chain_node_client_deinit()
{
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
    dap_chain_node_client_t *l_node_client = DAP_CHAIN_NODE_CLIENT(a_client);
    if(!l_node_client)
        return;
    // check for last attempt
    bool l_is_last_attempt = a_arg ? true : false;
    if(l_is_last_attempt){
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_DISCONNECTED;
        pthread_mutex_unlock(&l_node_client->wait_mutex);
#ifndef _WIN32
        pthread_cond_signal(&l_node_client->wait_cond);
#else
        SetEvent( l_node_client->wait_cond );
#endif
    }

    if(l_node_client && l_node_client->keep_connection &&
            ((dap_client_get_stage(a_client) != STAGE_STREAM_STREAMING) ||
                    (dap_client_get_stage_status(a_client) == STAGE_STATUS_ERROR))) {
        log_it(L_NOTICE,"Some errors happends, current state is %s but we need to return back to STAGE_STREAM_STREAMING",
                dap_client_get_stage_str(a_client) );

        log_it(L_DEBUG, "Wakeup all who waits");
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_ERROR;
        pthread_mutex_unlock(&l_node_client->wait_mutex);

#ifndef _WIN32
        pthread_cond_signal(&l_node_client->wait_cond);
#else
        SetEvent( l_node_client->wait_cond );
#endif
        //dap_client_go_stage( a_client , STAGE_STREAM_STREAMING, s_stage_end_callback );
    }
    //printf("* tage_status_error_callback client=%x data=%x\n", a_client, a_arg);
}

/**
 * @brief a_stage_end_callback
 * @param a_client
 * @param a_arg
 */
static void s_stage_connected_callback(dap_client_t *a_client, void *a_arg)
{
    dap_chain_node_client_t *l_node_client = a_client->_inheritor;
    //assert(l_node_client);
    if(l_node_client) {
        log_it(L_NOTICE, "Stream connection with node " NODE_ADDR_FP_STR " established",
                NODE_ADDR_FP_ARGS_S( l_node_client->remote_node_addr));
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_CONNECTED;
        // find current channel code
        dap_client_pvt_t * l_client_internal = DAP_CLIENT_PVT(a_client);
        dap_stream_ch_t * l_ch = NULL;
        if(l_client_internal && l_client_internal->active_channels)
            l_ch = dap_client_get_stream_ch(a_client, l_client_internal->active_channels[0]);
        //dap_stream_ch_t * l_ch = dap_client_get_stream_ch(a_client, dap_stream_ch_chain_get_id());
        if(l_ch) {
            dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
            l_ch_chain->callback_notify_packet_out = s_ch_chain_callback_notify_packet_out;
            l_ch_chain->callback_notify_packet_in = s_ch_chain_callback_notify_packet_in;
            l_ch_chain->callback_notify_arg = l_node_client;
        } else {
            log_it(L_WARNING, "No ch_chain channel, can't init notify callback for pkt type CH_CHAIN");
        }

        pthread_mutex_unlock(&l_node_client->wait_mutex);
        if(l_node_client->callback_connected)
            l_node_client->callback_connected(l_node_client, a_arg);
        l_node_client->keep_connection = true;
        log_it(L_DEBUG, "Wakeup all who waits");

#ifndef _WIN32
        pthread_cond_signal(&l_node_client->wait_cond);
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
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_NODE_ADDR_LEASED;
        pthread_mutex_unlock(&l_node_client->wait_mutex);
#ifndef _WIN32
        pthread_cond_signal(&l_node_client->wait_cond);
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
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_GET_NODE_ADDR;
        pthread_mutex_unlock(&l_node_client->wait_mutex);
#ifndef _WIN32
        pthread_cond_signal(&l_node_client->wait_cond);
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
    dap_chain_node_client_t * l_node_client = (dap_chain_node_client_t *) a_arg;
    switch (a_pkt_type) {
    case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR:
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_ERROR;
        dap_snprintf(l_node_client->last_error, sizeof(l_node_client->last_error),
                "%s", (char*) a_pkt->data);
        log_it(L_WARNING, "Received packet DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR with error \"%s\"",
                l_node_client->last_error);
        pthread_mutex_unlock(&l_node_client->wait_mutex);

#ifndef _WIN32
        pthread_cond_signal(&l_node_client->wait_cond);
#else
            SetEvent( l_node_client->wait_cond );
#endif

    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: {
        dap_stream_ch_chain_sync_request_t * l_request = NULL;
        if(a_pkt_data_size == sizeof(*l_request))
            l_request = (dap_stream_ch_chain_sync_request_t*) a_pkt->data;

        if(l_request) {
            uint64_t l_id_last_here = 1;
            // for sync chain not used time
            //if(a_pkt_type != DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS)
            //    l_id_last_here =(uint64_t) dap_db_log_get_last_id();
            if(1) {//if(l_request->id_start < l_id_last_here) {
                log_it(L_INFO, "Remote is synced but we have updates for it");
                bool l_is_sync = true;
                // Get log diff
                if(a_pkt_type == DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB) {
                    a_ch_chain->request_last_ts = dap_db_log_get_last_id();
                    uint64_t l_start_item = l_request->id_start;
                    dap_db_log_list_t *l_db_log = NULL;
                    // If the current global_db has been truncated, but the remote node has not known this
                    uint64_t l_last_id = dap_db_log_get_last_id();
                    if(l_request->id_start > a_ch_chain->request_last_ts){
                        dap_chain_net_t *l_net = dap_chain_net_by_id(a_pkt->hdr.net_id);
                        dap_list_t *l_add_groups = dap_chain_net_get_add_gdb_group(l_net, a_ch_chain->request.node_addr);
                        l_db_log = dap_db_log_list_start(l_start_item + 1, l_add_groups);
                        if(!l_db_log)
                            l_start_item = 0;
                    }
                    //dap_list_t *l_list = dap_db_log_get_list(l_request->id_start + 1);
                    if(!l_db_log){
                        dap_chain_net_t *l_net = dap_chain_net_by_id(a_pkt->hdr.net_id);
                        dap_list_t *l_add_groups = dap_chain_net_get_add_gdb_group(l_net, a_ch_chain->request.node_addr);
                        l_db_log = dap_db_log_list_start(l_start_item + 1, l_add_groups);
                    }
                    if(l_db_log) {
                        // Add it to outgoing list
                        //l_list->prev = a_ch_chain->request_global_db_trs;
                        a_ch_chain->request_global_db_trs = l_db_log;//l_list;
                    }
                    else
                        l_is_sync = false;
                }
                if(l_is_sync) {
                    a_ch_chain->request_net_id.uint64 = a_pkt->hdr.net_id.uint64;
                    a_ch_chain->request_cell_id.uint64 = a_pkt->hdr.cell_id.uint64;
                    a_ch_chain->request_chain_id.uint64 = a_pkt->hdr.chain_id.uint64;
                    a_ch_chain->state = dap_stream_ch_chain_pkt_type_to_dap_stream_ch_chain_state(a_pkt_type);//CHAIN_STATE_SYNC_CHAINS;//GLOBAL_DB;

                    // type of first packet
                    uint8_t l_type =
                            (a_pkt_type != DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS) ?
                                    DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB :
                                    DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN;
                    if(l_type == DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN)
                    {
                        dap_chain_t * l_chain = dap_chain_find_by_id(a_pkt->hdr.net_id, a_pkt->hdr.chain_id);
                        if (l_chain ){
                            dap_chain_atom_iter_t* l_iter = l_chain ? l_chain->callback_atom_iter_create(l_chain) : NULL;
                            if ( l_iter ){
                                //a_ch_chain->request_atom_iter = l_iter;

                                dap_chain_atom_ptr_t * l_lasts = NULL;
                                size_t l_lasts_size = 0;
                                l_lasts = l_chain->callback_atom_iter_get_lasts(l_iter, &l_lasts_size);
                                if ( l_lasts){
                                    for(size_t i = 0; i < l_lasts_size; i++) {
                                        dap_chain_atom_item_t * l_item = NULL;
                                        dap_chain_hash_fast_t l_atom_hash;
                                        dap_hash_fast(l_lasts[i], l_chain->callback_atom_get_size(l_lasts[i]), &l_atom_hash);
                                        pthread_mutex_lock(&a_ch_chain->mutex);
                                        HASH_FIND(hh, a_ch_chain->request_atoms_lasts, &l_atom_hash, sizeof(l_atom_hash), l_item);
                                        if(l_item == NULL) { // Not found, add new lasts
                                            l_item = DAP_NEW_Z(dap_chain_atom_item_t);
                                            l_item->atom = l_lasts[i];
                                            memcpy(&l_item->atom_hash, &l_atom_hash, sizeof(l_atom_hash));
                                            HASH_ADD(hh, a_ch_chain->request_atoms_lasts, atom_hash, sizeof(l_atom_hash), l_item);
                                        }
                                        //else
                                        //    DAP_DELETE(l_lasts[i]);
                                        pthread_mutex_unlock(&a_ch_chain->mutex);
                                    }
                                    DAP_DELETE(l_lasts);
                                }
                                DAP_DELETE(l_iter);
                            }else{
                                log_it(L_ERROR, "Can't create iterator for chain_id 0x%016X", a_pkt->hdr.chain_id );
                            }
                        }else {
                            log_it(L_WARNING, "Can't find chain_id 0x%016X", a_pkt->hdr.chain_id );
                        }
                    }
                    dap_chain_node_addr_t l_node_addr = { 0 };
                    dap_chain_net_t *l_net = dap_chain_net_by_id(a_ch_chain->request_net_id);
                    l_node_addr.uint64 = l_net ? dap_db_get_cur_node_addr(l_net->pub.name) : 0;
                    dap_stream_ch_chain_pkt_write(a_ch_chain->ch, l_type,
                            a_ch_chain->request_net_id, a_ch_chain->request_chain_id,
                            a_ch_chain->request_cell_id, &l_node_addr, sizeof(dap_chain_node_addr_t));

                    log_it(L_INFO, "Sync for remote tr type=%d", a_pkt_type);//_count=%d", dap_list_length(l_list));
                    dap_stream_ch_set_ready_to_write(a_ch_chain->ch, true);
                }
                else {
                    log_it(L_INFO, "Remote node has lastes timestamp for us type=%d", a_pkt_type);
                    pthread_mutex_lock(&l_node_client->wait_mutex);
                    l_node_client->state = NODE_CLIENT_STATE_SYNCED;
                    pthread_mutex_unlock(&l_node_client->wait_mutex);
#ifndef _WIN32
                    pthread_cond_signal(&l_node_client->wait_cond);
#else
                    SetEvent( l_node_client->wait_cond );
#endif

                }
            }
        } else {
            log_it(L_INFO, "Sync notify without request to sync back, stay in SYNCED state");
            pthread_mutex_lock(&l_node_client->wait_mutex);
            l_node_client->state = NODE_CLIENT_STATE_SYNCED;
            pthread_mutex_unlock(&l_node_client->wait_mutex);
#ifndef _WIN32
            pthread_cond_signal(&l_node_client->wait_cond);
#else
                SetEvent( l_node_client->wait_cond );
#endif
        }

    }
    default: {
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
    switch (a_pkt_type) {
    case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB:
        case DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS: {
        pthread_mutex_lock(&l_node_client->wait_mutex);
        l_node_client->state = NODE_CLIENT_STATE_SYNCED;
        pthread_mutex_unlock(&l_node_client->wait_mutex);
#ifndef _WIN32
        pthread_cond_signal(&l_node_client->wait_cond);
#else
            SetEvent( l_node_client->wait_cond );
#endif
    }
        break;
    default: {
    }
    }
}

/**
 * Create connection to server
 *
 * return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_client_connect(dap_chain_node_info_t *a_node_info, dap_client_stage_t a_stage_target,
        const char *a_active_channels)
{
    if(!a_node_info) {
        log_it(L_ERROR, "Can't connect to the node: null object node_info");
        return NULL;
    }
    dap_chain_node_client_t *l_node_client = DAP_NEW_Z(dap_chain_node_client_t);
    l_node_client->state = NODE_CLIENT_STATE_DISCONNECTED;

#ifndef _WIN32
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    pthread_cond_init(&l_node_client->wait_cond, &attr);
#else
    l_node_client->wait_cond = CreateEventA( NULL, FALSE, FALSE, NULL );
#endif

    pthread_mutex_init(&l_node_client->wait_mutex, NULL);
    l_node_client->events = NULL; //dap_events_new();
    l_node_client->client = dap_client_new(l_node_client->events, s_stage_status_callback,
            s_stage_status_error_callback);
    l_node_client->client->_inheritor = l_node_client;
    l_node_client->remote_node_addr.uint64 = a_node_info->hdr.address.uint64;
    dap_client_set_active_channels(l_node_client->client, a_active_channels);

    int hostlen = 128;
    char host[hostlen];
    if(a_node_info->hdr.ext_addr_v4.s_addr)
    {
        struct sockaddr_in sa4 = { .sin_family = AF_INET, .sin_addr = a_node_info->hdr.ext_addr_v4 };
        inet_ntop(AF_INET, &(((struct sockaddr_in *) &sa4)->sin_addr), host, hostlen);
    }
    else
    {
        struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6, .sin6_addr = a_node_info->hdr.ext_addr_v6 };
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &sa6)->sin6_addr), host, hostlen);
    }
    // address not defined
    if(!strcmp(host, "::")) {
        dap_chain_node_client_close(l_node_client);
        return NULL;
    }
    dap_client_set_uplink(l_node_client->client, strdup(host), a_node_info->hdr.ext_port);
//    dap_client_stage_t a_stage_target = STAGE_ENC_INIT;
//    dap_client_stage_t l_stage_target = STAGE_STREAM_STREAMING;

    l_node_client->state = NODE_CLIENT_STATE_CONNECT;
    // ref pvt client
    //dap_client_pvt_ref(DAP_CLIENT_PVT(l_node_client->client));
    // Handshake & connect
    dap_client_go_stage(l_node_client->client, a_stage_target, s_stage_connected_callback);
    return l_node_client;
}

/**
 * Create connection to server
 *
 * return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_node_client_connect(dap_chain_node_info_t *a_node_info)
{
    dap_client_stage_t l_stage_target = STAGE_STREAM_STREAMING;
    const char *l_active_channels = "CN";
    return dap_chain_client_connect(a_node_info, l_stage_target, l_active_channels);
}

/**
 * Close connection to server, delete chain_node_client_t *client
 */
void dap_chain_node_client_close(dap_chain_node_client_t *a_client)
{
    if (a_client && a_client->client) { // block tryes to close twice
        // clean client
        dap_client_delete(a_client->client);
#ifndef _WIN32
        pthread_cond_destroy(&a_client->wait_cond);
#else
        CloseHandle( a_client->wait_cond );
#endif
        pthread_mutex_destroy(&a_client->wait_mutex);
        a_client->client = NULL;
        DAP_DELETE(a_client);
    }
}

/**
 * Send stream request to server
 */
int dap_chain_node_client_send_ch_pkt(dap_chain_node_client_t *a_client, uint8_t a_ch_id, uint8_t a_type,
        const void *a_pkt_data, size_t a_pkt_data_size)
{
    if(!a_client || a_client->state < NODE_CLIENT_STATE_CONNECTED)
        return -1;

//    dap_stream_t *l_stream = dap_client_get_stream(a_client->client);
    dap_stream_ch_t * l_ch = dap_client_get_stream_ch(a_client->client, a_ch_id);
    if(l_ch) {
//        dap_stream_ch_chain_net_t * l_ch_chain = DAP_STREAM_CH_CHAIN_NET(l_ch);

        dap_stream_ch_pkt_write(l_ch, a_type, a_pkt_data, a_pkt_data_size);
        dap_stream_ch_set_ready_to_write(l_ch, true);
        return 0;
    } else
        return -1;
}

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample NODE_CLIENT_STATE_CONNECT or NODE_CLIENT_STATE_SENDED
 * return -2 false, -1 timeout, 0 end of connection or sending data
 */
int dap_chain_node_client_wait(dap_chain_node_client_t *a_client, int a_waited_state, int a_timeout_ms)
{
    int ret = -1;
    if(!a_client)
        return -3;

    pthread_mutex_lock(&a_client->wait_mutex);
    // have waited
    if(a_client->state == a_waited_state) {
        pthread_mutex_unlock(&a_client->wait_mutex);
        return 0;
    }
    if(a_client->state == NODE_CLIENT_STATE_DISCONNECTED) {
        pthread_mutex_unlock(&a_client->wait_mutex);
        return -2;
    }

#ifndef _WIN32
    // prepare for signal waiting
    struct timespec to;
    clock_gettime( CLOCK_MONOTONIC, &to);
    int64_t nsec_new = to.tv_nsec + a_timeout_ms * 1000000ll;
    // if the new number of nanoseconds is more than a second

    if(nsec_new > (long) 1e9) {
        to.tv_sec += nsec_new / (long) 1e9;
        to.tv_nsec = nsec_new % (long) 1e9;
    }
    else
        to.tv_nsec = (long) nsec_new;
#else
    pthread_mutex_unlock( &a_client->wait_mutex );
#endif

    // signal waiting
    do {

#ifndef _WIN32
        int wait = pthread_cond_timedwait(&a_client->wait_cond, &a_client->wait_mutex, &to);
        if(wait == 0 && (
                a_client->state == a_waited_state ||
                        (a_client->state == NODE_CLIENT_STATE_ERROR || a_client->state == NODE_CLIENT_STATE_DISCONNECTED))
                ) {
            ret = a_client->state == a_waited_state ? 0 : -2;
            break;
        }
        else if(wait == ETIMEDOUT) { // 110 260
            ret = -1;
            break;
        }
#else
        int wait = WaitForSingleObject( a_client->wait_cond, (uint32_t)a_timeout_ms );
        pthread_mutex_lock( &a_client->wait_mutex );

        if ( wait == WAIT_OBJECT_0 && (
                    a_client->state == a_waited_state ||
                    a_client->state == NODE_CLIENT_STATE_ERROR || a_client->state == NODE_CLIENT_STATE_DISCONNECTED
          )) {
            ret = a_client->state == a_waited_state ? 0 : -2;
            break;
        }

        else if ( wait == WAIT_TIMEOUT || wait == WAIT_FAILED ) {
            ret = -1;
            break;
        }
#endif

    } while(1);

    pthread_mutex_unlock(&a_client->wait_mutex);
    return ret;
}

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
            l_ch = dap_client_get_stream_ch(a_client, a_ch_id);
        if(l_ch) {
            if(a_ch_id == dap_stream_ch_chain_get_id()) {
                dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(l_ch);
                l_ch_chain->callback_notify_packet_out = s_ch_chain_callback_notify_packet_out;
                l_ch_chain->callback_notify_packet_in = s_ch_chain_callback_notify_packet_in;
                l_ch_chain->callback_notify_arg = l_node_client;
            }
            if(a_ch_id == dap_stream_ch_chain_net_get_id()) {
                dap_stream_ch_chain_net_t *l_ch_chain = DAP_STREAM_CH_CHAIN_NET(l_ch);
                l_ch_chain->notify_callback = s_ch_chain_callback_notify_packet_in2;
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
 * Send nodelist request to server
 */
int dap_chain_node_client_send_nodelist_req(dap_chain_node_client_t *a_client)
{
    if(!a_client || !a_client->client || a_client->state < NODE_CLIENT_STATE_CONNECTED)
        return -1;
    //dap_client_pvt_t * l_client_pvt = DAP_CLIENT_PVT(a_client->client);

    //TODO send request to get nodelist
    //dap_client_request_enc(a_client->client, DAP_UPLINK_PATH_NODE_LIST, "", "", "", 0,
    //        nodelist_response_callback, nodelist_response_error_callback);
    return 1;
}
