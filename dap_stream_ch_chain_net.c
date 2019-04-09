/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

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

#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "uthash.h"
#include "dap_http_client.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"

#define LOG_TAG "dap_stream_ch_chain_net"

static void s_stream_ch_new(dap_stream_ch_t* ch, void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch, void* arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* ch, void* arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* ch, void* arg);

typedef struct session_data {
    unsigned int id;
    //int sock;
    int message_id;
    uint16_t type; // data type
    time_t timestamp_start;
    time_t timestamp_cur;
    dap_list_t *list_tr; // list of transactions
    dap_chain_node_addr_t node_remote;
    dap_chain_node_addr_t node_cur;

    UT_hash_handle hh;
} session_data_t;

typedef struct message_data {
    time_t timestamp_start;
    uint64_t addr_from; // node addr
    uint64_t addr_to; // node addr
} message_data_t;

// list of active sessions
static session_data_t *s_chain_net_data = NULL;
// for separate access to session_data_t
static pthread_mutex_t s_hash_mutex = PTHREAD_MUTEX_INITIALIZER;

// create packet to send
uint8_t* dap_stream_ch_chain_net_make_packet(uint64_t a_node_addr_from, uint64_t a_node_addr_to,
        time_t a_timestamp_start, uint8_t *a_sdata, size_t a_sdata_len, size_t *a_data_len_out)
{
    //message_data_t *l_data = DAP_NEW_Z(message_data_t);
    message_data_t *l_data = DAP_NEW_Z_SIZE(message_data_t, sizeof(message_data_t) + a_sdata_len);
    l_data->timestamp_start = a_timestamp_start;
    l_data->addr_from = a_node_addr_from;
    l_data->addr_to = a_node_addr_to;
    // copy add data
    memcpy(l_data + 1, a_sdata, a_sdata_len);
    *a_data_len_out = sizeof(message_data_t) + a_sdata_len;
    return (uint8_t*) l_data;
}

// parse received packet
static const message_data_t *dap_stream_ch_chain_net_parse_packet(uint8_t* a_data, size_t a_data_len,
        const uint8_t **a_add_data_out, size_t *a_add_data_len_out)
{
    if(a_data_len < sizeof(message_data_t))
        return NULL;
    message_data_t *l_data = (message_data_t*) a_data;
    if(a_add_data_out)
        *a_add_data_out = (uint8_t*) (l_data + 1);
    if(a_add_data_len_out)
        *a_add_data_len_out = a_data_len - sizeof(message_data_t);
    return l_data;
}

static void session_data_update(unsigned int a_id, int a_messsage_id, dap_list_t *a_list, message_data_t *a_data,
        time_t a_timestamp_cur)
{
    session_data_t *l_sdata;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_FIND_INT(s_chain_net_data, &a_id, l_sdata);
    if(l_sdata == NULL) {
        l_sdata = DAP_NEW_Z(session_data_t);
        l_sdata->id = a_id;
        HASH_ADD_INT(s_chain_net_data, id, l_sdata);
    }
    if(a_messsage_id != -1)
        l_sdata->message_id = a_messsage_id;

    l_sdata->list_tr = a_list;

    if(a_data) {
        l_sdata->timestamp_start = a_data->timestamp_start;
        l_sdata->node_remote.uint64 = a_data->addr_from;
        l_sdata->node_cur.uint64 = a_data->addr_to;
    }
    if(a_timestamp_cur != (time_t) -1) {
        l_sdata->timestamp_cur = a_timestamp_cur;
    }

    pthread_mutex_unlock(&s_hash_mutex);
}

static session_data_t* session_data_find(unsigned int a_id)
{
    session_data_t *l_sdata;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_FIND_INT(s_chain_net_data, &a_id, l_sdata);
    pthread_mutex_unlock(&s_hash_mutex);
    return l_sdata;
}

static void session_data_del(unsigned int a_id)
{
    session_data_t *l_sdata;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_FIND_INT(s_chain_net_data, &a_id, l_sdata);
    if(l_sdata) {
        DAP_DELETE(l_sdata);
        HASH_DEL(s_chain_net_data, l_sdata);
    }
    pthread_mutex_unlock(&s_hash_mutex);
}

static void session_data_del_all()
{
    session_data_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_ITER(hh, s_chain_net_data , l_sdata, l_sdata_tmp)
    {
        DAP_DELETE(l_sdata);
        HASH_DEL(s_chain_net_data, l_sdata);
    }
    pthread_mutex_unlock(&s_hash_mutex);
}

uint8_t dap_stream_ch_chain_net_get_id()
{
    return 'N';
}

/**
 * @brief dap_stream_ch_chain_net_init
 * @return
 */
int dap_stream_ch_chain_net_init()
{
    log_it(L_NOTICE, "Chain network channel initialized");
    dap_stream_ch_proc_add(dap_stream_ch_chain_net_get_id(), s_stream_ch_new, s_stream_ch_delete,
            s_stream_ch_packet_in, s_stream_ch_packet_out);

    return 0;
}

/**
 * @brief dap_stream_ch_chain_deinit
 */
void dap_stream_ch_chain_net_deinit()
{
    //printf("* del all sessions\n");
    session_data_del_all();
}

/**
 * @brief s_stream_ch_new
 * @param a_ch
 * @param arg
 */
void s_stream_ch_new(dap_stream_ch_t* a_ch, void* a_arg)
{
    a_ch->internal = DAP_NEW_Z(dap_stream_ch_chain_net_t);
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    l_ch_chain_net->ch = a_ch;
    pthread_mutex_init(&l_ch_chain_net->mutex, NULL);
}

/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg)
{
    //printf("* del session=%d\n", a_ch->stream->session->id);
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    pthread_mutex_lock(&l_ch_chain_net->mutex);
    session_data_del(a_ch->stream->session->id);
    pthread_mutex_unlock(&l_ch_chain_net->mutex);
}

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    if(l_ch_chain_net) {
        pthread_mutex_lock(&l_ch_chain_net->mutex);
        dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
        dap_stream_ch_chain_net_pkt_t *l_chain_pkt = (dap_stream_ch_chain_net_pkt_t *) l_ch_pkt->data;
        if(l_chain_pkt) {

            size_t l_ch_pkt_data_size = l_ch_pkt->hdr.size - sizeof(dap_stream_ch_chain_net_pkt_hdr_t);
            //printf("*packet TYPE=%d data_size=%d\n", l_chain_pkt->hdr.type, l_ch_pkt_data_size);
            //(data_size > 0) ? (char*) (l_chain_pkt->data) : "-");

            switch (l_chain_pkt->hdr.type) {
            case STREAM_CH_CHAIN_NET_PKT_TYPE_DBG: {
                dap_stream_ch_chain_net_pkt_write(a_ch, STREAM_CH_CHAIN_NET_PKT_TYPE_PING, NULL, 0);
                dap_stream_ch_set_ready_to_write(a_ch, true);
            }
                break;
                // received ping request - > send pong request
            case STREAM_CH_CHAIN_NET_PKT_TYPE_PING: {
                log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_PING");
                int l_res = dap_stream_ch_chain_net_pkt_write(a_ch, STREAM_CH_CHAIN_NET_PKT_TYPE_PONG, NULL, 0);
                dap_stream_ch_set_ready_to_write(a_ch, true);
            }
                break;
                // receive pong request -> send nothing
            case STREAM_CH_CHAIN_NET_PKT_TYPE_PONG: {
                log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_PONG");
                dap_stream_ch_set_ready_to_write(a_ch, false);
            }
                break;
                // get node address
            case STREAM_CH_CHAIN_NET_PKT_TYPE_GET_NODE_ADDR: {
                log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_GET_NODE_ADDR");
                dap_stream_ch_set_ready_to_write(a_ch, false);
            }
                break;
                // set new node address
            case STREAM_CH_CHAIN_NET_PKT_TYPE_SET_NODE_ADDR: {
                log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_SET_NODE_ADDR");
                {
                    uint64_t l_addr = 0;
                    // set cur node addr
                    if(l_ch_pkt_data_size == sizeof(uint64_t)) {
                        memcpy(&l_addr, l_chain_pkt->data, sizeof(uint64_t));
                        dap_db_set_cur_node_addr(l_addr);
                    }
                }
                session_data_update(a_ch->stream->session->id, STREAM_CH_CHAIN_NET_PKT_TYPE_SET_NODE_ADDR,
                NULL, NULL, -1);
                dap_stream_ch_set_ready_to_write(a_ch, true);
            }
                break;
            case STREAM_CH_CHAIN_NET_PKT_TYPE_GLOVAL_DB: {
                log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_GLOVAL_DB data_size=%d", l_ch_pkt_data_size);
                // get transaction and save it to global_db
                if(l_ch_pkt_data_size > 0) {

                    // parse received packet
                    size_t l_data_size = 0;
                    const uint8_t *l_data = NULL;
                    const message_data_t *l_mdata = dap_stream_ch_chain_net_parse_packet(l_chain_pkt->data,
                            l_ch_pkt_data_size,
                            &l_data, &l_data_size);

                    /*dap_chain_node_addr_t l_node_cur;
                     dap_chain_node_addr_t l_node_remote;
                     uint8_t *l_recv_data = l_chain_pkt->data; //DAP_NEW_SIZE(uint8_t, l_item_size_out + 2 * sizeof(dap_chain_node_addr_t));
                     memcpy(&l_node_remote, l_recv_data, sizeof(dap_chain_node_addr_t));
                     memcpy(&l_node_cur, l_recv_data + sizeof(dap_chain_node_addr_t), sizeof(dap_chain_node_addr_t));
                     uint8_t *l_mdata = l_recv_data + 2 * sizeof(dap_chain_node_addr_t);
                     l_ch_pkt_data_size -= 2 * sizeof(dap_chain_node_addr_t);*/

                    if(l_data && l_data_size > 0) {
                        //session_data_t *l_data = session_data_find(a_ch->stream->session->id);
                        int l_data_obj_count = 0;

                        // deserialize data
                        void *l_data_obj = dap_db_log_unpack((uint8_t*) l_data, l_data_size, &l_data_obj_count); // Parse data from dap_db_log_pack()
                        // save data to global_db
                        if(!dap_chain_global_db_obj_save(l_data_obj, l_data_obj_count)) {
                            log_it(L_ERROR, "Don't saved to global_db objs=0x%x count=%d", l_data_obj,
                                    l_data_obj_count);
                        }
                        else {
                            // Get remote timestamp
                            time_t l_timestamp_remote = dap_db_log_unpack_get_timestamp((uint8_t*) l_data, l_data_size);
                            // set new timestamp (saved data) for remote node
                            dap_db_log_set_last_timestamp_remote(l_mdata->addr_from, l_timestamp_remote);
                            //printf("***ts=%llu\n", l_timestamp_remote);
                        }
                    }
                    dap_stream_ch_set_ready_to_write(a_ch, false);

                }

                /*// go to data transfer mode
                 else if(!data_size) {

                 dap_stream_ch_set_ready_to_write(a_ch, false);
                 // Get log diff
                 //dap_list_t *l_list = dap_db_log_get_list(a_data->timestamp_start);
                 //session_data_update(a_ch->stream->session->id, l_list, a_data, 0);

                 }*/
            }
                break;
                // receive the latest global_db revision of the remote node -> go to send mode
            case STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC: {

                if(l_ch_pkt_data_size == sizeof(message_data_t)) {

                    // parse received packet
                    const message_data_t *l_data = dap_stream_ch_chain_net_parse_packet(l_chain_pkt->data,
                            l_ch_pkt_data_size,
                            NULL, NULL);
                    if(l_data) {
                        //message_data_t *l_data = (message_data_t*) l_chain_pkt->data;

                        //time_t l_timestamp_remote_get = l_data->timestamp_start;
                        //time_t l_timestamp_remote_cur = dap_db_log_get_last_timestamp_remote(l_data->addr_from);

                        // last timestamp for remote node
                        time_t l_timestamp_remote_saved = l_data->timestamp_start; //min(l_timestamp_remote_get, l_timestamp_remote_cur);

                        // Get log diff
                        dap_list_t *l_list = dap_db_log_get_list(l_timestamp_remote_saved);
                        session_data_update(a_ch->stream->session->id,
                        STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC,
                                l_list, (message_data_t*) l_data, -1);

                        log_it(L_INFO,
                                "Get STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC session_id=%u from 0x%llx to 0x%llx count=%d",
                                a_ch->stream->session->id, l_data->addr_from, l_data->addr_to, dap_list_length(l_list));
                    }
                    // go to send data from list [in s_stream_ch_packet_out()]
                    // no data to send -> send one empty message STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC
                    dap_stream_ch_set_ready_to_write(a_ch, true);
                }
                else {
                    log_it(L_ERROR, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC session_id=%u bad request",
                            a_ch->stream->session->id);
                    dap_stream_ch_set_ready_to_write(a_ch, false);
                }
            }
                break;
            }
            if(l_ch_chain_net->notify_callback) {
                if(l_chain_pkt->hdr.type == STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC) {
                    session_data_t *l_data = session_data_find(a_ch->stream->session->id);
                    // end of session
                    if(!l_data->list_tr)
                        l_ch_chain_net->notify_callback(NULL, l_ch_pkt_data_size, l_ch_chain_net->notify_callback_arg);
                    else
                        l_ch_chain_net->notify_callback(l_chain_pkt, l_ch_pkt_data_size,
                                l_ch_chain_net->notify_callback_arg);
                }
                else
                    l_ch_chain_net->notify_callback(l_chain_pkt, l_ch_pkt_data_size,
                            l_ch_chain_net->notify_callback_arg);
            }
        }
        pthread_mutex_unlock(&l_ch_chain_net->mutex);
    }
}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    pthread_mutex_lock(&l_ch_chain_net->mutex);

    session_data_t *l_data = session_data_find(a_ch->stream->session->id);
    //printf("*packet out session_id=%u\n", a_ch->stream->session->id);
    if(!l_data) {
        log_it(L_WARNING, "if packet_out() l_data=NULL");
        dap_stream_ch_set_ready_to_write(a_ch, false);
        return;
    }

    if(l_data->message_id == STREAM_CH_CHAIN_NET_PKT_TYPE_SET_NODE_ADDR) {
        // get cur node addr
        uint64_t l_addr = dap_db_get_cur_node_addr();
        size_t l_send_data_len = sizeof(uint64_t);
        // send cur node addr
        dap_stream_ch_chain_net_pkt_write(a_ch, STREAM_CH_CHAIN_NET_PKT_TYPE_GET_NODE_ADDR, &l_addr, l_send_data_len);

        pthread_mutex_unlock(&l_ch_chain_net->mutex);
        dap_stream_ch_set_ready_to_write(a_ch, false);
        return;
    }

    dap_chain_node_addr_t node_cur;

    // Get log diff
    size_t l_data_size_out = 0;
    dap_list_t *l_list = l_data->list_tr;
    int len = dap_list_length(l_list);
    //printf("*len=%d\n", len);
    if(l_list) {
        int l_item_size_out = 0;
        uint8_t *l_item = NULL;
        while(l_list && !l_item) {
            l_item = dap_db_log_pack((dap_global_db_obj_t *) l_list->data, &l_item_size_out);
            if(!l_item) {
                // remove current item from list
                dap_chain_global_db_obj_delete((dap_global_db_obj_t *) l_list->data);
                l_list = dap_list_delete_link(l_list, l_list);
            }
        }

        size_t l_send_data_len = 0;
        uint8_t *l_send_data = dap_stream_ch_chain_net_make_packet(l_data->node_cur.uint64, l_data->node_remote.uint64,
                0, l_item, l_item_size_out, &l_send_data_len);

        dap_stream_ch_chain_net_pkt_write(a_ch, STREAM_CH_CHAIN_NET_PKT_TYPE_GLOVAL_DB, l_send_data, l_send_data_len);
        DAP_DELETE(l_send_data);

        // remove current item from list
        dap_chain_global_db_obj_delete((dap_global_db_obj_t *) l_list->data);

        l_list = dap_list_delete_link(l_list, l_list);

        session_data_update(a_ch->stream->session->id, -1, l_list, NULL, -1);
    }
    // last message
    if(!l_list) {
        // send request
        size_t l_data_size_out = 0;
        // Get current last timestamp in log
        //time_t l_timestamp_remote_saved = dap_db_log_get_last_timestamp();

        // get remote last timestamp (saved data) for remote node
        time_t l_timestamp_remote_saved = dap_db_log_get_last_timestamp_remote(l_data->node_remote.uint64);

        size_t l_data_send_len = 0;
        uint8_t *l_data_send = dap_stream_ch_chain_net_make_packet(l_data->node_cur.uint64, l_data->node_remote.uint64,
                l_timestamp_remote_saved, NULL, 0, &l_data_send_len);

        dap_stream_ch_chain_net_pkt_write(a_ch, STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC, l_data_send,
                l_data_send_len);
        DAP_DELETE(l_data_send);

        l_data = NULL;
    }
    int l_res = 0;

    // end of session
    if(!l_list)
        dap_stream_ch_set_ready_to_write(a_ch, false);
    else
        dap_stream_ch_set_ready_to_write(a_ch, true);

    pthread_mutex_unlock(&l_ch_chain_net->mutex);
}
