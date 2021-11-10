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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_cert.h"
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

typedef struct dap_chain_net_session_data {
    unsigned int session_id;

    dap_chain_node_addr_t addr_remote;

    UT_hash_handle hh;
} dap_chain_net_session_data_t;

// list of active sessions
static dap_chain_net_session_data_t *s_chain_net_data = NULL;
// for separate access to session_data_t
static pthread_mutex_t s_hash_mutex = PTHREAD_MUTEX_INITIALIZER;


static dap_chain_net_session_data_t* session_data_find(unsigned int a_id)
{
    dap_chain_net_session_data_t *l_sdata;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_FIND_INT(s_chain_net_data, &a_id, l_sdata);
    pthread_mutex_unlock(&s_hash_mutex);
    return l_sdata;
}

static void session_data_del(unsigned int a_id)
{
    dap_chain_net_session_data_t *l_sdata;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_FIND_INT(s_chain_net_data, &a_id, l_sdata);
    if(l_sdata) {
        HASH_DEL(s_chain_net_data, l_sdata);
        DAP_DELETE(l_sdata);
    }
    pthread_mutex_unlock(&s_hash_mutex);
}

static void session_data_del_all()
{
    dap_chain_net_session_data_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_ITER(hh, s_chain_net_data , l_sdata, l_sdata_tmp)
    {
        HASH_DEL(s_chain_net_data, l_sdata);
        DAP_DELETE(l_sdata);
    }
    //HASH_CLEAR(hh,s_chain_net_data);
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
    (void) a_arg;
    a_ch->internal = DAP_NEW_Z(dap_stream_ch_chain_net_t);
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    l_ch_chain_net->ch = a_ch;
    pthread_mutex_init(&l_ch_chain_net->mutex, NULL);

    // Create chain net session ever it created
    dap_chain_net_session_data_t *l_sdata;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_FIND_INT(s_chain_net_data, &a_ch->stream->session->id, l_sdata);
    if(l_sdata == NULL) {
        l_sdata = DAP_NEW_Z(dap_chain_net_session_data_t);
        l_sdata->session_id = a_ch->stream->session->id;
        HASH_ADD_INT(s_chain_net_data, session_id, l_sdata);
    }
    pthread_mutex_unlock(&s_hash_mutex);
}

/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;
    //printf("* del session=%d\n", a_ch->stream->session->id);
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    if(l_ch_chain_net) {
        pthread_mutex_lock(&l_ch_chain_net->mutex);
        session_data_del(a_ch->stream->session->id);
        pthread_mutex_unlock(&l_ch_chain_net->mutex);
    }
}

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    dap_chain_net_session_data_t *l_session_data = session_data_find(a_ch->stream->session->id);
    if (l_session_data == NULL) {
        log_it(L_ERROR, "Can't find chain net session for stream session %d", a_ch->stream->session->id);
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        return;
    }

    if(l_ch_chain_net) {
        pthread_mutex_lock(&l_ch_chain_net->mutex);
        dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
        dap_stream_ch_chain_net_pkt_t *l_ch_chain_net_pkt = (dap_stream_ch_chain_net_pkt_t *) l_ch_pkt->data;
        uint16_t l_acl_idx = dap_chain_net_acl_idx_by_id(l_ch_chain_net_pkt->hdr.net_id);
        bool l_error = false;
        char l_err_str[64];
        if (l_acl_idx == (uint16_t)-1) {
            log_it(L_ERROR, "Invalid net id in packet");
            strcpy(l_err_str, "ERROR_NET_INVALID_ID");
            l_error = true;
        }
        if (!l_error && a_ch->stream->session->acl && !a_ch->stream->session->acl[l_acl_idx]) {
            log_it(L_WARNING, "Unauthorized request attempt to network %s",
                   dap_chain_net_by_id(l_ch_chain_net_pkt->hdr.net_id)->pub.name);
            strcpy(l_err_str, "ERROR_NET_NOT_AUTHORIZED");
            l_error = true;
        }
        if (l_error) {
            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                              l_ch_chain_net_pkt->hdr.net_id, l_err_str, strlen(l_err_str) + 1);
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
        }
        //size_t l_ch_chain_net_pkt_data_size = (size_t) l_ch_pkt->hdr.size - sizeof (l_ch_chain_net_pkt->hdr);
        if (!l_error && l_ch_chain_net_pkt) {
            size_t l_ch_chain_net_pkt_data_size = l_ch_pkt->hdr.size - sizeof(dap_stream_ch_chain_net_pkt_hdr_t);
            switch (l_ch_pkt->hdr.type) {
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_DBG: {
                    dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PING,
                                                      l_ch_chain_net_pkt->hdr.net_id, NULL, 0);
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                }
                    break;
                    // received ping request - > send pong request
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PING: {
                    //log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_PING");
                    dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PONG,
                                                      l_ch_chain_net_pkt->hdr.net_id,NULL, 0);
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                }
                    break;
                    // receive pong request -> send nothing
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PONG: {
                    //log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_PONG");
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
                }
                break;
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR: {
                    log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_ADDR");
                    if ( l_ch_chain_net_pkt_data_size == sizeof (dap_chain_node_addr_t) ) {
                        dap_chain_node_addr_t * l_addr = (dap_chain_node_addr_t *) l_ch_chain_net_pkt->data;
                        if(l_session_data)
                            memcpy( &l_session_data->addr_remote,l_addr,sizeof (*l_addr) );
                        log_it(L_NOTICE,"Accepted remote node addr 0x%016llX",l_addr->uint64);
                    }else {
                        log_it(L_WARNING,"Wrong data secion size %u",l_ch_chain_net_pkt_data_size,
                               sizeof (dap_chain_node_addr_t));
                    }
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
                }break;
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE: {
                    log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE");
                    if ( l_ch_chain_net_pkt_data_size == sizeof (dap_chain_node_addr_t) ) {
                        dap_chain_node_addr_t * l_addr = (dap_chain_node_addr_t *) l_ch_chain_net_pkt->data;
                        log_it(L_NOTICE,"Leased new node addr 0x%016llX",l_addr->uint64);
                        dap_chain_net_t * l_net = dap_chain_net_by_id( l_ch_chain_net_pkt->hdr.net_id );
                        if ( l_net == NULL){
                            char l_err_str[]="ERROR_NET_INVALID_ID";
                            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                                              l_ch_chain_net_pkt->hdr.net_id, l_err_str,sizeof (l_err_str));
                            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                            log_it(L_ERROR, "Invalid net id in packet");
                        } else {
                            if (dap_db_set_cur_node_addr_exp( l_addr->uint64, l_net->pub.name ))
                                log_it(L_NOTICE,"Set up cur node address 0x%016llX",l_addr->uint64);
                            else
                                log_it(L_ERROR,"Can't set up cur node address 0x%016llX",l_addr->uint64);
                        }
                        if(l_session_data)
                            memcpy( &l_session_data->addr_remote,l_addr,sizeof (*l_addr) );
                    }else {
                        log_it(L_WARNING,"Wrong data secion size %u",l_ch_chain_net_pkt_data_size,
                               sizeof (dap_chain_node_addr_t));
                    }
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
                }break;
                // get current node address
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST: {
                    log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST");
                    // get cur node addr
                    dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain_net_pkt->hdr.net_id);
                    uint64_t l_addr = l_net ? dap_db_get_cur_node_addr(l_net->pub.name) : 0;
                    size_t l_send_data_len = sizeof(uint64_t);
                    // send cur node addr
                    dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR,
                                                      l_ch_chain_net_pkt->hdr.net_id, &l_addr, l_send_data_len);
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                } break;
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE_REQUEST: {
                    log_it(L_INFO, "Get STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST");
                    // gen node addr
                    dap_chain_net_t * l_net = dap_chain_net_by_id( l_ch_chain_net_pkt->hdr.net_id );
                    if ( l_net == NULL){
                        char l_err_str[]="ERROR_NET_INVALID_ID";
                        dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR , l_ch_chain_net_pkt->hdr.net_id,
                                                          l_err_str,sizeof (l_err_str));
                        dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                    } else {
                        dap_chain_node_addr_t *l_addr_new = dap_chain_node_gen_addr(l_net, &l_net->pub.cell_id );
                        dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE ,
                                                         l_ch_chain_net_pkt->hdr.net_id, l_addr_new, sizeof (*l_addr_new));
                        dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                        if(l_session_data)
                            memcpy( &l_session_data->addr_remote,l_addr_new,sizeof (*l_addr_new) );
                        DAP_DELETE(l_addr_new);
                    }
                }
                break;
            }
            if(l_ch_chain_net->notify_callback)
                l_ch_chain_net->notify_callback(l_ch_chain_net,l_ch_pkt->hdr.type, l_ch_chain_net_pkt,
                                                l_ch_chain_net_pkt_data_size, l_ch_chain_net->notify_callback_arg);

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
}
