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
#include "dap_global_db.h"
#include "dap_global_db_remote.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"

#include "dap_chain_net_srv_stake_pos_delegate.h"

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
        // Clang bug at this, l_sdata should change at every loop cycle
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



dap_chain_node_addr_t dap_stream_ch_chain_net_from_session_data_extract_node_addr(unsigned int a_session_id) {
    dap_chain_node_addr_t l_addr= {0};
    dap_chain_net_session_data_t *l_sdata, *l_sdata_tmp;
    pthread_mutex_lock(&s_hash_mutex);
    HASH_ITER(hh, s_chain_net_data , l_sdata, l_sdata_tmp) {
        if (l_sdata->session_id == a_session_id) {
            l_addr = l_sdata->addr_remote;
        }
    }
    pthread_mutex_unlock(&s_hash_mutex);
    return l_addr;
}

/**
 * @brief dap_stream_ch_chain_net_init
 * @return always 0
 */
int dap_stream_ch_chain_net_init()
{
    log_it(L_NOTICE, "Chain network channel initialized");
    dap_stream_ch_proc_add(DAP_STREAM_CH_ID_NET, s_stream_ch_new, s_stream_ch_delete,
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
        if (!l_sdata) {
            log_it(L_ERROR, "Memory allocation error in %s, line %d", __PRETTY_FUNCTION__, __LINE__);
            pthread_mutex_unlock(&s_hash_mutex);
            return;
        }
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
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    if(l_ch_chain_net) {
        pthread_mutex_lock(&l_ch_chain_net->mutex);
        session_data_del(a_ch->stream->session->id);
        pthread_mutex_unlock(&l_ch_chain_net->mutex);
    }
    DAP_DEL_Z(a_ch->internal);
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
        dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *)a_arg;
        if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_TEST) {
            char *l_data_hash_str;
            dap_get_data_hash_str_static(l_ch_pkt->data, l_ch_pkt->hdr.data_size, l_data_hash_str);
            log_it(L_ATT, "Receive test data packet with hash %s", l_data_hash_str);
            pthread_mutex_unlock(&l_ch_chain_net->mutex);
            return;
        }
        dap_stream_ch_chain_net_pkt_t *l_ch_chain_net_pkt = (dap_stream_ch_chain_net_pkt_t *) l_ch_pkt->data;
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain_net_pkt->hdr.net_id);
        bool l_error = false;
        char l_err_str[64];
        if (!l_net) {
            log_it(L_ERROR, "Invalid net id in packet");
            strcpy(l_err_str, "ERROR_NET_INVALID_ID");
            l_error = true;
        }
        if (!l_error) {
            uint16_t l_acl_idx = dap_chain_net_get_acl_idx(l_net);
            uint8_t l_acl = a_ch->stream->session->acl ? a_ch->stream->session->acl[l_acl_idx] : 1;
            if (!l_acl) {
                log_it(L_WARNING, "Unauthorized request attempt to network %s",
                       dap_chain_net_by_id(l_ch_chain_net_pkt->hdr.net_id)->pub.name);
                strcpy(l_err_str, "ERROR_NET_NOT_AUTHORIZED");
                l_error = true;
            }
        } else {

            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                              l_ch_chain_net_pkt->hdr.net_id, l_err_str, strlen(l_err_str) + 1);
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
        }
        if (!l_error && l_ch_chain_net_pkt) {
            size_t l_ch_chain_net_pkt_data_size = l_ch_pkt->hdr.data_size - sizeof(dap_stream_ch_chain_net_pkt_hdr_t);
            switch (l_ch_pkt->hdr.type) {
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
                        log_it(L_NOTICE,"Accepted remote node addr 0x%016"DAP_UINT64_FORMAT_X, l_addr->uint64);
                    }else {
                        log_it(L_WARNING,"Wrong data secion size %zu",l_ch_chain_net_pkt_data_size);
                    }
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
                }break;
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE: {
                    log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE");
                    if ( l_ch_chain_net_pkt_data_size == sizeof (dap_chain_node_addr_t) ) {
                        dap_chain_node_addr_t * l_addr = (dap_chain_node_addr_t *) l_ch_chain_net_pkt->data;
                        log_it(L_NOTICE,"Leased new node addr 0x%016"DAP_UINT64_FORMAT_X,l_addr->uint64);
                        dap_chain_net_t * l_net = dap_chain_net_by_id( l_ch_chain_net_pkt->hdr.net_id );
                        if ( l_net == NULL){
                            char l_err_str[]="ERROR_NET_INVALID_ID";
                            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                                              l_ch_chain_net_pkt->hdr.net_id, l_err_str,sizeof (l_err_str));
                            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                            log_it(L_ERROR, "Invalid net id in packet");
                        } else {
                            if (dap_db_set_cur_node_addr_exp( l_addr->uint64, l_net->pub.name ))
                                log_it(L_NOTICE,"Set up cur node address 0x%016"DAP_UINT64_FORMAT_X,l_addr->uint64);
                            else
                                log_it(L_ERROR,"Can't set up cur node address 0x%016"DAP_UINT64_FORMAT_X,l_addr->uint64);
                        }
                        if(l_session_data)
                            memcpy( &l_session_data->addr_remote,l_addr,sizeof (*l_addr) );
                    }else {
                        log_it(L_WARNING,"Wrong data secion size %zu",l_ch_chain_net_pkt_data_size);
                    }
                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
                }break;
                // get current node address
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST: {
                    log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_REQUEST");
                    // get cur node addr
                    dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain_net_pkt->hdr.net_id);
                    uint64_t l_addr = l_net ? dap_chain_net_get_cur_node_addr_gdb_sync(l_net->pub.name) : 0;
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
                        dap_chain_node_addr_t *l_addr_new = dap_chain_node_gen_addr(l_net->pub.id);
                        dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_ADDR_LEASE ,
                                                         l_ch_chain_net_pkt->hdr.net_id, l_addr_new, sizeof (*l_addr_new));
                        dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                        if(l_session_data)
                            memcpy( &l_session_data->addr_remote,l_addr_new,sizeof (*l_addr_new) );
                        DAP_DELETE(l_addr_new);
                    }
                } break;
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST:{
                    log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST");
                    dap_chain_net_t * l_net = dap_chain_net_by_id( l_ch_chain_net_pkt->hdr.net_id );
                    if ( l_net == NULL){
                        char l_err_str[]="ERROR_NET_INVALID_ID";
                        dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                                          l_ch_chain_net_pkt->hdr.net_id, l_err_str,sizeof (l_err_str));
                        dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                        log_it(L_ERROR, "Invalid net id in packet");
                    } else {
                        dap_chain_net_srv_order_t * l_orders = NULL;
                        dap_enc_key_t * enc_key_pvt = NULL;
                        dap_chain_t *l_chain = NULL;
                        DL_FOREACH(l_net->pub.chains, l_chain)
                            if(l_chain->callback_get_signing_certificate != NULL){
                                enc_key_pvt = l_chain->callback_get_signing_certificate(l_chain);
                                if(enc_key_pvt)
                                    break;
                            }
                        dap_sign_t *l_sign = NULL;
                        size_t sign_s = 0;
                        size_t l_orders_num = 0;
                        dap_stream_ch_chain_validator_test_t *send = NULL;
                        dap_chain_net_srv_price_unit_uid_t l_price_unit = { { 0 } };
                        dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
                        uint256_t l_price_min = {};
                        uint256_t l_price_max = {};
                        uint8_t flags = 0;

                        if(enc_key_pvt)
                        {
                            flags = flags | F_CERT;//faund sert
                            l_sign = dap_sign_create(enc_key_pvt, (uint8_t*)l_ch_chain_net_pkt->data,
                                                   l_ch_chain_net_pkt_data_size, 0);
                            if(l_sign)
                            {
                                sign_s = dap_sign_get_size(l_sign);
                                flags = flags | D_SIGN;//data signed
                            }
                            else
                                flags = flags & ~D_SIGN;//data doesn't sign
                        }
                        else
                            flags = flags & ~F_CERT;//Specified certificate not found

                        send = DAP_NEW_Z_SIZE(dap_stream_ch_chain_validator_test_t, sizeof(dap_stream_ch_chain_validator_test_t) + sign_s);
#ifdef DAP_VERSION
                        strncpy((char *)send->header.version, (char *)DAP_VERSION, sizeof(send->header.version));
#endif
                        send->header.sign_size = sign_s;
                        //strncpy(send->header.data,(uint8_t*)l_ch_chain_net_pkt->data,10);
                        flags = (l_net->pub.mempool_autoproc) ? flags | A_PROC : flags & ~A_PROC;

                        dap_chain_net_srv_order_find_all_by(l_net,SERV_DIR_UNDEFINED,l_uid,
                                                           l_price_unit,NULL,l_price_min,l_price_max,&l_orders,&l_orders_num);
                        flags = l_orders_num ? flags | F_ORDR : flags & ~F_ORDR;
                        bool auto_online = dap_config_get_item_bool_default( g_config, "general", "auto_online", false );
                        bool auto_update = dap_config_get_item_bool_default( g_config, "general", "auto_update", false );
                        flags = auto_online ? flags | A_ONLN : flags & ~A_ONLN;
                        flags = auto_update ? flags | A_UPDT : flags & ~A_UPDT;
                        send->header.flags = flags;
                        //add sign
                        if(sign_s)
                            memcpy(send->sign,l_sign,sign_s);
                        dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY ,
                                                         l_ch_chain_net_pkt->hdr.net_id, send, sizeof(dap_stream_ch_chain_validator_test_t) + sign_s);
                        dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                        if(l_sign)
                            DAP_DELETE(l_sign);
                        DAP_DELETE(send);
                    }
                }break;
                case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY:{
                    log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY");

                    dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
                }break;
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
