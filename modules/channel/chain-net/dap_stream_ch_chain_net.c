/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_net_srv_order.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"

#include "dap_chain_net_srv_stake_pos_delegate.h"

#define LOG_TAG "dap_stream_ch_chain_net"

static void s_stream_ch_new(dap_stream_ch_t* ch, void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch, void* arg);
static bool s_stream_ch_packet_in(dap_stream_ch_t* ch, void* arg);

/**
 * @brief dap_stream_ch_chain_net_init
 * @return always 0
 */
int dap_stream_ch_chain_net_init()
{
    log_it(L_NOTICE, "Chain network channel initialized");
    dap_stream_ch_proc_add(DAP_STREAM_CH_CHAIN_NET_ID, s_stream_ch_new, s_stream_ch_delete,
            s_stream_ch_packet_in, NULL);

    return 0;
}

/**
 * @brief dap_chain_ch_deinit
 */
void dap_stream_ch_chain_net_deinit()
{
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
}

/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* a_ch, void* a_arg)
{
    (void) a_arg;
    DAP_DEL_Z(a_ch->internal);
}

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
static bool s_stream_ch_packet_in(dap_stream_ch_t *a_ch, void* a_arg)
{
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    if(l_ch_chain_net) {
        dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *)a_arg;
        if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_TEST)
            return log_it(L_ATT, "Receive test data packet with hash %s", 
                                 dap_get_data_hash_str(l_ch_pkt->data, l_ch_pkt->hdr.data_size).s), false;
        if (l_ch_pkt->hdr.data_size < sizeof(dap_stream_ch_chain_net_pkt_t))
            return log_it(L_WARNING, "Too small stream channel N packet size %u (header size %zu)",
                                    l_ch_pkt->hdr.data_size, sizeof(dap_stream_ch_chain_net_pkt_t)), false;
        dap_stream_ch_chain_net_pkt_t *l_ch_chain_net_pkt = (dap_stream_ch_chain_net_pkt_t *)l_ch_pkt->data;
        if ((uint32_t)l_ch_chain_net_pkt->hdr.data_size + sizeof(dap_stream_ch_chain_net_pkt_t) > l_ch_pkt->hdr.data_size) {
            log_it(L_WARNING, "Too small stream channel N packet size %u (expected at least %zu)",
                                    l_ch_pkt->hdr.data_size, l_ch_chain_net_pkt->hdr.data_size + sizeof(dap_stream_ch_chain_net_pkt_t));
            return false;
        }
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ch_chain_net_pkt->hdr.net_id);
        if (!l_net) {
            log_it(L_ERROR, "Invalid net id 0x%016" DAP_UINT64_FORMAT_x " in stream channel N packet", l_ch_chain_net_pkt->hdr.net_id.uint64);
            char l_err_str[] = "ERROR_NET_INVALID_ID";
            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                              l_ch_chain_net_pkt->hdr.net_id, l_err_str, sizeof(l_err_str));
            return false;
        }
        if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR) {
            if (l_ch_chain_net_pkt->data[l_ch_chain_net_pkt->hdr.data_size - 1] != '\0') {
                log_it(L_WARNING, "Invalid error string format with no trailing zero");
                return false;
            }
            char *l_err_str = (char *)l_ch_chain_net_pkt->data;
            log_it(L_WARNING, "Stream channel N for network communication got error on other side: %s", l_err_str);
            if (a_ch->stream->authorized) {
                assert(!dap_stream_node_addr_is_blank(&a_ch->stream->node));
                dap_link_manager_accounting_link_in_net(l_net->pub.id.uint64, &a_ch->stream->node, false);
            }
            return false;
        }
        uint16_t l_acl_idx = dap_chain_net_get_acl_idx(l_net);
        uint8_t l_acl = a_ch->stream->session->acl ? a_ch->stream->session->acl[l_acl_idx] : 1;
        if (!l_acl) {
            log_it(L_WARNING, "Unauthorized request attempt to network %s",
                   dap_chain_net_by_id(l_ch_chain_net_pkt->hdr.net_id)->pub.name);
            char l_err_str[] = "ERROR_NET_NOT_AUTHORIZED";
            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                              l_ch_chain_net_pkt->hdr.net_id, l_err_str, sizeof(l_err_str));
            return false;
        }
        if (dap_chain_net_state_is_offline(l_net)) {
            char l_err_str[] = "ERROR_NET_IS_OFFLINE";
            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR,
                                              l_ch_chain_net_pkt->hdr.net_id, l_err_str, sizeof(l_err_str));
            return false;
        }
        switch (l_ch_pkt->hdr.type) {

        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE:
        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE_ACK:
            if (!a_ch->stream->authorized) {
                log_it(L_WARNING, "Trying to announce net from not authorized stream");
                char l_err_str[] = "ERROR_STREAM_NOT_AUTHORIZED";
                dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                                  l_ch_chain_net_pkt->hdr.net_id, l_err_str, sizeof(l_err_str));
                break;
            }
            assert(!dap_stream_node_addr_is_blank(&a_ch->stream->node));
            dap_link_manager_accounting_link_in_net(l_net->pub.id.uint64, &a_ch->stream->node, true);
            if (l_ch_pkt->hdr.type == DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE)
                dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE_ACK,
                                                  l_ch_chain_net_pkt->hdr.net_id, NULL, 0);
            break;

        // received ping request - > send pong request
        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PING:
            //log_it(L_INFO, "Get CHAIN_CH_NET_PKT_TYPE_PING");
            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PONG,
                                              l_ch_chain_net_pkt->hdr.net_id,NULL, 0);
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
            break;

        // received pong request -> send nothing
        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PONG:
            //log_it(L_INFO, "Get CHAIN_CH_NET_PKT_TYPE_PONG");
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
            break;

        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST:{
            if (l_ch_chain_net_pkt->hdr.data_size != DAP_CHAIN_NET_CH_VALIDATOR_READY_REQUEST_SIZE) {
                log_it(L_WARNING, "Invalid VALIDATOR_READY_REQUEST size %hu, expected %u", l_ch_chain_net_pkt->hdr.data_size,
                                                                            DAP_CHAIN_NET_CH_VALIDATOR_READY_REQUEST_SIZE);
                return false;
            }
            log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST");
            dap_chain_net_t * l_net = dap_chain_net_by_id( l_ch_chain_net_pkt->hdr.net_id );
            if ( l_net == NULL){
                char l_err_str[]="ERROR_NET_INVALID_ID";
                dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR ,
                                                  l_ch_chain_net_pkt->hdr.net_id, l_err_str,sizeof (l_err_str));
                dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
                log_it(L_ERROR, "Invalid net id in packet");
                break;
            }
            dap_list_t * l_orders = NULL;
            dap_enc_key_t *l_enc_key_pvt = NULL;
            dap_chain_t *l_chain = NULL;
            DL_FOREACH(l_net->pub.chains, l_chain)
                if (!dap_strcmp(dap_chain_get_cs_type(l_chain), "esbocs")) {
                    l_enc_key_pvt = dap_chain_esbocs_get_sign_key(l_chain);
                    if (l_enc_key_pvt)
                        break;
                }
            dap_sign_t *l_sign = NULL;
            size_t sign_s = 0;
            size_t l_orders_num = 0;
            dap_chain_ch_validator_test_t *send = NULL;
            dap_chain_net_srv_price_unit_uid_t l_price_unit = { { 0 } };
            dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID };
            uint256_t l_price_min = {};
            uint256_t l_price_max = {};
            uint8_t flags = 0;

            if (l_enc_key_pvt) {
                flags = flags | F_CERT;//faund sert
                l_sign = dap_sign_create(l_enc_key_pvt, (uint8_t*)l_ch_chain_net_pkt->data, l_ch_chain_net_pkt->hdr.data_size);
                if (l_sign) {
                    sign_s = dap_sign_get_size(l_sign);
                    flags = flags | D_SIGN;//data signed
                } else
                    flags = flags & ~D_SIGN;//data doesn't sign
            }
            else
                flags = flags & ~F_CERT;//Specified certificate not found

            send = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_ch_validator_test_t, sizeof(dap_chain_ch_validator_test_t) + sign_s, false);
#ifdef DAP_VERSION
            strncpy((char *)send->header.version, (char *)DAP_VERSION, sizeof(send->header.version));
#endif
            send->header.sign_size = sign_s;
            //strncpy(send->header.data,(uint8_t*)l_ch_chain_net_pkt->data,10);
            flags = (l_net->pub.mempool_autoproc) ? flags | A_PROC : flags & ~A_PROC;

            if (dap_chain_net_srv_order_find_all_by(l_net, SERV_DIR_UNDEFINED, l_uid, l_price_unit, NULL,
                                                    l_price_min, l_price_max, &l_orders, &l_orders_num) == 0) {
                for (dap_list_t *l_temp = l_orders; l_temp; l_temp = l_temp->next) {
                    dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_temp->data;
                    if (l_order->node_addr.uint64 == g_node_addr.uint64) {
                        dap_sign_t *l_order_sign = (dap_sign_t *)(l_order->ext_n_sign + l_order->ext_size);
                        if (dap_sign_compare_pkeys(l_sign, l_order_sign)) {
                            flags = flags | F_ORDR;
                            break;
                        }
                    }
                }
                dap_list_free_full(l_orders, NULL);
            }
            bool auto_online = dap_config_get_item_bool_default( g_config, "general", "auto_online", false );
            bool auto_update = false;
            if((system("systemctl status cellframe-updater.service") == 768) && (system("systemctl status cellframe-updater.timer") == 0))
                auto_update = true;
            else
                auto_update = false;
            flags = auto_online ? flags | A_ONLN : flags & ~A_ONLN;
            flags = auto_update ? flags | A_UPDT : flags & ~A_UPDT;
            send->header.flags = flags;
            //add sign
            if(sign_s)
                memcpy(send->sign,l_sign,sign_s);
            dap_stream_ch_chain_net_pkt_write(a_ch, DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY ,
                                             l_ch_chain_net_pkt->hdr.net_id, send, sizeof(dap_chain_ch_validator_test_t) + sign_s);
            dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
            if(l_sign)
                DAP_DELETE(l_sign);
            DAP_DELETE(send);
        } break;

        case DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY:{
            log_it(L_INFO, "Get CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY");

            dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        } break;

        default:
            log_it(L_ERROR, "Unknown paket type %hhu", l_ch_pkt->hdr.type);
            return false;
        }

        if(l_ch_chain_net->notify_callback)
            l_ch_chain_net->notify_callback(l_ch_chain_net,l_ch_pkt->hdr.type, l_ch_chain_net_pkt,
                                            l_ch_chain_net_pkt->hdr.data_size, l_ch_chain_net->notify_callback_arg);

    }
    return true;
}
