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
#include "dap_common.h"
#include "dap_http_client.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain_net_pkt.h"
#include "dap_stream_ch_chain_net.h"


#define LOG_TAG "dap_stream_ch_chain_net"

static void s_stream_ch_new(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg);

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

}

/**
 * @brief s_stream_ch_new
 * @param a_ch
 * @param arg
 */
void s_stream_ch_new(dap_stream_ch_t* a_ch , void* arg)
{
    a_ch->internal=DAP_NEW_Z(dap_stream_ch_chain_net_t);
    dap_stream_ch_chain_net_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET(a_ch);
    pthread_mutex_init( &l_ch_chain_net->mutex,NULL);
}


/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg)
{

}

static int debug_count = 0;

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch, void* a_arg)
{
    dap_stream_ch_chain_net_t * l_ch_chain = DAP_STREAM_CH_CHAIN_NET(a_ch);
    if(l_ch_chain) {
        dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
        dap_stream_ch_chain_net_pkt_t *l_chain_pkt = (dap_stream_ch_chain_net_pkt_t *) l_ch_pkt->data;
        if(l_chain_pkt) {
            size_t data_size = l_ch_pkt->hdr.size - sizeof(dap_stream_ch_chain_net_pkt_hdr_t);
            printf("*packet TYPE=%d data_size=%d in=%s\n", l_chain_pkt->hdr.type, data_size,
                    (data_size > 0) ? (char*) (l_chain_pkt->data) : "-");

            switch (l_chain_pkt->hdr.type) {
            case STREAM_CH_CHAIN_NET_PKT_TYPE_DBG: {
                dap_stream_ch_chain_net_pkt_write(a_ch, STREAM_CH_CHAIN_NET_PKT_TYPE_PING, NULL, 0);
                dap_stream_ch_set_ready_to_write(a_ch, true);
            }
                break;
            case STREAM_CH_CHAIN_NET_PKT_TYPE_PING: {
                log_it(L_INFO,"Get STREAM_CH_CHAIN_NET_PKT_TYPE_PING");
                int l_res = dap_stream_ch_chain_net_pkt_write(a_ch, STREAM_CH_CHAIN_NET_PKT_TYPE_PONG, NULL, 0);
                dap_stream_ch_set_ready_to_write(a_ch, true);
            }
                break;
            case STREAM_CH_CHAIN_NET_PKT_TYPE_PONG: {
                log_it(L_INFO,"Get STREAM_CH_CHAIN_NET_PKT_TYPE_PONG");
                dap_stream_ch_set_ready_to_write(a_ch, false);
            }
                break;
            case STREAM_CH_CHAIN_NET_PKT_TYPE_GLOVAL_DB: {
            }
                break;
            case STREAM_CH_CHAIN_NET_PKT_TYPE_GLOBAL_DB_REQUEST_SYNC: {
                // должен сообщать последнюю ревизию global_db у ноды-клиента,
                // чем инициировать у ноды-сервера процесс отправки транзиция
            }
                break;
            }
            if(l_ch_chain->notify_callback)
                l_ch_chain->notify_callback(l_chain_pkt, l_ch_chain->notify_callback_arg);
        }
    }
    debug_count++;
}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch, void* a_arg)
{
    printf("*packet out count=%d\n", debug_count);
    dap_stream_ch_set_ready_to_write(a_ch, false);
}
