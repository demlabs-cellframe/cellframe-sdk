/*
* Authors:
* Dmitriy Gerasimov <naeper@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2019
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
#include "dap_common.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"
#include "dap_stream_ch_chain_net_srv_session.h"
#include "dap_stream_ch_proc.h"

#define LOG_TAG "dap_stream_ch_chain_net_srv"

typedef struct dap_stream_ch_chain_net_srv {
    pthread_mutex_t mutex;
} dap_stream_ch_chain_net_srv_t;

#define DAP_STREAM_CH_CHAIN_NET_SRV(a) ((dap_stream_ch_chain_net_srv_t *) ((a)->internal) )

static void s_stream_ch_new(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg);

/**
 * @brief dap_stream_ch_chain_net_init
 * @return
 */
int dap_stream_ch_chain_net_srv_init(void)
{
    log_it(L_NOTICE,"Chain network services channel initialized");
    dap_stream_ch_proc_add('R',s_stream_ch_new,s_stream_ch_delete,s_stream_ch_packet_in,s_stream_ch_packet_out);

    return 0;
}

/**
 * @brief dap_stream_ch_chain_deinit
 */
void dap_stream_ch_chain_net_srv_deinit(void)
{

}

/**
 * @brief s_stream_ch_new
 * @param a_ch
 * @param arg
 */
void s_stream_ch_new(dap_stream_ch_t* a_ch , void* arg)
{
    a_ch->internal=DAP_NEW_Z(dap_stream_ch_chain_net_srv_t);
    dap_stream_ch_chain_net_srv_t * l_ch_chain_net_srv = DAP_STREAM_CH_CHAIN_NET_SRV(a_ch);
    pthread_mutex_init( &l_ch_chain_net_srv->mutex,NULL);
    if (a_ch->stream->session->_inheritor == NULL && a_ch->stream->session != NULL)
        dap_stream_ch_chain_net_srv_session_create( a_ch->stream->session );
    else if ( a_ch->stream->session == NULL)
        log_it( L_ERROR, "No session at all!");
    else
        log_it(L_ERROR, "Session inheritor is already present!");
}


/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* a_ch , void* a_arg)
{

}

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch , void* a_arg)
{
    dap_stream_ch_chain_net_srv_t * l_ch_chain_net = DAP_STREAM_CH_CHAIN_NET_SRV(a_ch);
    dap_stream_ch_pkt_t *l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg; // chain packet
    if(l_ch_pkt) {
        switch (l_ch_pkt->hdr.type) {
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_REQUEST:{
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_REQUEST:{
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_SIGN_RESPONSE:{
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RECEIPE:{
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_SUCCESS:{
            } break;
            case DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR:{
            } break;
            default: log_it( L_WARNING, "Unknown packet type 0x%02X", l_ch_pkt->hdr.type);
        }
    }

}

/**
 * @brief s_stream_ch_packet_out
 * @param a_ch
 * @param a_arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* a_ch , void* a_arg)
{
    (void) a_arg;
    log_it(L_WARNING,"We don't need anything special to write but for some reasons write flag was on and now we're in output callback. Why?");
    dap_stream_ch_set_ready_to_write(a_ch, false);
}
