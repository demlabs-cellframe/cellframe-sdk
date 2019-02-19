/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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

#include "dap_common.h"

#include "dap_config.h"

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_proc.h"
#include "dap_stream_ch_chain.h"
#include "dap_stream_ch_chain_pkt.h"

#define LOG_TAG "dap_stream_ch_chain"
typedef enum dap_stream_ch_chain_state{
    CHAIN_STATE_NOTHING,
    CHAIN_STATE_SEND_CHAIN
} dap_stream_ch_chain_state_t;

typedef struct dap_stream_ch_chain {
    pthread_mutex_t mutex;
    dap_chain_hash_t block_id;

} dap_stream_ch_chain_t;

#define DAP_STREAM_CH_CHAIN(a) ((dap_stream_ch_chain_t *) ((a)->internal) )

void s_stream_ch_new(dap_stream_ch_t* ch , void* arg);
void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg);
void s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg);
void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg);
/**
 * @brief dap_stream_ch_chain_init
 * @return
 */
int dap_stream_ch_chain_init()
{
    log_it(L_NOTICE,"Chain blocks and datums exchange channel initialized");
    dap_stream_ch_proc_add('C',s_stream_ch_new,s_stream_ch_delete,s_stream_ch_packet_in,s_stream_ch_packet_out);

    return 0;
}

/**
 * @brief dap_stream_ch_chain_deinit
 */
void dap_stream_ch_chain_deinit()
{

}

/**
 * @brief s_stream_ch_new
 * @param a_ch
 * @param arg
 */
void s_stream_ch_new(dap_stream_ch_t* a_ch , void* arg)
{
    a_ch->internal=DAP_NEW_Z(dap_stream_ch_chain_t);
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    pthread_mutex_init( &l_ch_chain->mutex,NULL);
}


/**
 * @brief s_stream_ch_delete
 * @param ch
 * @param arg
 */
void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg)
{

}

/**
 * @brief s_stream_ch_packet_in
 * @param a_ch
 * @param a_arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* a_ch , void* a_arg)
{
    dap_stream_ch_chain_t * l_ch_chain = DAP_STREAM_CH_CHAIN(a_ch);
    if ( l_ch_chain){
        dap_stream_ch_pkt_t * l_ch_pkt = (dap_stream_ch_pkt_t *) a_arg;
        dap_stream_ch_chain_pkt_t * l_chain_pkt =(dap_stream_ch_chain_pkt_t *) l_ch_pkt->data;
        if( l_chain_pkt ){
            dap_chain_t * l_chain = dap_chain_find_by_id(l_chain_pkt->hdr.net_id,  l_chain_pkt->hdr.chain_id,
                                                         l_chain_pkt->hdr.shard_id);
            if ( l_chain ) {
                switch ( l_chain_pkt->hdr.type ) {
                    case STREAM_CH_CHAIN_PKT_TYPE_REQUEST:{
                    }break;
                    case STREAM_CH_CHAIN_PKT_TYPE_DATUM:{
                    }break;
                    case STREAM_CH_CHAIN_PKT_TYPE_BLOCK:{
                    }break;
                    case STREAM_CH_CHAIN_PKT_TYPE_GLOVAL_DB:{
                    }break;
                }
            }
        }
    }
}
/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg)
{

}
