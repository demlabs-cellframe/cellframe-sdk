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

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include "dap_common.h"
#include "dap_stream.h"
#include "dap_stream_ch.h"
#include "dap_stream_ch_chain_net.h"
#include "dap_stream_ch_proc.h"


#define LOG_TAG "dap_stream_ch_chain_net"

typedef struct dap_stream_ch_chain_net {
    pthread_mutex_t mutex;
} dap_stream_ch_chain_net_t;

#define DAP_STREAM_CH_CHAIN_NET(a) ((dap_stream_ch_chain_net_t *) ((a)->internal) )

static void s_stream_ch_new(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_delete(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg);
static void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg);

/**
 * @brief dap_stream_ch_chain_net_init
 * @return
 */
int dap_stream_ch_chain_net_init()
{
    log_it(L_NOTICE,"Chain network channel initialized");
    dap_stream_ch_proc_add('N',s_stream_ch_new,s_stream_ch_delete,s_stream_ch_packet_in,s_stream_ch_packet_out);

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

/**
 * @brief s_stream_ch_packet_in
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_in(dap_stream_ch_t* ch , void* arg)
{

}

/**
 * @brief s_stream_ch_packet_out
 * @param ch
 * @param arg
 */
void s_stream_ch_packet_out(dap_stream_ch_t* ch , void* arg)
{

}
