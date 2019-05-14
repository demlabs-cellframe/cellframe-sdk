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
**/

#pragma once

#include <pthread.h>
#include <stdint.h>
#include "dap_stream_ch.h"
#include "dap_stream_ch_chain_net_pkt.h"

typedef void (*dap_stream_ch_chain_net_callback_t)(dap_stream_ch_chain_net_pkt_t *a_pkt, size_t a_pkt_data_size, void *arg);

typedef struct dap_stream_ch_chain_net {
    pthread_mutex_t mutex;
    dap_stream_ch_chain_net_callback_t notify_callback;
    dap_stream_ch_t *ch;
    void *notify_callback_arg;
} dap_stream_ch_chain_net_t;

#define DAP_STREAM_CH_CHAIN_NET(a) ((dap_stream_ch_chain_net_t *) ((a)->internal) )

uint8_t dap_stream_ch_chain_net_get_id();
uint8_t* dap_stream_ch_chain_net_make_packet(uint64_t a_node_addr_from, uint64_t a_node_addr_to,
        time_t a_timestamp_start, uint8_t *a_sdata, size_t a_sdata_len, size_t *a_data_len_out);
int dap_stream_ch_chain_net_init();
void dap_stream_ch_chain_net_deinit();
