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

typedef struct dap_stream_ch_chain_net dap_stream_ch_chain_net_t;

typedef void (*dap_stream_ch_chain_net_callback_packet_t)(
        dap_stream_ch_chain_net_t *, uint8_t, dap_stream_ch_chain_net_pkt_t *, size_t , void *);

typedef struct dap_stream_ch_chain_net {
    pthread_mutex_t mutex;
    dap_stream_ch_chain_net_callback_packet_t notify_callback;
    dap_stream_ch_t *ch;
    void *notify_callback_arg;
} dap_stream_ch_chain_net_t;

#define DAP_STREAM_CH_CHAIN_NET(a) ((dap_stream_ch_chain_net_t *) ((a)->internal) )

uint8_t dap_stream_ch_chain_net_get_id();
int dap_stream_ch_chain_net_init();
void dap_stream_ch_chain_net_deinit();
