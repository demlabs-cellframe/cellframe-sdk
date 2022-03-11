/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020
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

#pragma once

#include <pthread.h>
#include "dap_stream_worker.h"
#include "dap_stream_ch_pkt.h"
#include "dap_chain_common.h"

typedef struct dap_stream_ch_chain_net_srv dap_stream_ch_chain_net_srv_t;

typedef void (*dap_stream_ch_chain_net_srv_callback_packet_t)(dap_stream_ch_chain_net_srv_t *, uint8_t,
        dap_stream_ch_pkt_t *, void *);

typedef struct dap_stream_ch_chain_net_srv {
    dap_chain_net_srv_uid_t srv_uid;
    dap_stream_ch_t *ch;
    dap_stream_ch_uuid_t ch_uuid;
    dap_stream_ch_chain_net_srv_callback_packet_t notify_callback;
    void *notify_callback_arg;
} dap_stream_ch_chain_net_srv_t;

#define DAP_STREAM_CH_CHAIN_NET_SRV(a) ((dap_stream_ch_chain_net_srv_t *) ((a)->internal) )

uint8_t dap_stream_ch_chain_net_srv_get_id();
int dap_stream_ch_chain_net_srv_init(void);
