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

#include <stdint.h>
#include <stddef.h>
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_node.h"

#define STREAM_CH_CHAIN_NET_PKT_TYPE_PING       0x0000
#define STREAM_CH_CHAIN_NET_PKT_TYPE_PONG       0x0001

typedef struct stream_ch_chain_net_pkt_hdr{
    dap_chain_net_id_t net_id;
    uint16_t type; // Chain data type
    uint8_t padding1[2]; // Some padding
    union{
        uint64_t raw;
    };
}  __attribute__((packed)) dap_stream_ch_chain_net_pkt_hdr_t;

typedef struct dap_stream_ch_chain_net_pkt{
    dap_stream_ch_chain_net_pkt_hdr_t hdr;
    uint8_t data[];
} __attribute__((packed)) dap_stream_ch_chain_net_pkt_t;

