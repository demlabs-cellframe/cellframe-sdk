/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
**/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_node.h"
#include "dap_stream_ch.h"

#define DAP_STREAM_CH_CHAIN_NET_PKT_VERSION                             1

#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_TEST                           0x01

#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PING                           0x02
#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_PONG                           0x03

#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY_REQUEST   0x30
#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_NODE_VALIDATOR_READY           0x31

#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE                       0x44
#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ANNOUNCE_ACK                   0x45

#define DAP_STREAM_CH_CHAIN_NET_PKT_TYPE_ERROR                          0xff

#define DAP_CHAIN_NET_CH_VALIDATOR_READY_REQUEST_SIZE                   1024

typedef struct stream_ch_chain_net_pkt_hdr {
    uint8_t version;
    byte_t padding;
    uint16_t data_size;
    dap_chain_net_id_t net_id;
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_pkt_hdr_t;

typedef struct dap_stream_ch_chain_net_pkt{
    dap_stream_ch_chain_net_pkt_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_net_pkt_t;

size_t dap_stream_ch_chain_net_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type, dap_chain_net_id_t a_net_id, const void * a_data, size_t a_data_size);
DAP_PRINTF_ATTR(4, 5) size_t dap_stream_ch_chain_net_pkt_write_f(dap_stream_ch_t *a_ch, uint8_t a_type, dap_chain_net_id_t a_net_id, const char *a_str, ...);

