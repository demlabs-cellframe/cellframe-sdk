/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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
    dap_stream_ch_chain_net_callback_packet_t notify_callback;
    dap_stream_ch_t *ch;
    void *notify_callback_arg;
} dap_stream_ch_chain_net_t;

typedef struct dap_chain_ch_validator_test{
    struct{
        /// node Version
        uint8_t version[32];
        /// autoproc status
        uint8_t flags;//0 bit -autoproc; 1 bit - find order; 2 bit - auto online; 3 bit - auto update; 6 bit - data sign; 7 bit - find cert;
        uint32_t sign_size;
        uint8_t sign_correct;
        uint8_t overall_correct;
        //uint8_t data[10];
    }DAP_ALIGN_PACKED header;
    byte_t sign[];
} DAP_ALIGN_PACKED dap_chain_ch_validator_test_t;

#define A_PROC 0x01//autoproc set
#define F_ORDR 0x02//order exist
#define A_ONLN 0x04//auto online
#define A_UPDT 0x08//auto update
#define D_SIGN 0x40//data signed
#define F_CERT 0x80//faund sert

#define DAP_STREAM_CH_CHAIN_NET_ID 'N'
#define DAP_STREAM_CH_CHAIN_NET(a) ((dap_stream_ch_chain_net_t *) ((a)->internal) )

dap_chain_node_addr_t dap_stream_ch_chain_net_from_session_data_extract_node_addr(uint32_t a_session_id);

int dap_stream_ch_chain_net_init();
void dap_stream_ch_chain_net_deinit();
