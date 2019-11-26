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
#include <string.h>

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"

#include "dap_stream_ch.h"

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN                     0x01
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB                 0x11
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN               0x20
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB           0x21

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS               0x02
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB            0x12
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_ALL                  0x22


#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS             0x03
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB          0x13
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL                0x23
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR                     0xff


typedef struct dap_stream_ch_chain_sync_request{
    dap_chain_node_addr_t node_addr; // Requesting node's address
    dap_chain_hash_fast_t hash_from;
    dap_chain_hash_fast_t hash_to;
    uint64_t id_start;
    uint64_t id_end;
} DAP_ALIGN_PACKED dap_stream_ch_chain_sync_request_t;


typedef struct dap_stream_ch_chain_pkt_hdr{
    uint8_t version;
    uint8_t padding[7];
    dap_chain_net_id_t net_id;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
}  DAP_ALIGN_PACKED dap_stream_ch_chain_pkt_hdr_t;

typedef struct dap_stream_ch_chain_pkt{
    dap_stream_ch_chain_pkt_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_pkt_t;

static const char* c_dap_stream_ch_chain_pkt_type_str[]={
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_ALL] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_ALL",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR"

};

uint dap_stream_ch_chain_pkt_type_to_dap_stream_ch_chain_state(uint a_state);

size_t dap_stream_ch_chain_pkt_write(dap_stream_ch_t *a_ch, uint8_t a_type,dap_chain_net_id_t a_net_id,
                                     dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
        const void * a_data, size_t a_data_size);

inline static size_t dap_stream_ch_chain_pkt_write_error(dap_stream_ch_t *a_ch, dap_chain_net_id_t a_net_id,
                                                  dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id, const char * a_err_string )
{
    return  dap_stream_ch_chain_pkt_write( a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR, a_net_id, a_chain_id, a_cell_id, a_err_string,strlen (a_err_string)+1 );
}
