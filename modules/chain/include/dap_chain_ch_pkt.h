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

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>

#include "dap_common.h"
#include "dap_proc_thread.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"

#include "dap_stream_ch.h"

#define DAP_CHAIN_CH_PKT_VERSION_CURRENT                0x02

//Legacy
#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_REQ      0x06
#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START    0x26
#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB          0x36
#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END      0x46
#define DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB           0x21
#define DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB                 0x11
#define DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB          0x13

#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_REQ         0x05
#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_START       0x25
#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS             0x35
#define DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END         0x45
#define DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN               0x20
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_OLD                 0x01
#define DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS             0x03

// Freeze detectors
#define DAP_CHAIN_CH_PKT_TYPE_CHAINS_NO_FREEZE          0x15
#define DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB_NO_FREEZE       0x16

// Stable
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ                 0x80
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS                0x69
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN                     0x84
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY             0x81
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK                 0x82
#define DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN              0x88
#define DAP_CHAIN_CH_PKT_TYPE_ERROR                     0xff

// *** Legacy *** //

typedef struct dap_chain_ch_update_element {
    dap_hash_fast_t hash;
    uint32_t size;
} DAP_ALIGN_PACKED dap_chain_ch_update_element_t;

typedef struct dap_chain_ch_sync_request_old {
    dap_chain_node_addr_t node_addr; // Requesting node's address
    dap_chain_hash_fast_t hash_from;
    byte_t unused[48];
} DAP_ALIGN_PACKED dap_chain_ch_sync_request_old_t;

DAP_STATIC_INLINE const char *dap_chain_ch_pkt_type_to_str(uint8_t a_pkt_type)
{
    switch (a_pkt_type) {
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_REQ: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_REQ";
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_START";
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB";
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END";
    case DAP_CHAIN_CH_PKT_TYPE_FIRST_GLOBAL_DB: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_GLOBAL_DB_END";
    case DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB: return "DAP_CHAIN_CH_PKT_TYPE_GLOBAL_DB";
    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB: return "DAP_CHAIN_CH_PKT_TYPE_SYNCED_GLOBAL_DB";

    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_REQ: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_REQ";
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_START: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_START";
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS";
    case DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END: return "DAP_CHAIN_CH_PKT_TYPE_UPDATE_CHAINS_END";
    case DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN: return "DAP_CHAIN_CH_PKT_TYPE_FIRST_CHAIN";
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_OLD: return "DAP_CHAIN_CH_PKT_TYPE_CHAIN_OLD";
    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS: return "DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAINS";

    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ: return "DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ";
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS: return "DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS";
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN: return "DAP_CHAIN_CH_PKT_TYPE_CHAIN";
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY: return "DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY";
    case DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK: return "DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK";
    case DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN: return "DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN";

    case DAP_CHAIN_CH_PKT_TYPE_ERROR: return "DAP_CHAIN_CH_PKT_TYPE_ERROR";
    default: return "DAP_CHAIN_CH_PKT_TYPE_UNKNOWN";
    }
}

void dap_chain_ch_pkt_set_version(uint8_t a_version);

// *** Active *** //

typedef struct dap_chain_ch_sync_request {
    dap_chain_hash_fast_t hash_from;
    uint64_t num_from;
} DAP_ALIGN_PACKED dap_chain_ch_sync_request_t;

typedef struct dap_chain_ch_summary {
    uint64_t num_cur;
    uint64_t num_last;
    byte_t reserved[128];
} DAP_ALIGN_PACKED dap_chain_ch_summary_t;

typedef struct dap_chain_ch_miss_info {
    dap_hash_fast_t missed_hash;
    dap_hash_fast_t last_hash;
    uint64_t last_num;
} DAP_ALIGN_PACKED dap_chain_ch_miss_info_t;

typedef struct dap_chain_ch_pkt_hdr {
    uint8_t version;
    uint8_t num_hi;
    uint16_t num_lo;
    uint32_t data_size;
    dap_chain_net_id_t net_id;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
}  DAP_ALIGN_PACKED dap_chain_ch_pkt_hdr_t;

typedef struct dap_chain_ch_pkt {
    dap_chain_ch_pkt_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_chain_ch_pkt_t;

DAP_STATIC_INLINE size_t dap_chain_ch_pkt_get_size(dap_chain_ch_pkt_t *a_pkt) { return sizeof(dap_chain_ch_pkt_hdr_t) + a_pkt->hdr.data_size; }

dap_chain_ch_pkt_t *dap_chain_ch_pkt_new(dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                         const void *a_data, size_t a_data_size);

size_t dap_chain_ch_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type,
                                     dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                     const void *a_data, size_t a_data_size);

size_t dap_chain_ch_pkt_write_mt(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                 dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                 const void *a_data, size_t a_data_size);

size_t dap_chain_ch_pkt_write_inter(dap_events_socket_t *a_es_input, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                    dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                    const void *a_data, size_t a_data_size);
