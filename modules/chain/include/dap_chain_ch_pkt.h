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
#include <string.h>
#include <stdarg.h>

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_stream_ch.h"

#define DAP_CHAIN_CH_PKT_VERSION_CURRENT                0x02

// Stable
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_REQ                 0x80
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_MISS                0x69
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN                     0x84
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_SUMMARY             0x81
#define DAP_CHAIN_CH_PKT_TYPE_CHAIN_ACK                 0x82
#define DAP_CHAIN_CH_PKT_TYPE_SYNCED_CHAIN              0x88
#define DAP_CHAIN_CH_PKT_TYPE_ERROR                     0xff

DAP_STATIC_INLINE const char *dap_chain_ch_pkt_type_to_str(uint8_t a_pkt_type)
{
    switch (a_pkt_type) {
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

// *** Legacy *** //

typedef struct dap_chain_ch_sync_request_old {
    dap_chain_hash_fast_t hash_from;
    uint64_t num_from;
} DAP_ALIGN_PACKED dap_chain_ch_sync_request_old_t;

// *** Active *** //

typedef struct dap_chain_ch_sync_request {
    dap_chain_hash_fast_t hash_from;
    uint64_t num_from;
    uint16_t generation;
} DAP_ALIGN_PACKED dap_chain_ch_sync_request_t;

typedef struct dap_chain_ch_summary {
    uint64_t num_cur;
    uint64_t num_last;
    uint16_t generation;
    byte_t reserved[126];
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
                                         const void *a_data, size_t a_data_size, uint8_t a_version);

size_t dap_chain_ch_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type,
                                     dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                     const void *a_data, size_t a_data_size, uint8_t a_version);

size_t dap_chain_ch_pkt_write(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,
                                 dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id, dap_chain_cell_id_t a_cell_id,
                                 const void *a_data, size_t a_data_size, uint8_t a_version);
