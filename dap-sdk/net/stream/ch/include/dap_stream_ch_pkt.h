/*
 Copyright (c) 2020 (c) DeM Labs Ltd http://demlabs.net
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/


#pragma once

#define STREAM_CH_PKT_TYPE_REQUEST      0x0
//#define STREAM_CH_PKT_TYPE_KEEPALIVE    0x11

#include <stdint.h>
#include <stddef.h>

#include "dap_enc_key.h"

typedef uint64_t dap_stream_ch_uuid_t;
typedef struct dap_stream_ch dap_stream_ch_t;
typedef struct dap_stream_session dap_stream_session_t;
typedef struct dap_events_socket dap_events_socket_t;
typedef struct dap_stream_worker dap_stream_worker_t;
typedef struct dap_stream_ch_pkt_hdr{
    uint8_t id;   // Channel id
    uint8_t enc_type; // Zero if not encrypted
    uint8_t type; // general, command, info, signal and etc
    uint8_t padding;
    uint64_t seq_id; // Sequence id or position id
//    uint64_t seq
    uint32_t size;
}  __attribute__((packed)) dap_stream_ch_pkt_hdr_t;

typedef struct dap_stream_ch_pkt{
    dap_stream_ch_pkt_hdr_t hdr;
    uint8_t data[];
} __attribute__((packed)) dap_stream_ch_pkt_t;

typedef void (*dap_stream_ch_callback_packet_t)(void *, uint8_t, dap_stream_ch_pkt_t *, void *);

int dap_stream_ch_pkt_init();
void dap_stream_ch_pkt_deinit();

size_t dap_stream_ch_pkt_write_f_unsafe(dap_stream_ch_t * a_ch, uint8_t a_type, const char * a_str,...);
size_t dap_stream_ch_pkt_write_unsafe(dap_stream_ch_t * a_ch,  uint8_t a_type, const void * a_data, size_t a_data_size);

size_t dap_stream_ch_pkt_write_f_mt(dap_stream_worker_t * a_worker , dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const char * a_str,...);
size_t dap_stream_ch_pkt_write_mt(dap_stream_worker_t * a_worker , dap_stream_ch_uuid_t a_ch_uuid,  uint8_t a_type, const void * a_data, size_t a_data_size);

size_t dap_stream_ch_pkt_write_f_inter(dap_events_socket_t * a_queue , dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, const char * a_str,...);
size_t dap_stream_ch_pkt_write_inter(dap_events_socket_t * a_queue , dap_stream_ch_uuid_t a_ch_uuid,  uint8_t a_type, const void * a_data, size_t a_data_size);
