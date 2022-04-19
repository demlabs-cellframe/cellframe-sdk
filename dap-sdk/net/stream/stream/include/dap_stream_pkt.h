/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
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
#include <stdint.h>
#include <stddef.h>
#include "dap_enc_key.h"
#include "dap_events_socket.h"
#define STREAM_PKT_SIZE_MAX 100000
typedef struct dap_stream dap_stream_t;
typedef struct dap_stream_session dap_stream_session_t;
#define STREAM_PKT_TYPE_DATA_PACKET 0x00
#define STREAM_PKT_TYPE_SERVICE_PACKET 0xff
#define STREAM_PKT_TYPE_KEEPALIVE   0x11
#define STREAM_PKT_TYPE_ALIVE       0x12
#define STREAM_PKT_SIG_SIZE         8

typedef struct dap_stream_pkt_hdr{
    uint8_t sig[STREAM_PKT_SIG_SIZE];  // Signature to find out beginning of the frame
    uint32_t size;
    uint64_t timestamp;
    uint8_t type;      // Packet type
    uint64_t src_addr; // Source address ( vasya@domain.net )
    uint64_t dst_addr; // Destination address ( general#domain.net )
}  __attribute__((packed)) dap_stream_pkt_hdr_t;

typedef struct dap_stream_pkt{
    dap_stream_pkt_hdr_t hdr;
    uint8_t data[];
}  __attribute__((packed)) dap_stream_pkt_t;

typedef struct stream_srv_pkt{
    uint32_t session_id;
    uint8_t enc_type;
    uint32_t coockie;
} __attribute__((packed)) stream_srv_pkt_t;

extern const uint8_t c_dap_stream_sig[8];

dap_stream_pkt_t * dap_stream_pkt_detect(void * a_data, size_t data_size);

size_t dap_stream_pkt_read_unsafe(dap_stream_t * a_stream, dap_stream_pkt_t * a_pkt, void * a_buf_out, size_t a_buf_out_size);

size_t dap_stream_pkt_write_unsafe(dap_stream_t * a_stream, const void * data, size_t a_data_size);
size_t dap_stream_pkt_write_mt (dap_worker_t * a_w, dap_events_socket_uuid_t a_es_uuid, dap_enc_key_t *a_key, const void * data, size_t a_data_size);

void dap_stream_send_keepalive( dap_stream_t * a_stream);


