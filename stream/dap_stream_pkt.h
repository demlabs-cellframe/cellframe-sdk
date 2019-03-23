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

#define STREAM_PKT_SIZE_MAX 500000
struct dap_stream;

#define STREAM_PKT_TYPE_DATA_PACKET 0x00
#define STREAM_PKT_TYPE_SERVICE_PACKET 0xff
//#define STREAM_PKT_TYPE_KEEPALIVE 0x11

typedef struct stream_pkt_hdr{
    uint8_t sig[8];  // Signature to find out beginning of the frame
    uint32_t size;
    uint64_t timestamp;
    uint8_t type;      // Packet type
    uint64_t s_addr; // Source address ( vasya@domain.net )
    uint64_t d_addr; // Destination address ( general#domain.net )
}  __attribute__((packed)) stream_pkt_hdr_t;

typedef struct dap_stream_pkt{
    stream_pkt_hdr_t hdr;
    uint8_t data[];
}  __attribute__((packed)) dap_stream_pkt_t;

typedef struct stream_srv_pkt{
    uint32_t session_id;
    uint8_t enc_type;
    uint32_t coockie;
} __attribute__((packed)) stream_srv_pkt_t;


extern const uint8_t dap_sig[8];

dap_stream_pkt_t * dap_stream_pkt_detect(void * data, uint32_t data_size);

size_t dap_stream_pkt_read(struct dap_stream * sid,struct dap_stream_pkt * pkt, void * buf_out, size_t buf_out_size);

size_t dap_stream_pkt_write(struct dap_stream * sid, const void * data, uint32_t data_size);

void dap_stream_send_keepalive(struct dap_stream * sid);


