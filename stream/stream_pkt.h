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

#ifndef _STREAM_PKT_H_
#define _STREAM_PKT_H_
//#include <gst/gst.h>
#include <stdint.h>

#define STREAM_PKT_SIZE_MAX 100000
struct stream;

#define DATA_PACKET 0x00
#define SERVICE_PACKET 0xff
#define KEEPALIVE_PACKET 0x11

typedef struct stream_pkt_hdr{
    uint8_t sig[8];  // Signature to find out beginning of the frame
    uint32_t size;
    uint64_t timestamp;
    uint8_t type;      // Packet type
    uint64_t s_addr; // Source address ( vasya@domain.net )
    uint64_t d_addr; // Destination address ( general#domain.net )
}  __attribute__((packed)) stream_pkt_hdr_t;

typedef struct stream_pkt{
    stream_pkt_hdr_t hdr;
    uint8_t data[];
}  __attribute__((packed)) stream_pkt_t;

typedef struct stream_srv_pkt{
    uint32_t session_id;
    uint8_t enc_type;
    uint32_t coockie;
} __attribute__((packed)) stream_srv_pkt_t;


extern const uint8_t dap_sig[8];

extern stream_pkt_t * stream_pkt_detect(void * data, uint32_t data_size);

extern size_t stream_pkt_read(struct stream * sid,struct stream_pkt * pkt, void * buf_out);

extern size_t stream_pkt_write(struct stream * sid, const void * data, uint32_t data_size);

extern void stream_send_keepalive(struct stream * sid);

#endif
