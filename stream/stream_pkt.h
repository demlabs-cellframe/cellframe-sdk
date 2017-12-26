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

typedef struct stream_pkt_hdr{
    uint8_t sig[8];  // Signature to find out beginning of the frame
    uint32_t size;
    uint8_t TTL;
    char s_addr[32]; // Source address ( vasya@domain.net )
    char d_addr[32]; // Destination address ( general#domain.net )
}  __attribute__((packed)) stream_pkt_hdr_t;

typedef struct stream_pkt{
    stream_pkt_hdr_t hdr;
    uint8_t data[];
}  __attribute__((packed)) stream_pkt_t;

extern const uint8_t dap_sig[8];

extern stream_pkt_t * stream_pkt_detect(void * data, uint32_t data_size);

extern size_t stream_pkt_read(struct stream * sid,struct stream_pkt * pkt, void * buf_out);

extern size_t stream_pkt_write(struct stream * sid, const void * data, uint32_t data_size);

#endif
