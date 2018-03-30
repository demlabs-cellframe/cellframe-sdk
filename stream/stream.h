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

#ifndef _STREAM_H
#define _STREAM_H
//#include <gst/gst.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#include "stream_session.h"
#include "stream_ch.h"


#define CHUNK_SIZE_MAX 3*1024

struct dap_client_remote;

struct dap_http_client;
struct dap_http;
struct stream;
struct stream_pkt;
#define STREAM_BUF_SIZE_MAX 10240

typedef void (*stream_callback)(struct stream*,void*);

typedef struct stream {

    int id;
    stream_session_t * session;
    struct dap_client_remote * conn; // Connection

    struct dap_http_client * conn_http; // HTTP-specific

    bool is_live;

    struct stream_pkt * in_pkt;
    struct stream_pkt *pkt_buf_in;
    size_t pkt_buf_in_data_size;

    uint8_t buf[500000];

    stream_ch_t * channel[255]; // TODO reduce channels to 16 to economy memory
    size_t channel_count;

    size_t frame_sent; // Frame counter

    size_t stream_size;

} stream_t;

#define STREAM(a) ((stream_t *) (a)->_internal )

extern int stream_init();
extern void stream_deinit();

extern void stream_add_proc(struct dap_http * sh, const char * url);

#endif
