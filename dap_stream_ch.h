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

#ifndef _STREAM_CH_H
#define _STREAM_CH_H
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>

typedef struct dap_stream dap_stream_t;
typedef struct dap_stream_pkt dap_stream_pkt_t;
typedef struct dap_stream_ch_proc dap_stream_ch_proc_t;
typedef struct dap_stream_ch dap_stream_ch_t;
typedef struct dap_events_socket dap_events_socket_t;

#define SERVICE_CHANNEL_ID 's'
#define VPN_CLIENT_ID SERVICE_CHANNEL_ID
#define DATA_CHANNEL_ID 'd'

typedef void (*dap_stream_ch_callback_t) (dap_stream_ch_t*,void*);

typedef struct dap_stream_ch{
    pthread_mutex_t mutex;
    bool ready_to_write;
    bool ready_to_read;
    dap_stream_t * stream;
    struct{
        uint64_t bytes_write;
        uint64_t bytes_read;
    } stat;

    uint8_t buf[500000];

    dap_stream_ch_proc_t * proc;
    void * internal;
} dap_stream_ch_t;

int dap_stream_ch_init();
void dap_stream_ch_deinit();

dap_stream_ch_t* dap_stream_ch_new( dap_stream_t * dap_stream,uint8_t id);

void dap_stream_ch_set_ready_to_write(dap_stream_ch_t * ch,bool is_ready);

void dap_stream_ch_delete(dap_stream_ch_t*ch);

#endif
