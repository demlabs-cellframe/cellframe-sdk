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

struct stream;
struct stream_pkt;
struct stream_ch_proc;
struct stream_ch;

#define SERVICE_CHANNEL_ID 's'
#define DATA_CHANNEL_ID 'd'

typedef void (*stream_ch_callback_t) (struct stream_ch*,void*);

typedef struct stream_ch{
    pthread_mutex_t mutex;
    bool ready_to_write;
    bool ready_to_read;
    struct stream * stream;

    struct{
        uint64_t bytes_write;
        uint64_t bytes_read;
    } stat;

    uint8_t buf[500000];

    struct stream_ch_proc * proc;
    void * internal;  // Internal structure, GStreamer for example
} stream_ch_t;

extern int stream_ch_init();
extern void stream_ch_deinit();

extern stream_ch_t* stream_ch_new(struct stream*stream,uint8_t id);

extern void stream_ch_set_ready_to_write(stream_ch_t * ch,bool is_ready);

extern void stream_ch_delete(stream_ch_t*ch);

#endif
