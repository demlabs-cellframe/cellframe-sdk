/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "uthash.h"
#include "dap_math_ops.h"
#include "dap_stream.h"
#include "dap_stream_ch_pkt.h"

#define TECHICAL_CHANNEL_ID 't'

typedef struct dap_stream_worker dap_stream_worker_t;
typedef struct dap_stream_ch_proc dap_dap_stream_ch_proc_t;
typedef struct dap_events_socket dap_events_socket_t;

typedef void (*dap_stream_ch_callback_t)(dap_stream_ch_t *a_ch, void *a_arg);
typedef bool (*dap_stream_ch_read_callback_t)(dap_stream_ch_t *a_ch, void *a_arg);
typedef bool (*dap_stream_ch_write_callback_t)(dap_stream_ch_t *a_ch, void *a_arg);
typedef void (*dap_stream_ch_notify_callback_t)(dap_stream_ch_t *a_ch, uint8_t a_type, const void *a_data, size_t a_data_size, void *a_arg);

typedef enum dap_stream_packet_direction {
    DAP_STREAM_PKT_DIR_IN,
    DAP_STREAM_PKT_DIR_OUT
} dap_stream_packet_direction_t;

typedef struct dap_stream_ch_notifier {
    dap_stream_ch_notify_callback_t callback;
    void *arg;
} dap_stream_ch_notifier_t;

typedef struct dap_stream_ch {
    pthread_mutex_t mutex;
    bool ready_to_write;
    bool ready_to_read;
    dap_stream_t * stream;
    dap_stream_ch_uuid_t uuid;
    dap_stream_worker_t * stream_worker;
    struct{
        uint64_t bytes_write;
        uint64_t bytes_read;
    } stat;

    dap_list_t *packet_in_notifiers;
    dap_list_t *packet_out_notifiers;

    dap_dap_stream_ch_proc_t * proc;
    void * internal;
    struct dap_stream_ch *me;
    UT_hash_handle hh_worker;
} dap_stream_ch_t;

typedef struct dap_stream_ch_cachet {
    dap_stream_worker_t *stream_worker;
    dap_stream_ch_uuid_t uuid;
} dap_stream_ch_cachet_t;

int dap_stream_ch_init();
void dap_stream_ch_deinit();

unsigned int dap_new_stream_ch_id();
dap_stream_ch_t* dap_stream_ch_new( dap_stream_t * a_stream, uint8_t a_id);
void dap_stream_ch_set_ready_to_read_unsafe(dap_stream_ch_t * a_ch,bool a_is_ready);
void dap_stream_ch_set_ready_to_write_unsafe(dap_stream_ch_t * a_ch,bool a_is_ready);
void dap_stream_ch_delete(dap_stream_ch_t *a_ch);

dap_stream_ch_t *dap_stream_ch_find_by_uuid_unsafe(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_uuid);
dap_stream_ch_t *dap_stream_ch_by_id_unsafe(dap_stream_t *a_stream, const char a_ch_id);
// MT-safe functions
DAP_STATIC_INLINE bool dap_stream_ch_check_uuid_mt(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid)
{
    return dap_stream_ch_find_by_uuid_unsafe(a_worker, a_ch_uuid);
}

int dap_stream_ch_add_notifier(dap_stream_node_addr_t *a_stream_addr, uint8_t a_ch_id,
                             dap_stream_packet_direction_t a_direction, dap_stream_ch_notify_callback_t a_callback,
                             void *a_callback_arg);
int dap_stream_ch_del_notifier(dap_stream_node_addr_t *a_stream_addr, uint8_t a_ch_id,
                             dap_stream_packet_direction_t a_direction, dap_stream_ch_notify_callback_t a_callback,
                             void *a_callback_arg);

#endif
