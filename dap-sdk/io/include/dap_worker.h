/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2020
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <pthread.h>
#include <stdatomic.h>
#include "dap_events_socket.h"
#include "dap_proc_queue.h"
#include "dap_common.h"
#include "dap_events.h"
#include "dap_context.h"

//typedef struct dap_proc_queue dap_proc_queue_t;
typedef struct dap_timerfd dap_timerfd_t;
typedef struct dap_worker
{
    uint32_t  id;
    dap_proc_queue_t* proc_queue;
    dap_events_socket_t *proc_queue_input;

    // worker control queues
    dap_events_socket_t *queue_es_new; // Queue socket for new socket
    dap_events_socket_t **queue_es_new_input; // Queue socket for new socket

    dap_events_socket_t *queue_es_delete; // Queue socke
    dap_events_socket_t **queue_es_delete_input; // Queue socke

    dap_events_socket_t *queue_es_reassign; // Queue for reassign between workers
    dap_events_socket_t **queue_es_reassign_input; // Queue for reassign between workers

    dap_events_socket_t *queue_es_io; // Queue socket for io ops
    dap_events_socket_t **queue_es_io_input; // Queue socket for io ops between workers

    dap_events_socket_t *queue_callback;                                    /* Queue for pure callback on worker */

    dap_events_socket_t *queue_gdb_input;                                   /* Inputs for request to GDB, @RRL: #6238 */

    dap_timerfd_t * timer_check_activity;

    dap_context_t *context;
    void * _inheritor;
} dap_worker_t;

#define DAP_CONTEXT_TYPE_WORKER   10

// Message for reassigment
typedef struct dap_worker_msg_reassign{
    dap_events_socket_t * esocket;
    dap_events_socket_uuid_t esocket_uuid;
    dap_worker_t * worker_new;
} dap_worker_msg_reassign_t;

// Message for input/output queue
typedef struct dap_worker_msg_io{
    dap_events_socket_uuid_t esocket_uuid;
    size_t data_size;
    void *data;
    uint32_t flags_set;
    uint32_t flags_unset;
} dap_worker_msg_io_t;

// Message for callback execution
typedef void (*dap_worker_callback_t)(dap_worker_t *,void *);
typedef struct dap_worker_msg_callback{
    dap_worker_callback_t callback; // Callback for specific client operations
    void * arg;
} dap_worker_msg_callback_t;


extern pthread_key_t g_pth_key_worker;

#ifdef __cplusplus
extern "C" {
#endif

int dap_worker_init( size_t a_conn_timeout );
void dap_worker_deinit();

static inline dap_worker_t * dap_worker_get_current(){
    return (dap_worker_t*) pthread_getspecific(g_pth_key_worker);
}

static inline int dap_worker_add_events_socket_unsafe(dap_worker_t *a_worker, dap_events_socket_t *a_esocket)
{
    int err = dap_context_add(a_worker->context, a_esocket);
    if (!err)
        a_esocket->is_initalized = true;
    return err;
}

void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker);
void dap_worker_add_events_socket_inter(dap_events_socket_t * a_es_input, dap_events_socket_t * a_events_socket);
dap_worker_t *dap_worker_add_events_socket_auto( dap_events_socket_t * a_events_socket );
void dap_worker_exec_callback_on(dap_worker_t * a_worker, dap_worker_callback_t a_callback, void * a_arg);
void dap_worker_exec_callback_inter(dap_events_socket_t * a_es_input, dap_worker_callback_t a_callback, void * a_arg);

bool dap_worker_check_esocket_polled_now(); // Check if esocket is right now polled and present in list
// Context callbacks
void dap_worker_context_callback_started( dap_context_t * a_context, void *a_arg);
void dap_worker_context_callback_stopped( dap_context_t * a_context, void *a_arg);


#ifdef __cplusplus
}
#endif
