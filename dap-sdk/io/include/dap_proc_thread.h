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
#include "dap_proc_queue.h"
#include "dap_worker.h"
#include "dap_common.h"
#include "dap_context.h"
typedef struct dap_proc_thread{

    dap_proc_queue_t *proc_queue;                                           /* Queues  */
    atomic_uint proc_queue_size;                                            /* Thread's load factor - is not supported at the moment  */

    dap_events_socket_t * proc_event;                                       /* Should be armed if we have to deal with it */

    dap_events_socket_t ** queue_assign_input;                              /* Inputs for assign queues */
    dap_events_socket_t ** queue_io_input;                                  /* Inputs for assign queues */
    dap_events_socket_t ** queue_callback_input;                            /* Inputs for worker context callback queues */

    dap_events_socket_t *queue_gdb_input;                                   /* Inputs for request to GDB, @RRL: #6238 */

    dap_context_t * context;

    void * _inheritor;
} dap_proc_thread_t;
#define DAP_CONTEXT_TYPE_PROC_THREAD 1

int dap_proc_thread_init(uint32_t a_threads_count);
void dap_proc_thread_deinit();


dap_proc_thread_t *dap_proc_thread_get(uint32_t a_thread_number);
dap_proc_thread_t *dap_proc_thread_get_auto();
dap_events_socket_t *dap_proc_thread_create_queue_ptr(dap_proc_thread_t * a_thread, dap_events_socket_callback_queue_ptr_t a_callback);

bool dap_proc_thread_assign_on_worker_inter(dap_proc_thread_t * a_thread, dap_worker_t * a_worker, dap_events_socket_t *a_esocket  );

int dap_proc_thread_esocket_write_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_events_socket_uuid_t a_es_uuid,
                                        const void * a_data, size_t a_data_size);
int dap_proc_thread_esocket_write_f_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_events_socket_uuid_t a_es_uuid,
                                        const char * a_format,...);

typedef void (*dap_proc_worker_callback_t)(dap_worker_t *,void *);

void dap_proc_thread_worker_exec_callback_inter(dap_proc_thread_t * a_thread, size_t a_worker_id, dap_proc_worker_callback_t a_callback, void * a_arg);

int dap_proc_thread_assign_esocket_unsafe(dap_proc_thread_t * a_thread, dap_events_socket_t * a_esocket);


#define dap_proc_thread_esocket_update_poll_flags(a, b) dap_context_poll_update(b)
