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
#include "dap_common.h"
#include "dap_proc_queue.h"

typedef struct dap_proc_thread{
    uint32_t cpu_id;
    pthread_t thread_id;
    dap_proc_queue_t * proc_queue;
    dap_events_socket_t * proc_event; // Should be armed if we have to deal with it

    dap_events_socket_t ** queue_assign_input; // Inputs for assign queues
    dap_events_socket_t ** queue_io_input; // Inputs for assign queues
    atomic_uint proc_queue_size;

    pthread_cond_t started_cond;
    pthread_mutex_t started_mutex;

    bool signal_kill;

#ifdef DAP_EVENTS_CAPS_EPOLL
    EPOLL_HANDLE epoll_ctl;
    struct epoll_event epoll_events[DAP_EVENTS_SOCKET_MAX];
#elif defined (DAP_EVENTS_CAPS_POLL)
    int poll_fd;
    struct pollfd * poll;
    dap_events_socket_t ** esockets;
    size_t poll_count;
    size_t poll_count_max;
#else
#error "No poll for proc thread for your platform"
#endif
} dap_proc_thread_t;

int dap_proc_thread_init(uint32_t a_threads_count);
dap_proc_thread_t * dap_proc_thread_get(uint32_t a_thread_number);
dap_proc_thread_t * dap_proc_thread_get_auto();
bool dap_proc_thread_assign_on_worker_inter(dap_proc_thread_t * a_thread, dap_worker_t * a_worker, dap_events_socket_t *a_esocket  );
int dap_proc_thread_esocket_write_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_events_socket_t *a_esocket,
                                        const void * a_data, size_t a_data_size);
int dap_proc_thread_esocket_write_f_inter(dap_proc_thread_t * a_thread,dap_worker_t * a_worker,  dap_events_socket_t *a_esocket,
                                        const char * a_format,...);
