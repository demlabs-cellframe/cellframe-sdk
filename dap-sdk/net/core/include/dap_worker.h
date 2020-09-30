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
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include "dap_events_socket.h"
#include "dap_timerfd.h"

#include "dap_proc_queue.h"
typedef struct dap_worker
{
    uint32_t id;
    dap_events_t* events;
    dap_proc_queue_t* proc_queue;
    atomic_uint event_sockets_count;
    dap_events_socket_t *esockets; // Hashmap of event sockets

    // Signal to exit
    bool signal_exit;
    // worker control queues
    dap_events_socket_t * queue_es_new; // Events socket for new socket
    dap_events_socket_t * queue_es_delete; // Events socke
    dap_events_socket_t * queue_es_reassign; // Reassign between workers
    dap_events_socket_t * queue_es_io; // Events socket for new socket
    dap_events_socket_t * event_exit; // Events socket for exit

    dap_events_socket_t * queue_callback; // Queue for pure callback on worker

    dap_timerfd_t * timer_check_activity;
#ifdef DAP_EVENTS_CAPS_EPOLL
    EPOLL_HANDLE epoll_fd;
#endif
    pthread_cond_t started_cond;
    pthread_mutex_t started_mutex;
    void * _inheritor;
} dap_worker_t;

// Message for reassigment
typedef struct dap_worker_msg_reassign{
    dap_events_socket_t * esocket;
    dap_worker_t * worker_new;
} dap_worker_msg_reassign_t;

// Message for input/output queue
typedef struct dap_worker_msg_io{
    dap_events_socket_t * esocket;
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

int dap_worker_init( size_t a_conn_timeout );
void dap_worker_deinit();

void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker);
dap_worker_t *dap_worker_add_events_socket_auto( dap_events_socket_t * a_events_socket );
void dap_worker_exec_callback_on(dap_worker_t * a_worker, dap_worker_callback_t a_callback, void * a_arg);

// Thread function
void *dap_worker_thread(void *arg);
