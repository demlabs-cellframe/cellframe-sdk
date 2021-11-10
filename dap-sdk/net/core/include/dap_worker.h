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

#include "dap_events_socket.h"
#include <pthread.h>
#include "dap_common.h"



typedef struct dap_proc_queue dap_proc_queue_t;
typedef struct dap_timerfd dap_timerfd_t;
typedef struct dap_worker
{
    uint32_t id;
    dap_events_t* events;
    dap_proc_queue_t* proc_queue;
    dap_events_socket_t *proc_queue_input;

    atomic_uint event_sockets_count;
    pthread_rwlock_t esocket_rwlock;
    dap_events_socket_t *esockets; // Hashmap of event sockets

    // Signal to exit
    bool signal_exit;

    // worker control queues
    dap_events_socket_t * queue_es_new; // Queue socket for new socket
    dap_events_socket_t ** queue_es_new_input; // Queue socket for new socket

    dap_events_socket_t * queue_es_delete; // Queue socke
    dap_events_socket_t ** queue_es_delete_input; // Queue socke

    dap_events_socket_t * queue_es_reassign; // Queue for reassign between workers
    dap_events_socket_t ** queue_es_reassign_input; // Queue for reassign between workers

    dap_events_socket_t * queue_es_io; // Queue socket for io ops
    dap_events_socket_t ** queue_es_io_input; // Queue socket for io ops between workers

    dap_events_socket_t * event_exit; // Events socket for exit

    dap_events_socket_t * queue_callback; // Queue for pure callback on worker

    dap_timerfd_t * timer_check_activity;
#if defined DAP_EVENTS_CAPS_MSMQ
    HANDLE msmq_events[MAXIMUM_WAIT_OBJECTS];
#endif

#if defined DAP_EVENTS_CAPS_EPOLL
    EPOLL_HANDLE epoll_fd;
#elif defined ( DAP_EVENTS_CAPS_POLL)
    int poll_fd;
    struct pollfd * poll;
    dap_events_socket_t ** poll_esocket;
    atomic_uint poll_count;
    size_t poll_count_max;
    bool poll_compress; // Some of fd's became NULL so arrays need to be reassigned
#elif defined (DAP_EVENTS_CAPS_KQUEUE)
    int kqueue_fd;
    struct kevent * kqueue_events_selected;
    struct kevent * kqueue_events;
    size_t kqueue_events_count;

    int kqueue_events_count_max;
    int kqueue_events_selected_count_max;
#else
#error "Not defined worker for your platform"
#endif
    pthread_cond_t started_cond;
    pthread_mutex_t started_mutex;
    void * _inheritor;
} dap_worker_t;

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


#ifdef __cplusplus
extern "C" {
#endif

int dap_worker_init( size_t a_conn_timeout );
void dap_worker_deinit();

int dap_worker_add_events_socket_unsafe( dap_events_socket_t * a_esocket, dap_worker_t * a_worker);
void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker);
void dap_worker_add_events_socket_inter(dap_events_socket_t * a_es_input, dap_events_socket_t * a_events_socket);
dap_worker_t *dap_worker_add_events_socket_auto( dap_events_socket_t * a_events_socket );
void dap_worker_exec_callback_on(dap_worker_t * a_worker, dap_worker_callback_t a_callback, void * a_arg);

bool dap_worker_check_esocket_polled_now(); // Check if esocket is right now polled and present in list
// Thread function
void *dap_worker_thread(void *arg);


#ifdef __cplusplus
}
#endif
