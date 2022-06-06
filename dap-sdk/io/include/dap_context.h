/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2022
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
#include <uthash.h>
#include "dap_common.h"
#include "dap_events_socket.h"
#include "dap_proc_queue.h"

typedef struct dap_worker dap_worker_t;
typedef struct dap_proc_thread dap_proc_thread_t;
typedef struct dap_context {
    uint32_t id;  // Context ID

    // Compatibility fields, in future should be replaced with _inheritor
    dap_proc_thread_t * proc_thread; // If the context belongs to proc_thread
    dap_worker_t * worker; // If the context belongs to worker

#if defined DAP_EVENTS_CAPS_MSMQ
    HANDLE msmq_events[MAXIMUM_WAIT_OBJECTS];
#endif

#if defined DAP_EVENTS_CAPS_EPOLL
    EPOLL_HANDLE epoll_fd;
    struct epoll_event epoll_events[ DAP_EVENTS_SOCKET_MAX];
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

    dap_events_socket_t *esockets; // Hashmap of event sockets

    // Signal to exit
    bool signal_exit;

} dap_context_t;

extern pthread_key_t g_dap_context_pth_key;
static inline dap_context_t * dap_context_current(){
    return (dap_context_t*) pthread_getspecific(g_dap_context_pth_key);
}


int dap_context_init(); // Init

// New context create. Thread-safe functions
dap_context_t * dap_context_new();

/// ALL THIS FUNCTIONS ARE UNSAFE ! CALL THEM ONLY INSIDE THEIR OWN CONTEXT!!
int dap_context_thread_init(dap_context_t * a_context);
int dap_context_thread_loop(dap_context_t * a_context);

int dap_context_add_esocket(dap_context_t * a_context, dap_events_socket_t * a_esocket );
int dap_context_poll_update(dap_events_socket_t * a_esocket);
dap_events_socket_t *dap_context_esocket_find_by_uuid(dap_context_t * a_context, dap_events_socket_uuid_t a_es_uuid );
dap_events_socket_t * dap_context_create_esocket_queue(dap_context_t * a_context, dap_events_socket_callback_queue_ptr_t a_callback);
dap_events_socket_t * dap_context_create_esocket_event(dap_context_t * a_context, dap_events_socket_callback_event_t a_callback);
dap_events_socket_t * dap_context_create_esocket_pipe(dap_context_t * a_context, dap_events_socket_callback_t a_callback, uint32_t a_flags);
