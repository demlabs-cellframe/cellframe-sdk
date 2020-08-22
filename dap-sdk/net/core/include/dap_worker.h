/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2017
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

typedef struct dap_worker
{
    uint32_t id;
    atomic_uint event_sockets_count;

    dap_events_socket_t * event_new_es; // Events socket for new socket
    dap_events_socket_t * event_delete_es; // Events socket for new socket
    EPOLL_HANDLE epoll_fd;
    dap_events_t *events;

    pthread_cond_t started_cond;
    pthread_mutex_t started_mutex;
} dap_worker_t;

int dap_worker_init( size_t a_conn_timeout );
void dap_worker_deinit();

void dap_events_socket_assign_on_worker(dap_events_socket_t * a_es, struct dap_worker * a_worker);
void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker);
void dap_worker_add_events_socket_auto( dap_events_socket_t * a_events_socket );

// Thread function
void *dap_worker_thread(void *arg);
