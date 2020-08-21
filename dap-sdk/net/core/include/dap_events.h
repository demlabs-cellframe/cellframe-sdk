/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#ifndef WIN32
#include <netinet/in.h>

#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/eventfd.h>
#define EPOLL_HANDLE  int
#else
#define EPOLL_HANDLE  HANDLE
#endif

#include "uthash.h"
#include "dap_events_socket.h"
#include "dap_server.h"

struct dap_events;

typedef void (*dap_events_callback_t) (struct dap_events *, void *arg); // Callback for specific server's operations

typedef struct dap_thread {
  pthread_t tid;
} dap_thread_t;

struct dap_worker;

typedef struct dap_events {

  dap_events_socket_t *sockets; // Hashmap of event sockets
  pthread_rwlock_t sockets_rwlock;
  void *_inheritor;  // Pointer to the internal data, HTTP for example
  dap_thread_t proc_thread;
  pthread_rwlock_t servers_rwlock;

} dap_events_t;

typedef struct dap_worker
{
  atomic_uint event_sockets_count;

  dap_events_socket_t * event_new_es; // Events socket for new socket
  dap_events_socket_t * event_delete_es; // Events socket for new socket
  EPOLL_HANDLE epoll_fd;
  uint32_t number_thread;
  pthread_mutex_t locker_on_count;
  dap_events_t *events;

} dap_worker_t;

int32_t  dap_events_init( uint32_t a_threads_count, size_t conn_t ); // Init server module
void dap_events_deinit( ); // Deinit server module

void dap_events_thread_wake_up( dap_thread_t *th );
dap_events_t* dap_events_new( );
void dap_events_delete( dap_events_t * sh );

int32_t dap_events_start( dap_events_t *sh );
void dap_events_stop();
int32_t dap_events_wait( dap_events_t *sh );

uint32_t dap_worker_get_index_min( );
dap_worker_t *dap_worker_get_min( );

uint32_t dap_get_cpu_count( );
dap_worker_t * dap_worker_get_index(uint8_t a_index);

void dap_events_socket_assign_on_worker(dap_events_socket_t * a_es, struct dap_worker * a_worker);
void dap_worker_add_events_socket(dap_events_socket_t * a_events_socket, dap_worker_t * a_worker);
void dap_worker_add_events_socket_auto( dap_events_socket_t * a_events_socket );
void dap_worker_print_all( );

