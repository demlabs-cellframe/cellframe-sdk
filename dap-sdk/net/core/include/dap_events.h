/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2020
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
#include <pthread.h>
#include "uthash.h"
#include "dap_events_socket.h"
#include "dap_server.h"
#include "dap_worker.h"
struct dap_events;
#define DAP_MAX_EVENTS_COUNT    8192

typedef void (*dap_events_callback_t) (struct dap_events *, void *arg); // Callback for specific server's operations

typedef struct dap_thread {
  pthread_t tid;
} dap_thread_t;

typedef struct dap_events {
    pthread_key_t pth_key_worker;
    void *_inheritor;  // Pointer to the internal data, HTTP for example
    dap_thread_t proc_thread;
} dap_events_t;


#ifdef __cplusplus
extern "C" {
#endif

extern bool g_debug_reactor;

int dap_events_init( uint32_t a_threads_count, size_t a_conn_timeout ); // Init server module
void dap_events_deinit( ); // Deinit server module

dap_events_t* dap_events_new( );
dap_events_t* dap_events_get_default( );
void dap_events_delete( dap_events_t * a_events );
void dap_events_remove_and_delete_socket_unsafe(dap_events_t*, dap_events_socket_t*, bool);

int32_t dap_events_start( dap_events_t *a_events );
void dap_events_stop_all();
int32_t dap_events_wait( dap_events_t *a_events );

void dap_events_worker_print_all( );
uint32_t dap_events_worker_get_index_min( );
uint32_t dap_events_worker_get_count();
dap_worker_t *dap_events_worker_get_auto( );

dap_worker_t * dap_events_worker_get(uint8_t a_index);
uint32_t dap_get_cpu_count();
void dap_cpu_assign_thread_on(uint32_t a_cpu_id);

static inline dap_worker_t * dap_events_get_current_worker(dap_events_t * a_events){
    return (dap_worker_t*) pthread_getspecific(a_events->pth_key_worker);
}

#ifdef __cplusplus
}
#endif
