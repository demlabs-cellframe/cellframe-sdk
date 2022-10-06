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
#define DAP_MAX_EVENTS_COUNT    8192


#ifdef __cplusplus
extern "C" {
#endif

extern bool g_debug_reactor;

int dap_events_init( uint32_t a_threads_count, size_t a_conn_timeout ); // Init events module
void dap_events_deinit( ); // Deinit events module


int32_t dap_events_start( );
void dap_events_stop_all();
int32_t dap_events_wait();

void dap_worker_print_all( );
uint32_t dap_events_thread_get_index_min( );
uint32_t dap_events_thread_get_count();
dap_worker_t *dap_events_worker_get_auto( );

bool dap_events_workers_init_status();

dap_worker_t * dap_events_worker_get(uint8_t a_index);
uint32_t dap_get_cpu_count();
void dap_cpu_assign_thread_on(uint32_t a_cpu_id);


#ifdef __cplusplus
}
#endif
