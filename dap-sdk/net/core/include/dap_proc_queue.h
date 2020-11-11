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

#ifndef _DAP_APROC_QUEUE_
#define _DAP_APROC_QUEUE_

#pragma once

#include "dap_events_socket.h"
#include "dap_worker.h"
#include "dap_proc_thread.h"

typedef struct dap_proc_thread dap_proc_thread_t;

typedef bool (*dap_proc_queue_callback_t)(dap_proc_thread_t*,void* ); // Callback for processor. Returns true if we want to continue running

typedef struct dap_proc_queue_item{
    dap_proc_queue_callback_t callback;
    void *callback_arg;
    struct dap_proc_queue_item * next;
} dap_proc_queue_item_t;

typedef struct dap_proc_queue{
    dap_proc_thread_t * proc_thread;
    dap_events_socket_t *esocket;
    dap_proc_queue_item_t * items;
} dap_proc_queue_t;

#ifdef __cplusplus
extern "C" {
#endif

dap_proc_queue_t * dap_proc_queue_create(dap_proc_thread_t * a_thread);

void dap_proc_queue_delete(dap_proc_queue_t * a_queue);
void dap_proc_queue_add_callback(dap_worker_t * a_worker, dap_proc_queue_callback_t a_callback, void * a_callback_arg);

#ifdef __cplusplus
}
#endif

#endif
