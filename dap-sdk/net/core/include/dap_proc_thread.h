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

#ifndef _DAP_PROC_THREAD_
#define _DAP_PROC_THREAD_

#pragma once

#include <pthread.h>
#include <stdatomic.h>
#include "dap_common.h"
#include "dap_proc_queue.h"

#include <assert.h>
#include "dap_server.h"

#if defined(DAP_EVENTS_CAPS_EPOLL)
#include <sys/epoll.h>
#elif defined (DAP_EVENTS_CAPS_POLL)
#include <sys/poll.h>
#else
#error "Unimplemented poll for this platform"
#endif

#include "dap_events.h"
#include "dap_events_socket.h"


typedef struct dap_proc_thread{
    uint32_t cpu_id;
    pthread_t thread_id;
    dap_proc_queue_t * proc_queue;
    dap_events_socket_t * proc_event; // Should be armed if we have to deal with it
    atomic_uint proc_queue_size;

    pthread_cond_t started_cond;
    pthread_mutex_t started_mutex;

    bool signal_kill;

#ifdef DAP_EVENTS_CAPS_EPOLL
    EPOLL_HANDLE epoll_ctl;
#elif defined (DAP_EVENTS_CAPS_POLL)
    int poll_fd;
#else
#error "No poll for proc thread for your platform"
#endif
} dap_proc_thread_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_proc_thread_init(uint32_t a_threads_count);
dap_proc_thread_t * dap_proc_thread_get(uint32_t a_thread_number);
dap_proc_thread_t * dap_proc_thread_get_auto();

#ifdef __cplusplus
}
#endif

#endif
