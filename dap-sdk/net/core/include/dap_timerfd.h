/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
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
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#if defined DAP_OS_LINUX
#include <sys/time.h>
#include <sys/timerfd.h>
#elif defined DAP_OS_BSD
#include <sys/event.h>
#elif defined DAP_OS_WINDOWS
#define _MSEC -10000
#endif

#include "dap_common.h"
#include "dap_events_socket.h"
#include "dap_proc_thread.h"

typedef bool (*dap_timerfd_callback_t)(void* ); // Callback for timer. If return true,
                                                // it will be called after next timeout

typedef struct dap_timerfd {
    uint64_t timeout_ms;
#ifdef DAP_OS_WINDOWS
	SOCKET tfd;
    u_short port;
#elif defined(DAP_OS_LINUX)
    int tfd; //timer file descriptor
#endif
    dap_events_socket_t *events_socket;
    dap_timerfd_callback_t callback;
    void *callback_arg;
#ifdef DAP_OS_WINDOWS
    HANDLE th;
    SOCKET pipe_in;
#endif
} dap_timerfd_t;

int dap_timerfd_init();
dap_timerfd_t* dap_timerfd_create(uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg);
dap_timerfd_t* dap_timerfd_start(uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *callback_arg);
dap_timerfd_t* dap_timerfd_start_on_worker(dap_worker_t * a_worker, uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg);
dap_timerfd_t* dap_timerfd_start_on_proc_thread(dap_proc_thread_t * a_proc_thread, uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg);
void dap_timerfd_delete(dap_timerfd_t *l_timerfd);

