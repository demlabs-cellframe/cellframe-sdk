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
#include <sys/time.h>
#include <sys/timerfd.h>
#include <inttypes.h>

#include "dap_common.h"
#include "dap_events_socket.h"

typedef bool (*dap_timerfd_callback_t)(void* ); // Callback for timer

typedef struct dap_timerfd {
    uint64_t timeout_ms;
    int tfd; //timer file descriptor
    dap_events_socket_t *events_socket;
    dap_timerfd_callback_t callback;
    void *callback_arg;
} dap_timerfd_t;

int dap_timerfd_init();
dap_timerfd_t* dap_timerfd_start(uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *callback_arg);
dap_timerfd_t* dap_timerfd_start_on_worker(dap_worker_t * a_worker, uint64_t a_timeout_ms, dap_timerfd_callback_t a_callback, void *a_callback_arg);
void dap_timerfd_delete(dap_timerfd_t *l_timerfd);

