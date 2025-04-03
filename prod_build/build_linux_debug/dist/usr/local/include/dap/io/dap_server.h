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

#include <pthread.h>
#include "uthash.h"
#include "utlist.h"
#include "dap_events_socket.h"
#include "dap_list.h"
#include "dap_cpu_monitor.h"

#ifdef DAP_OS_UNIX
#include <sys/un.h>
#endif

#if defined( DAP_OS_LINUX)
#include <netinet/in.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#define EPOLL_HANDLE  int
#elif defined(DAP_OS_WINDOWS)
#elif defined(DAP_OS_BSD)
#else
#error "No poll headers for your platform"
#endif

struct dap_server;
typedef void (*dap_server_callback_t) (struct dap_server*, void*); // Callback for specific server's operations

typedef struct dap_server {
    dap_events_socket_callbacks_t client_callbacks;
    dap_server_callback_t delete_callback;
    dap_cpu_stats_t cpu_stats;
    dap_list_t *es_listeners;
    const char **whitelist, **blacklist;
    void *_inheritor;
    bool ext_log;
} dap_server_t;

int dap_server_init( ); // Init server module
void  dap_server_deinit( void ); // Deinit server module

void dap_server_set_default(dap_server_t* a_server);
dap_server_t* dap_server_get_default();

dap_server_t* dap_server_new(const char *a_cfg_section,
                             dap_events_socket_callbacks_t *a_server_callbacks,
                             dap_events_socket_callbacks_t *a_client_callbacks);
int dap_server_listen_addr_add(dap_server_t *a_server, const char *a_addr, uint16_t a_port, 
                               dap_events_desc_type_t a_type, dap_events_socket_callbacks_t *a_callbacks);
int dap_server_callbacks_set(dap_server_t*, dap_events_socket_callbacks_t*, dap_events_socket_callbacks_t*);
void dap_server_delete(dap_server_t *a_server);
