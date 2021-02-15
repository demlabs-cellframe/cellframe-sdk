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

#include "dap_common.h"

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

#define EPOLL_HANDLE  HANDLE
#define MSG_DONTWAIT 0
#define MSG_NOSIGNAL 0
#include "winsock.h"
#elif defined(DAP_OS_BSD)

#else
#error "No poll headers for your platform"
#endif

#include <pthread.h>
#include "uthash.h"
#include "utlist.h"

#include "dap_list.h"
#include "dap_cpu_monitor.h"
#include "dap_events_socket.h"

typedef enum dap_server_type {SERVER_TCP, SERVER_UDP,SERVER_LOCAL} dap_server_type_t;



struct dap_server;

typedef void (*dap_server_callback_t)( struct dap_server *,void * arg ); // Callback for specific server's operations

typedef struct dap_server {

  dap_server_type_t type; // Server's type
  uint16_t port; // Listen port
  char *address; // Listen address
#ifdef DAP_OS_WINDOWS
  SOCKET socket_listener;
#else
  int32_t socket_listener; // Socket for listener
#endif
  dap_list_t *es_listeners;

  dap_events_t * events;

  struct sockaddr_in listener_addr; // Kernel structure for listener's binded address

#ifdef DAP_OS_UNIX
  struct sockaddr_un listener_path; // Path to UNIX socket
#endif

  void *_inheritor;  // Pointer to the internal data, HTTP for example

  dap_cpu_stats_t cpu_stats;

  dap_server_callback_t delete_callback;

  dap_events_socket_callbacks_t client_callbacks; // Callbacks for the new clients

  pthread_cond_t started_cond; // Condition for initialized socket
  pthread_mutex_t started_mutex; // Mutex for shared operation between mirrored sockets
} dap_server_t;

int dap_server_init( ); // Init server module
void  dap_server_deinit( void ); // Deinit server module

dap_server_t* dap_server_new(dap_events_t *a_events, const char * a_addr, uint16_t a_port, dap_server_type_t a_type, dap_events_socket_callbacks_t *a_callbacks);
dap_server_t* dap_server_new_local(dap_events_t *a_events, const char * a_path, const char * a_mode, dap_events_socket_callbacks_t *a_callbacks);

void dap_server_delete(dap_server_t *a_server);
