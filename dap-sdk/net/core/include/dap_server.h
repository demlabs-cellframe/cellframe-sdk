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

#ifndef _WIN32
#include <netinet/in.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#define EPOLL_HANDLE  int
#else
#define EPOLL_HANDLE  HANDLE
#define MSG_DONTWAIT 0
#define MSG_NOSIGNAL 0
#include "winsock.h"
#include "wepoll.h"
#endif

#include <pthread.h>
#include "uthash.h"
#include "utlist.h"

#include "dap_cpu_monitor.h"
#include "dap_events_socket.h"

typedef enum dap_server_type {DAP_SERVER_TCP} dap_server_type_t;

#define BIT( x ) ( 1 << x )

#define DAP_SOCK_READY_TO_READ     BIT( 0 )
#define DAP_SOCK_READY_TO_WRITE    BIT( 1 )
#define DAP_SOCK_SIGNAL_CLOSE      BIT( 2 )
#define DAP_SOCK_ACTIVE            BIT( 3 )

struct dap_server;

typedef void (*dap_server_callback_t)( struct dap_server *,void * arg ); // Callback for specific server's operations

typedef struct dap_server {

  dap_server_type_t type; // Server's type
  uint16_t port; // Listen port
  char *address; // Listen address

  int32_t socket_listener; // Socket for listener
  dap_events_socket_t * es_listener;

  struct sockaddr_in listener_addr; // Kernel structure for listener's binded address

  void *_inheritor;  // Pointer to the internal data, HTTP for example

  dap_cpu_stats_t cpu_stats;

  dap_server_callback_t delete_callback;

  dap_events_socket_callbacks_t client_callbacks; // Callbacks for the new clients
} dap_server_t;

int dap_server_init( ); // Init server module
void  dap_server_deinit( void ); // Deinit server module

dap_server_t* dap_server_new(dap_events_t *a_events, const char * a_addr, uint16_t a_port, dap_server_type_t a_type);
dap_events_socket_t * dap_server_events_socket_new(dap_events_t * a_events, int a_sock,
                                             dap_events_socket_callbacks_t * a_callbacks, dap_server_t * a_server);
