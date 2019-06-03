/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#ifndef _WIN32
#include <netinet/in.h>

#include <stdint.h>
#include <pthread.h>

#include <sys/epoll.h>
#include <sys/timerfd.h>
#define EPOLL_HANDLE  int
#else
#define EPOLL_HANDLE  HANDLE
#endif

#include "uthash.h"
#include "utlist.h"

#include "dap_cpu_monitor.h"
#include "dap_client_remote.h"

typedef enum dap_server_type {DAP_SERVER_TCP} dap_server_type_t;

typedef struct dap_server_thread_s {

  EPOLL_HANDLE epoll_fd;
  uint32_t thread_num;
  uint32_t connections_count;

  struct epoll_event  *epoll_events;
  dap_client_remote_t *dap_remote_clients;

  pthread_mutex_t mutex_dlist_add_remove;

} dap_server_thread_t;

struct dap_server;

typedef void (*dap_server_callback_t)( struct dap_server *,void * arg ); // Callback for specific server's operations

typedef struct dap_server {

  dap_server_type_t type; // Server's type
  uint16_t port; // Listen port
  char *address; // Listen address

  dap_client_remote_t *clients; // Hashmap of clients

  int32_t socket_listener; // Socket for listener
  EPOLL_HANDLE epoll_fd; // Epoll fd

  struct sockaddr_in listener_addr; // Kernel structure for listener's binded address

  void *_inheritor;  // Pointer to the internal data, HTTP for example

  pthread_mutex_t mutex_on_hash;
  dap_cpu_stats_t cpu_stats;

  dap_server_callback_t server_delete_callback;

  dap_server_client_callback_t client_new_callback; // Create new client callback
  dap_server_client_callback_t client_delete_callback; // Delete client callback
  dap_server_client_callback_t client_read_callback; // Read function
  dap_server_client_callback_t client_write_callback; // Write function
  dap_server_client_callback_t client_error_callback; // Error processing function

} dap_server_t;

int32_t dap_server_init( uint32_t count_threads ); // Init server module
void    dap_server_deinit( void ); // Deinit server module

dap_server_t *dap_server_listen( const char *addr, uint16_t port, dap_server_type_t type );

int32_t dap_server_loop( dap_server_t *d_server );
