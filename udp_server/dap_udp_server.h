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
#ifndef _UDP_SERVER_H_
#define _UDP_SERVER_H_

#include <stdint.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/queue.h>
#include "dap_udp_client.h"

struct dap_udp_server;

typedef struct dap_udp_thread{
    pthread_t tid;
} dap_udp_thread_t;

typedef void (*dap_udp_server_callback_t) (struct dap_udp_server *,void * arg); // Callback for specific server's operations

typedef struct dap_udp_server{
    uint16_t port; // Listen port
    char * address; // Listen address

    dap_udp_client_t * clients; // Hashmap of clients
    dap_udp_client_t * waiting_clients; // List clients for writing data

    int socket_listener; // Socket for listener
    int epoll_fd; // Epoll fd

    struct sockaddr_in listener_addr; // Kernel structure for listener's binded address

    void * _inheritor;  // Pointer to the internal data, HTTP for example

    dap_udp_thread_t proc_thread;
    pthread_mutex_t mutex_on_hash; 

    dap_udp_server_callback_t server_delete_callback;

    dap_udp_client_callback_t client_new_callback; // Create new client callback
    dap_udp_client_callback_t client_delete_callback; // Delete client callback
    dap_udp_client_callback_t client_read_callback; // Read function
    dap_udp_client_callback_t client_write_callback; // Write function
    dap_udp_client_callback_t client_error_callback; // Error processing function

} dap_udp_server_t;

extern int dap_udp_server_init(); // Init server module

extern void dap_udp_server_deinit(); // Deinit server module

extern void dap_udp_server_delete(dap_udp_server_t * sh); 

extern void dap_udp_server_loop(dap_udp_server_t* udp_server);      // Start server event loop

extern dap_udp_server_t* dap_udp_server_listen(uint16_t port);      // Create and bind server

#endif


