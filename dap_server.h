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

#ifndef _DAP_SERVER_H_
#define _DAP_SERVER_H_

#include <netinet/in.h>

#include <stdint.h>
#include <pthread.h>
#include "uthash.h"

#include "dap_server_client.h"

typedef enum dap_server_type {DAP_SERVER_TCP} dap_server_type_t;

struct dap_server;

typedef void (*dap_server_callback_t) (struct dap_server *,void * arg); // Callback for specific server's operations

typedef struct dap_thread{
    pthread_t tid;
} dap_thread_t;

typedef struct dap_server{
    dap_server_type_t type; // Server's type
    uint16_t port; // Listen port
    char * address; // Listen address

    dap_server_client_t * clients; // Hashmap of clients

    int socket_listener; // Socket for listener
    int epoll_fd; // Epoll fd

    struct sockaddr_in listener_addr; // Kernel structure for listener's binded address

    void * _inheritor;  // Pointer to the internal data, HTTP for example

    dap_thread_t proc_thread;
    pthread_mutex_t mutex_on_hash;

    dap_server_callback_t server_delete_callback;

    dap_client_remote_callback_t client_new_callback; // Create new client callback
    dap_client_remote_callback_t client_delete_callback; // Delete client callback
    dap_client_remote_callback_t client_read_callback; // Read function
    dap_client_remote_callback_t client_write_callback; // Write function
    dap_client_remote_callback_t client_error_callback; // Error processing function

} dap_server_t;

extern int dap_server_init(size_t count_threads); // Init server module
extern void dap_server_deinit(void); // Deinit server module

extern dap_server_t* dap_server_listen(const char * addr, uint16_t port, dap_server_type_t type);

extern int dap_server_loop(dap_server_t * sh);

#endif
