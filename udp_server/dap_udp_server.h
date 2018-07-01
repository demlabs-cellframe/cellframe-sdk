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
#include "../../libdap-server/core_server/dap_server.h"
#include "dap_client_remote.h"

struct dap_udp_server;

typedef struct dap_udp_thread{
    pthread_t tid;
} dap_udp_thread_t;

typedef void (*dap_udp_server_callback_t) (struct dap_udp_server *,void * arg); // Callback for specific server's operations

typedef struct dap_udp_server{
    dap_udp_client_t * clients;
    dap_udp_client_t * waiting_clients; // List clients for writing data
    pthread_mutex_t mutex_on_list;
    void* _inheritor;
    dap_server_t* dap_server;
} dap_udp_server_t;

#define DAP_UDP_SERVER(a) ((dap_udp_server_t *) (a)->_inheritor)

extern void dap_udp_server_delete(dap_server_t * sh); 

extern void dap_udp_server_loop(dap_server_t* udp_server);      // Start server event loop

extern dap_server_t* dap_udp_server_listen(uint16_t port);      // Create and bind server

#endif


