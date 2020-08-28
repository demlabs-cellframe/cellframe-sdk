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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef WIN32
#include <sys/queue.h>
#endif

#include "dap_events_socket.h"
#include "dap_server.h"
#include "uthash.h"

typedef struct dap_udp_server dap_udp_server_t;
struct dap_udp_client;

#define UDP_CLIENT_BUF 65535

typedef struct dap_udp_client {

    dap_events_socket_t *esocket;
    uint64_t host_key; //key contains host address in first 4 bytes and port in last 4 bytes

    UT_hash_handle hh;

    struct dap_udp_client *next, *prev;   //pointers for writing queue
    pthread_mutex_t mutex_on_client;

    void *_inheritor; // Internal data to specific client type, usualy states for state machine

} dap_udp_client_t; // Node of bidirectional list of clients

#define DAP_UDP_CLIENT(a) ((dap_udp_client_t *) (a)->_inheritor)

dap_events_socket_t *dap_udp_client_create( dap_server_t *sh, EPOLL_HANDLE efd, unsigned long host, unsigned short port ); // Create new client and add it to the list
dap_events_socket_t *dap_udp_client_find( dap_server_t *sh, unsigned long host, unsigned short port ); // Find client by host and port

void dap_udp_client_ready_to_read( dap_events_socket_t *sc, bool is_ready );
void dap_udp_client_ready_to_write( dap_events_socket_t *sc, bool is_ready );

size_t dap_udp_client_write_unsafe( dap_events_socket_t *sc, const void * data, size_t data_size );
size_t dap_udp_client_write_f( dap_events_socket_t *a_client, const char * a_format, ... );

void add_waiting_client( dap_events_socket_t *client ); // Add client to writing queue

void dap_udp_client_get_address( dap_events_socket_t *client, unsigned int *host, unsigned short *port );
