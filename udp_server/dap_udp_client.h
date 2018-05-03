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
#ifndef _UDP_CLIENT_H
#define _UDP_CLIENT_H

#include <sys/queue.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/queue.h>
#include "uthash.h"
#include "dap_client_remote.h"
#include <ev.h>


typedef struct dap_udp_server dap_udp_server_t;
struct dap_udp_client;

#define UDP_CLIENT_BUF 100000

typedef struct dap_udp_client{
    dap_client_remote_t* client;
    uint64_t host_key; //key contains host address in first 4 bytes and port in last 4 bytes

    UT_hash_handle hh;
    struct dap_udp_client *next, *prev;   //pointers for writing queue
    pthread_mutex_t mutex_on_client;

    void * _inheritor; // Internal data to specific client type, usualy states for state machine
} dap_udp_client_t; // Node of bidirectional list of clients

#define DAP_UDP_CLIENT(a) ((dap_udp_client_t *) (a)->_inheritor)


dap_client_remote_t * dap_udp_client_create(dap_server_t * sh, ev_io* w_client, unsigned long host, unsigned short port); // Create new client and add it to the list
dap_client_remote_t * dap_udp_client_find(dap_server_t * sh, unsigned long host, unsigned short port); // Find client by host and port

void dap_udp_client_ready_to_read(dap_client_remote_t * sc,bool is_ready);
void dap_udp_client_ready_to_write(dap_client_remote_t * sc,bool is_ready);

size_t dap_udp_client_write(dap_client_remote_t *sc, const void * data, size_t data_size);
size_t dap_udp_client_write_f(dap_client_remote_t *a_client, const char * a_format,...);

void add_waiting_client(dap_client_remote_t* client); // Add client to writing queue


#endif