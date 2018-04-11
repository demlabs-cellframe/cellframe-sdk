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
#include <ev.h>


typedef struct dap_udp_server dap_udp_server_t;
struct dap_udp_client;

typedef void (*dap_udp_client_callback_t) (struct udp_client *,void * arg); // Callback for specific client operations

#define UDP_CLIENT_BUF 100000

typedef struct dap_udp_client{
    bool signal_close;

    bool _ready_to_write;
    bool _ready_to_read;

    uint32_t buf_out_zero_count;
    char buf_in[UDP_CLIENT_BUF+1]; // Internal buffer for input data
    size_t buf_in_size; // size of data that is in the input buffer

    char buf_out[UDP_CLIENT_BUF+1]; // Internal buffer for output data
    size_t buf_out_size; // size of data that is in the output buffer

    uint64_t host_key; //key contains host address in first 4 bytes and port in last 4 bytes

    ev_io* watcher_client;

    struct dap_udp_server * server;

    UT_hash_handle hh;
    struct dap_udp_client *next, *prev;   //pointers for writing queue

    void * _inheritor; // Internal data to specific client type, usualy states for state machine
} dap_udp_client_t; // Node of bidirectional list of clients



int dap_udp_client_init(); //  Init clients module
void dap_udp_client_deinit(); // Deinit clients module

dap_udp_client_t * dap_udp_client_create(dap_udp_server_t * sh, ev_io* w_client, unsigned long host, unsigned short port); // Create new client and add it to the list
dap_udp_client_t * dap_udp_client_find(dap_udp_server_t * sh, unsigned long host, unsigned short port); // Find client by host and port

void dap_udp_client_ready_to_read(dap_udp_client_t * sc,bool is_ready);
void dap_udp_client_ready_to_write(dap_udp_client_t * sc,bool is_ready);

size_t dap_udp_client_write(dap_udp_client_t *sc, const void * data, size_t data_size);
size_t dap_udp_client_write_f(dap_udp_client_t *a_client, const char * a_format,...);
size_t dap_udp_client_read(dap_udp_client_t *sc, void * data, size_t data_size);

void add_waiting_client(dap_udp_client_t* client); // Add client to writing queue

void dap_udp_client_remove(dap_udp_client_t *sc, dap_udp_server_t * sh); // Removes the client from the hash-table

void dap_udp_client_shrink_buf_in(dap_udp_client_t * cl, size_t shrink_size);

#endif