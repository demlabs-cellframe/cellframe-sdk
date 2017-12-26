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

#ifndef _DAP_CLIENT_H
#define _DAP_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "uthash.h"
#include <ev.h>


struct dap_server;
struct dap_client;

typedef void (*dap_client_callback_t) (struct dap_client *,void * arg); // Callback for specific client operations

#define DAP_CLIENT_BUF 100000

typedef struct dap_client{
    int socket;
    bool signal_close;

    bool _ready_to_write;
    bool _ready_to_read;

    uint32_t buf_out_zero_count;
    char buf_in[DAP_CLIENT_BUF+1]; // Internal buffer for input data
    size_t buf_in_size; // size of data that is in the input buffer

    char buf_out[DAP_CLIENT_BUF+1]; // Internal buffer for output data

    char hostaddr[1024]; // Address
    char service[128];

    size_t buf_out_size; // size of data that is in the output buffer

    ev_io* watcher_client;

    struct dap_server * server;

    UT_hash_handle hh;

    void * internal; // Internal data to specific client type, usualy states for state machine
} dap_client_t; // Node of bidirectional list of clients



extern int dap_client_init(); //  Init clients module
extern void dap_client_deinit(); // Deinit clients module

extern dap_client_t * dap_client_create(struct dap_server * sh, int s, ev_io* w_client); // Create new client and add it to the list
extern dap_client_t * dap_client_find(int sock, struct dap_server * sh); // Find client by socket

extern bool dap_client_is_ready_to_read(dap_client_t * sc);
extern bool dap_client_is_ready_to_write(dap_client_t * sc);
extern void dap_client_ready_to_read(dap_client_t * sc,bool is_ready);
extern void dap_client_ready_to_write(dap_client_t * sc,bool is_ready);

extern size_t dap_client_write(dap_client_t *sc, const void * data, size_t data_size);
extern size_t dap_client_write_f(dap_client_t *sc, const char * format,...);
extern size_t dap_client_read(dap_client_t *sc, void * data, size_t data_size);

extern void dap_client_remove(dap_client_t *sc, struct dap_server * sh); // Removes the client from the list

extern void dap_client_shrink_buf_in(dap_client_t * cl, size_t shrink_size);

#endif
