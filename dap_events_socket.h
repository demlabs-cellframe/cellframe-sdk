/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "uthash.h"
struct dap_events;
struct dap_events_socket;
struct dap_worker;
typedef struct dap_server dap_server_t;
typedef void (*dap_events_socket_callback_t) (struct dap_events_socket *,void * arg); // Callback for specific client operations
typedef struct dap_events_socket_callbacks{
    dap_events_socket_callback_t new_callback; // Create new client callback
    dap_events_socket_callback_t delete_callback; // Delete client callback
    dap_events_socket_callback_t read_callback; // Read function
    dap_events_socket_callback_t write_callback; // Write function
    dap_events_socket_callback_t error_callback; // Error processing function

} dap_events_socket_callbacks_t;


#define DAP_EVENTS_SOCKET_BUF 100000

typedef struct dap_events_socket{
    int socket;
    bool signal_close;

    bool _ready_to_write;
    bool _ready_to_read;

    uint32_t buf_out_zero_count;
    union{
        uint8_t buf_in[DAP_EVENTS_SOCKET_BUF+1]; // Internal buffer for input data
        char buf_in_str[DAP_EVENTS_SOCKET_BUF+1];
    };
    size_t buf_in_size; // size of data that is in the input buffer

    uint8_t buf_out[DAP_EVENTS_SOCKET_BUF+1]; // Internal buffer for output data

    char hostaddr[1024]; // Address
    char service[128];

    size_t buf_out_size; // size of data that is in the output buffer

    struct dap_events * events;

    struct dap_worker* dap_worker;
    dap_events_socket_callbacks_t *callbacks;

    time_t time_connection;
    time_t last_ping_request;
    bool is_pingable;

    UT_hash_handle hh;

    void * _inheritor; // Inheritor data to specific client type, usualy states for state machine
} dap_events_socket_t; // Node of bidirectional list of clients



int dap_events_socket_init(); //  Init clients module
void dap_events_socket_deinit(); // Deinit clients module

void dap_events_socket_create_after(dap_events_socket_t * a_es);

dap_events_socket_t * dap_events_socket_wrap_no_add(struct dap_events * a_events,
                                            int s, dap_events_socket_callbacks_t * a_callbacks); // Create new client and add it to the list


dap_events_socket_t * dap_events_socket_find(int sock, struct dap_events * sh); // Find client by socket

bool dap_events_socket_is_ready_to_read(dap_events_socket_t * sc);
bool dap_events_socket_is_ready_to_write(dap_events_socket_t * sc);
void dap_events_socket_set_readable(dap_events_socket_t * sc,bool is_ready);
void dap_events_socket_set_writable(dap_events_socket_t * sc,bool is_ready);

size_t dap_events_socket_write(dap_events_socket_t *sc, const void * data, size_t data_size);
size_t dap_events_socket_write_f(dap_events_socket_t *sc, const char * format,...);
size_t dap_events_socket_read(dap_events_socket_t *sc, void * data, size_t data_size);

void dap_events_socket_delete(dap_events_socket_t *sc,bool preserve_inheritor); // Removes the client from the list

void dap_events_socket_shrink_buf_in(dap_events_socket_t * cl, size_t shrink_size);

