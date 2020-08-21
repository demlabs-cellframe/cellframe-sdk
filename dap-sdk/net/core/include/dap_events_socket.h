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
#include <stdatomic.h>
#include "uthash.h"
#ifndef _WIN32
#include <sys/epoll.h>
#else
#include "wepoll.h"
#endif
#include <pthread.h>

// Caps for different platforms
#if defined(DAP_OS_LINUX)
    #define DAP_EVENTS_CAPS_EPOLL
#define DAP_EVENTS_CAPS_EVENT_EVENTFD
#elif defined (DAP_OS_UNIX)
    #define DAP_EVENTS_CAPS_POLL
    #define DAP_EVENTS_CAPS_EVENT_PIPE
#elif defined (DAP_OS_WINDOWS)
    #define DAP_EVENTS_CAPS_EVENT_PIPE
#endif

typedef struct dap_events dap_events_t;
typedef struct dap_events_socket dap_events_socket_t;
typedef struct dap_worker dap_worker_t;

typedef struct dap_server dap_server_t;
typedef void (*dap_events_socket_callback_t) (dap_events_socket_t *,void * arg); // Callback for specific client operations
typedef void (*dap_events_socket_worker_callback_t) (dap_events_socket_t *,dap_worker_t * ); // Callback for specific client operations

typedef struct dap_events_socket_callbacks {
    union{
        dap_events_socket_callback_t accept_callback; // Accept callback for listening socket
        dap_events_socket_callback_t timer_callback; // Timer callback for listening socket
        dap_events_socket_callback_t event_callback; // Timer callback for listening socket
        dap_events_socket_callback_t action_callback; // Callback for action with socket
                                                      // for events and timers thats pointer
                                                      // to processing callback
    };
    dap_events_socket_callback_t new_callback; // Create new client callback
    dap_events_socket_callback_t delete_callback; // Delete client callback
    dap_events_socket_callback_t read_callback; // Read function
    dap_events_socket_callback_t write_callback; // Write function
    dap_events_socket_callback_t error_callback; // Error processing function

    dap_events_socket_worker_callback_t worker_assign_callback; // After successful worker assign
    dap_events_socket_worker_callback_t worker_unassign_callback; // After successful worker unassign

} dap_events_socket_callbacks_t;

#define DAP_EVENTS_SOCKET_BUF 100000

typedef enum {
    DESCRIPTOR_TYPE_SOCKET = 0,
    DESCRIPTOR_TYPE_SOCKET_LISTENING,
    DESCRIPTOR_TYPE_EVENT,
    DESCRIPTOR_TYPE_TIMER,
    DESCRIPTOR_TYPE_FILE
} dap_events_desc_type_t;

typedef struct dap_events_socket {
    union{
        int socket;
        int fd;
    };
#ifdef DAP_EVENTS_CAPS_EVENT_PIPE
    int32_t socket2;
#endif
    dap_events_desc_type_t type;

    dap_events_socket_t ** workers_es; // If not NULL - on every worker must be present
    size_t workers_es_size;           //  events socket with same socket

    uint32_t  flags;
    bool no_close;
    atomic_bool kill_signal;

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

    struct dap_events *events;
    struct dap_worker *dap_worker;
    struct epoll_event ev;

    dap_events_socket_callbacks_t callbacks;

    time_t time_connection;
    time_t last_time_active;
    time_t last_ping_request;
    bool is_pingable;

    UT_hash_handle hh;
    struct dap_events_socket *next, *prev;
    struct dap_events_socket *knext, *kprev;

    void *_inheritor; // Inheritor data to specific client type, usualy states for state machine

    pthread_mutex_t write_hold;
} dap_events_socket_t; // Node of bidirectional list of clients

int dap_events_socket_init(); //  Init clients module
void dap_events_socket_deinit(); // Deinit clients module

void dap_events_socket_create_after(dap_events_socket_t * a_es);

dap_events_socket_t * dap_events_socket_create_type_event(dap_worker_t * a_w, dap_events_socket_callback_t a_callback);

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

void dap_events_socket_remove( dap_events_socket_t *a_es);
void dap_events_socket_delete(dap_events_socket_t *sc,bool preserve_inheritor); // Removes the client from the list
void dap_events_socket_remove_and_delete(dap_events_socket_t* a_es, bool preserve_inheritor );
int dap_events_socket_kill_socket( dap_events_socket_t *a_es );



void dap_events_socket_shrink_buf_in(dap_events_socket_t * cl, size_t shrink_size);

