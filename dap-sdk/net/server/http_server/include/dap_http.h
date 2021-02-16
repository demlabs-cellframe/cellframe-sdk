/*
* Authors:
* Dmitrii Gerasimov <naeper@demlabs.net>
* DeM Labs Inc.   https://demlabs.net
* Cellframe https://cellframe.net
* Copyright  (c) 2017-2019
* All rights reserved.

This file is part of DAP the open source project.

DAP is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DAP is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

See more details here <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_server.h"
#include "dap_events_socket.h"
#include "dap_http_header.h"
#include "dap_http_client.h"
#include "dap_http_cache.h"
#include "uthash.h"

struct dap_http;
struct dap_http_url_processor;
//Structure for internal data of dap_server_t structure for holding special HTTP data

// Structure for holding URL processors
typedef struct dap_http_url_proc{
    char url[512]; // First part of URL that will be processed
    struct dap_http * http; // Pointer to HTTP server instance

    dap_http_cache_t * cache; // In memory cache, could be present or not
    pthread_rwlock_t cache_rwlock;

    dap_http_client_callback_t new_callback; // Init internal structure
    dap_http_client_callback_t delete_callback; // Delete internal structure

    dap_http_client_callback_t headers_read_callback;
    dap_http_client_callback_t headers_write_callback;

    dap_http_client_callback_t data_read_callback;
    dap_http_client_callback_t data_write_callback;
    dap_http_client_callback_error_t error_callback;

    dap_http_client_callback_t access_callback;

    void *_inheritor; // Internal data specific to the current URL processor
    UT_hash_handle hh; // makes this structure hashable with UTHASH library
} dap_http_url_proc_t;

// Internal server structure for HTTP server
typedef struct dap_http {
    dap_server_t *server;
    char server_name[256];
    dap_http_url_proc_t * url_proc;
} dap_http_t;

#define DAP_HTTP(a) ((dap_http_t *) (a)->_inheritor)

int dap_http_init( ); // Init module
void dap_http_deinit( ); // Deinit module

int dap_http_new( dap_server_t *a_server, const char *a_server_name ); // Create dap_http structure in the internal data field of dap_server_t instance
void dap_http_delete( dap_server_t *a_server, void *a_arg ); // Clear dap_http structure in the internal data field of dap_server_t instance

dap_http_url_proc_t * dap_http_add_proc(dap_http_t *sh, const char *url_path, void *internal
                             ,dap_http_client_callback_t new_callback
                             ,dap_http_client_callback_t delete_callback
                             ,dap_http_client_callback_t headers_read_callback
                             ,dap_http_client_callback_t headers_write_callback
                             ,dap_http_client_callback_t data_read_callback
                             ,dap_http_client_callback_t data_write_callback
                             ,dap_http_client_callback_error_t error_callback ); // Add custom procesor for the HTTP server
