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

#ifndef _SERVER_HTTP_H_
#define _SERVER_HTTP_H_
#include "../../libdap-server/core_server/dap_server.h"
#include "dap_client.h"
#include "../../libdap/http/dap_http_header.h"
#include "../../libdap/http/dap_http_client.h"
#include "uthash.h"

struct dap_http;
struct dap_http_url_processor;
//Structure for internal data of dap_server_t structure for holding special HTTP data

// Structure for holding URL processors
typedef struct dap_http_url_proc{
    char url[512]; // First part of URL that will be processed
    struct dap_http * http; // Pointer to HTTP server instance

    dap_http_client_callback_t new_callback; // Init internal structure
    dap_http_client_callback_t delete_callback; // Delete internal structure

    dap_http_client_callback_t headers_read_callback;
    dap_http_client_callback_t headers_write_callback;

    dap_http_client_callback_t data_read_callback;
    dap_http_client_callback_t data_write_callback;
    dap_http_client_callback_t error_callback;

    dap_http_client_callback_t access_callback;

    void * _inheritor; // Internal data specific to the current URL processor
    UT_hash_handle hh; // makes this structure hashable with UTHASH library
} dap_http_url_proc_t;

// Internal server structure for HTTP server
typedef struct dap_http {
    dap_server_t * server;
    char server_name[256];
    dap_http_url_proc_t * url_proc;
} dap_http_t;

#define DAP_HTTP(a) ((dap_http_t *) (a)->_inheritor)

extern int dap_http_init(); // Init module
extern void dap_http_deinit(); // Deinit module

extern int dap_http_new(dap_server_t *sh, const char * server_name); // Create dap_http structure in the internal data field of dap_server_t instance
extern void dap_http_delete(dap_server_t *sh,void * arg); // Clear dap_http structure in the internal data field of dap_server_t instance

extern void dap_http_add_proc(dap_http_t * sh, const char * url_path, void * internal
                             ,dap_http_client_callback_t new_callback
                             ,dap_http_client_callback_t delete_callback
                             ,dap_http_client_callback_t headers_read_callback
                             ,dap_http_client_callback_t headers_write_callback
                             ,dap_http_client_callback_t data_read_callback
                             ,dap_http_client_callback_t data_write_callback
                             ,dap_http_client_callback_t error_callback ); // Add custom procesor for the HTTP server

#endif
