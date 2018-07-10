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


#ifndef _DAP_HTTP_CLIENT_H_
#define _DAP_HTTP_CLIENT_H_

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
typedef struct dap_client_remote dap_client_remote_t;
struct dap_http_client;
struct dap_http;
struct dap_http_url_proc;

typedef enum dap_http_client_state{
    DAP_HTTP_CLIENT_STATE_NONE=0,
    DAP_HTTP_CLIENT_STATE_START=1,
    DAP_HTTP_CLIENT_STATE_HEADERS=2,
    DAP_HTTP_CLIENT_STATE_DATA=3
} dap_http_client_state_t;

typedef void (*dap_http_client_callback_t) (struct dap_http_client *,void * arg); // Callback for specific client operations

typedef struct dap_http_client
{
    char action[128]; // Type of HTTP action (GET, PUT and etc)
    char url_path[2048]; // URL path of requested document
    uint32_t http_version_major; // Major version of HTTP protocol
    uint32_t http_version_minor; // Minor version of HTTP protocol
    bool keep_alive;

    dap_http_client_state_t state_read;
    dap_http_client_state_t state_write;

    struct dap_http_header * in_headers;
    uint64_t in_content_length;
    char in_content_type[256];
    char in_query_string[1024];
    char in_cookie[1024];

    struct dap_http_header * out_headers;
    uint64_t out_content_length;
    bool out_content_ready;
    char out_content_type[256];
    time_t out_last_modified;
    bool out_connection_close;


    dap_client_remote_t * client;
    struct dap_http * http;

    uint32_t reply_status_code;
    char reply_reason_phrase[256];

    struct dap_http_url_proc * proc;

    void * _inheritor;
    void * _internal;

} dap_http_client_t;

#define DAP_HTTP_CLIENT(a)  ((dap_http_client_t *) (a)->_inheritor )


#ifdef __cplusplus
extern "C" {
#endif

int dap_http_client_init();
void dap_http_client_deinit();


void dap_http_client_new(dap_client_remote_t * cl,void * arg); // Creates HTTP client's internal structure
void dap_http_client_delete(dap_client_remote_t * cl,void * arg); // Free memory for HTTP client's internal structure

void dap_http_client_read( dap_client_remote_t * cl,void * arg); // Process read event
void dap_http_client_write( dap_client_remote_t * cl,void * arg); // Process write event
void dap_http_client_error( dap_client_remote_t * cl,void * arg); // Process error event

#ifdef __cplusplus
}
#endif

#endif
