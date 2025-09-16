/*
 Copyright (c) 2017-2018 (c) Project "DeM Labs Inc" https://github.com/demlabsinc
  All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include <time.h>
#include <stdbool.h>
#include "dap_events_socket.h"

struct dap_http_client;
struct dap_http;
struct dap_http_url_proc;

typedef enum dap_http_client_state{
    DAP_HTTP_CLIENT_STATE_NONE = 0,
    DAP_HTTP_CLIENT_STATE_START = 1,
    DAP_HTTP_CLIENT_STATE_HEADERS = 2,
    DAP_HTTP_CLIENT_STATE_DATA = 3
} dap_http_client_state_t;

typedef void (*dap_http_client_callback_t) (struct dap_http_client *,void * arg); // Callback for specific client operations
typedef bool (*dap_http_client_callback_write_t) (struct dap_http_client *a_client, void *a_arg); // Callback for write client operation
typedef void (*dap_http_client_callback_error_t) (struct dap_http_client *,int); // Callback for specific client operations

typedef struct dap_http_client
{
    char action[32],                                                        /* HTTP method : GET, PUT and etc */
        url_path[1024],                                                     /* URL path of requested document */
        in_query_string[1024];                                              /* Arguments has been extracted from the request line */
    uint32_t action_len, url_path_len, in_query_string_len;

    int     keep_alive;                                                     /* Connection: Keep-Alive */

    dap_http_client_state_t state_read;

    struct dap_http_header *in_headers;                                     /* List of HTTP's fields */

    char in_content_type[256],
        in_cookie[1024];
    size_t in_content_length,
        in_cookie_len;

    struct dap_http_header *out_headers;

    int     out_content_ready;

    char    out_content_type[256];
    size_t out_content_length;

    time_t out_last_modified;
    int     out_connection_close;
    size_t out_cache_position;

    dap_events_socket_t *esocket;
    SOCKET socket_num;
    struct dap_http_server * http;

    uint16_t reply_status_code;

    char reply_reason_phrase[256];
    size_t reply_reason_phrase_len;

    struct dap_http_url_proc *proc;

    void *_inheritor;
    void *_internal;

} dap_http_client_t;

#define DAP_HTTP_CLIENT(a)  ((dap_http_client_t *) (a)->_inheritor )

#ifdef __cplusplus
extern "C" {
#endif

int dap_http_client_init(void);
void dap_http_client_deinit(void);
void dap_http_client_new( dap_events_socket_t *a_esocket, void *a_arg ); // Creates HTTP client's internal structure
void dap_http_client_delete( dap_events_socket_t * a_esocket,void *a_arg ); // Free memory for HTTP client's internal structure

void dap_http_client_read( dap_events_socket_t * a_esocket,void *a_arg ); // Process read event
bool dap_http_client_write_callback( dap_events_socket_t * a_esocket,void *a_arg ); // Process write event
void dap_http_client_error( dap_events_socket_t * a_esocket,int a_arg ); // Process error event
void dap_http_client_out_header_generate( dap_http_client_t *a_http_client );

void dap_http_client_write(dap_http_client_t *a_http_client);   // Start write event

#ifdef __cplusplus
}
#endif

