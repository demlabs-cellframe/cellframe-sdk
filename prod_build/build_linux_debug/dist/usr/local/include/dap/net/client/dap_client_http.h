/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_worker.h"
#include "http_status_code.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dap_client_http_callback_error_t)(int, void *); // Callback for specific http client operations
typedef void (*dap_client_http_callback_error_ext_t)(int,int , void *,size_t, void *); // Callback with extended error processing
typedef void (*dap_client_http_callback_data_t)(void *, size_t, void *, http_status_code_t); // Callback for specific http client operations

typedef struct dap_client_http {
    // TODO move unnessassary fields to dap_client_http_pvt privat structure
    dap_client_http_callback_data_t response_callback;
    dap_client_http_callback_error_t error_callback;
    void *callbacks_arg;

    byte_t *request;
    size_t request_size;
    size_t request_sent_size;
    bool is_over_ssl;

    int socket;

    bool is_header_read;
    bool is_closed_by_timeout;
    bool were_callbacks_called;
    size_t header_length;
    size_t content_length;
    time_t ts_last_read;
    uint8_t *response;
    size_t response_size;
    size_t response_size_max;

    // Request args
    char uplink_addr[DAP_HOSTADDR_STRLEN];
    uint16_t uplink_port;
    char *method;
    char *request_content_type;
    char * path;
    char *cookie;
    char *request_custom_headers; // Custom headers

    // Request vars
    dap_worker_t *worker;
    dap_timerfd_t *timer;
    dap_events_socket_t *es;

} dap_client_http_t;

#define DAP_CLIENT_HTTP(a) (a ? (dap_client_http_t *) (a)->_inheritor : NULL)


int dap_client_http_init();
void dap_client_http_deinit();

dap_client_http_t *dap_client_http_request_custom(dap_worker_t * a_worker, const char *a_uplink_addr, uint16_t a_uplink_port, const char *a_method,
        const char *a_request_content_type, const char * a_path, const void *a_request, size_t a_request_size, char *a_cookie,
        dap_client_http_callback_data_t a_response_callback, dap_client_http_callback_error_t a_error_callback,                                  
        void *a_callbacks_arg, char *a_custom_headers, bool a_over_ssl);
dap_client_http_t *dap_client_http_request(dap_worker_t * a_worker,const char *a_uplink_addr, uint16_t a_uplink_port, const char * a_method,
        const char* a_request_content_type, const char * a_path, const void *a_request, size_t a_request_size,
        char * a_cookie, dap_client_http_callback_data_t a_response_callback,
        dap_client_http_callback_error_t a_error_callback, void *a_callbacks_arg, char *a_custom_headers);

uint64_t dap_client_http_get_connect_timeout_ms();
void dap_client_http_set_connect_timeout_ms(uint64_t a_timeout_ms);

void dap_client_http_close_unsafe(dap_client_http_t *a_client_http);

#ifdef __cplusplus
}
#endif
