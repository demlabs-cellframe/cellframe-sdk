/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

#ifndef _DAP_CLIENT_HTTP_
#define _DAP_CLIENT_HTTP_

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "dap_worker.h"
#include <unistd.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_net.h"
#include "dap_events_socket.h"
#include "dap_stream_ch_proc.h"
#include "dap_server.h"
#include "dap_client.h"
#include "dap_client_pvt.h"

typedef void (*dap_client_http_callback_error_t)(int, void *); // Callback for specific http client operations
typedef void (*dap_client_http_callback_data_t)(void *, size_t, void *); // Callback for specific http client operations

#ifdef __cplusplus
extern "C" {
#endif

void* dap_client_http_request_custom(dap_worker_t * a_worker, const char *a_uplink_addr, uint16_t a_uplink_port, const char *a_method,
        const char *a_request_content_type, const char * a_path, void *a_request, size_t a_request_size, char *a_cookie,
        dap_client_http_callback_data_t a_response_callback, dap_client_http_callback_error_t a_error_callback,
        void *a_obj, char **a_custom, size_t a_custom_count);

void* dap_client_http_request(dap_worker_t * a_worker,const char *a_uplink_addr, uint16_t a_uplink_port, const char * a_method,
        const char* a_request_content_type, const char * a_path, void *a_request, size_t a_request_size,
        char * a_cookie, dap_client_http_callback_data_t a_response_callback,
        dap_client_http_callback_error_t a_error_callback, void *a_obj, void * a_custom);

#ifdef __cplusplus
}
#endif

#endif
