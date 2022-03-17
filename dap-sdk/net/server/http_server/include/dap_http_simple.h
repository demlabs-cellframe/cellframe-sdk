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

#include <stddef.h>
#include <stdint.h>
#include "dap_http.h"
#include "dap_uuid.h"
//#define DAP_HTTP_SIMPLE_REQUEST_MAX 100000
// number of simultaneous http requests
#define DAP_HTTP_SIMPLE_REQUEST_MAX 65536

struct dap_http_simple;
typedef void ( *dap_http_simple_callback_t )( struct dap_http_simple *, void * );

typedef struct dap_http_simple {
    dap_events_socket_t * esocket;
    dap_worker_t * worker;
    dap_http_client_t * http_client;
    uint128_t http_client_uuid;
    union {
        void *request;
        char *request_str;
        uint8_t * request_byte;
    };

    union {
        void *reply;
        uint8_t *reply_byte;
        char *reply_str;
    };
    size_t content_length;

    size_t request_size;
    size_t request_size_max;
    size_t reply_size;
    size_t reply_size_max;
    size_t reply_sent;

    char reply_mime[256];

   // dap_http_simple_callback_t reply_proc_post_callback;
} dap_http_simple_t;

#define DAP_HTTP_SIMPLE(a) ((dap_http_simple_t*) (a)->_inheritor )

struct dap_http_url_proc * dap_http_simple_proc_add( dap_http_t *sh, const char *url_path, size_t reply_size_max, dap_http_simple_callback_t cb ); // Add simple processor

int  dap_http_simple_module_init( void );
void dap_http_simple_module_deinit(void);

// input string must match NameClient/MiminalVersion
// For example DapClient/2.2
// If this function was not called. All user agents will supported by default
// ATTENTION: Last parameter must be NULL
// example call: dap_http_simple_set_supported_user_agents("DapVpnClient/2.2", "Mozila/5.0", NULL);
// returns false if operation not successful
int dap_http_simple_set_supported_user_agents( const char *str_agents, ... );

// if this function was called. We checking version only supported user-agents
// other will pass automatically ( and request with without user-agents field too )
// Affects the behavior of the internal function _is_user_agent_supported
void dap_http_simple_set_pass_unknown_user_agents(int pass );

size_t dap_http_simple_reply( dap_http_simple_t *shs, void *data, size_t data_size );
size_t dap_http_simple_reply_f( dap_http_simple_t *shs, const char *data, ... );
dap_http_cache_t * dap_http_simple_make_cache_from_reply(dap_http_simple_t * a_http_simple , time_t a_ts_expire );

