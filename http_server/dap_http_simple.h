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

#ifndef _DAP_HTTP_SIMPLE_H_
#define _DAP_HTTP_SIMPLE_H_
#include <stddef.h>
#include "dap_http.h"

#define DAP_HTTP_SIMPLE_REQUEST_MAX 100000

struct dap_http_simple;
typedef void (*dap_http_simple_callback_t)(struct dap_http_simple *,void*);

typedef struct dap_http_simple{
    dap_http_client_t * http;
    union{
        void * request;
        char * request_str;
    };
    size_t request_size;

    union{
        void * reply;
        char * reply_str;
    };
    size_t reply_size_max;
    size_t reply_size;

    size_t reply_sent;
    char reply_mime[256];

   // dap_http_simple_callback_t reply_proc_post_callback;
} dap_http_simple_t;

#define DAP_HTTP_SIMPLE(a) ((dap_http_simple_t*) (a)->_inheritor )


void dap_http_simple_proc_add(dap_http_t *sh, const char * url_path, size_t reply_size_max, dap_http_simple_callback_t cb); // Add simple processor
int dap_http_simple_module_init();
size_t dap_http_simple_reply(dap_http_simple_t * shs, void * data, size_t data_size);
size_t dap_http_simple_reply_f(dap_http_simple_t * shs, const char * data, ...);
#endif
