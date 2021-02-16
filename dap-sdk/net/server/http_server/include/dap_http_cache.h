/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd.   https://demlabs.net
 * Copyright  (c) 2021
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "dap_common.h"
#include "dap_http_header.h"

// Cache object
typedef struct dap_http_cache
{
    struct dap_http_url_proc * url_proc;
    byte_t *body;
    size_t body_size;
    dap_http_header_t * headers;
    char * response_phrase;
    int    response_code;
    time_t ts_expire;
} dap_http_cache_t;

dap_http_cache_t * dap_http_cache_update(struct dap_http_url_proc * a_url_proc, const byte_t * a_body, size_t a_body_size,
                                         dap_http_header_t * a_headers, const char * a_response_phrase, int a_respoonse_code,
                                         time_t a_ts_expire );
void dap_http_cache_delete(dap_http_cache_t * a_http_cache);
