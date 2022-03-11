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
//Structure for holding HTTP header in the bidirectional list
typedef struct dap_http_header{
    char *name;
    char *value;
    struct dap_http_header *next;
    struct dap_http_header *prev;
} dap_http_header_t;

struct dap_http_client;

int dap_http_header_init(); // Init module
void dap_http_header_deinit(); // Deinit module

int dap_http_header_parse(struct dap_http_client * cl_ht, const char * str);

dap_http_header_t *dap_http_header_add(dap_http_header_t **a_top, const char *a_name, const char *a_value);

dap_http_header_t * dap_http_out_header_add(struct dap_http_client * ht, const char*name, const char * value);
dap_http_header_t * dap_http_out_header_add_f(struct dap_http_client * ht, const char*name, const char * value,...);

dap_http_header_t * dap_http_header_find(dap_http_header_t * top, const char*name);

dap_http_header_t * dap_http_headers_dup(dap_http_header_t * a_top);

void dap_http_header_remove(dap_http_header_t **a_top,dap_http_header_t *a_hdr);

// For debug output
void print_dap_http_headers(dap_http_header_t * top);

