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


#ifndef _DAP_HTTP_HEADER_H_
#define _DAP_HTTP_HEADER_H_

//Structure for holding HTTP header in the bidirectional list
typedef struct dap_http_header{
    char *name;
    char *value;
    struct dap_http_header *next;
    struct dap_http_header *prev;
} dap_http_header_t;

struct dap_http_client;

extern int dap_http_header_init(); // Init module
extern void dap_http_header_deinit(); // Deinit module

extern int dap_http_header_parse(struct dap_http_client * cl_ht, const char * str);

extern dap_http_header_t * dap_http_header_add(dap_http_header_t ** top, const char*name, const char * value);

extern dap_http_header_t * dap_http_out_header_add(struct dap_http_client * ht, const char*name, const char * value);
extern dap_http_header_t * dap_http_out_header_add_f(struct dap_http_client * ht, const char*name, const char * value,...);

extern dap_http_header_t * dap_http_header_find(dap_http_header_t * top, const char*name);

extern void dap_http_header_remove(dap_http_header_t ** top,dap_http_header_t * hdr );

// For debug output
extern void print_dap_http_headers(dap_http_header_t * top);

#endif
