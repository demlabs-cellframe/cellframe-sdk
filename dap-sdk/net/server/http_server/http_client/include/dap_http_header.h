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

#include <stddef.h>

//Structure for holding HTTP header in the bidirectional list
typedef struct dap_http_header{
    char    *name, *value;                                                  /* Area to keep HT field name and value */
    size_t  namesz, valuesz;                                                /* Dimension of corresponding field */
    int     htfld;                                                          /* HTTP Field numeric Id */

    struct dap_http_header *next, *prev;                                    /* List's element links */
} dap_http_header_t;

typedef struct dap_http_client dap_http_client_t;

int dap_http_header_init(); // Init module
void dap_http_header_deinit(); // Deinit module

int dap_http_header_parse(dap_http_client_t *cl_ht, const char *ht_line, size_t ht_line_len);

dap_http_header_t *dap_http_header_add(dap_http_header_t **a_top, const char *a_name, const char *a_value);

dap_http_header_t * dap_http_out_header_add(dap_http_client_t *ht, const char *name, const char *value);
dap_http_header_t * dap_http_out_header_add_f(dap_http_client_t *ht, const char *name, const char *value, ...);

dap_http_header_t *dap_http_header_find(dap_http_header_t * ht, const char*name);

dap_http_header_t * dap_http_headers_dup(dap_http_header_t * a_top);

void dap_http_header_remove(dap_http_header_t **a_top,dap_http_header_t *a_hdr);

// For debug output
void print_dap_http_headers(dap_http_header_t * a_ht);

/*
 * https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
 * Don't change order of field until u undrstand what u do
 */
#define HTTP$SZ_METHOD      16                                              /* POST, GET, HEAD ... */
#define HTTP_FLD$SZ_NAME    64                                              /* Maximum HTTP Field name */
#define HTTP_FLD$SZ_VALUE   1024                                            /* -- // -- field length */

enum    {

    HTTP_FLD$K_CONNECTION = 0,                                              /* Connection: Keep-Alive */
    HTTP_FLD$K_CONTENT_TYPE,                                                /* Content-Type: application/x-www-form-urlencoded */
    HTTP_FLD$K_CONTENT_LEN,                                                 /* Content-Length: 348 */
    HTTP_FLD$K_COOKIE,                                                      /* Cookie: $Version=1; Skin=new; */


    HTTP_FLD$K_EOL                                                          /* End-Of-List marker, mast be last element here */
};
