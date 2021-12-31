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

#ifndef _ENC_HTTP_H_
#define _ENC_HTTP_H_
#include <stddef.h>
#include <stdbool.h>
#include "dap_hash.h"

struct dap_http;
struct dap_http_client;
struct dap_http_simple;
struct enc_key;

#define ENC_HTTP_MAX_RSA_ENC_SEQ 128000

typedef struct enc_http_delegate{
    bool isOk;

    char * url_path;
    size_t url_path_size;

    char * in_query;
    size_t in_query_size;

    char * cookie;
    char action[128];

    union{
        void *request;
        char *request_str;
        unsigned char *request_bytes;
    };
    size_t request_size;

    union{
        unsigned char* response_bytes;
        char *response_str;
        void *response;
    };
    size_t response_size;
    size_t response_size_max;

    struct dap_enc_key * key;

    struct dap_http_client *http;
} enc_http_delegate_t;

typedef void (*dap_enc_http_callback_t) (enc_http_delegate_t *,void *); // Callback for specific client operations
typedef uint8_t *(* dap_enc_acl_callback_t) (dap_chain_hash_fast_t *);   // Callback for access list for private chain networks

int enc_http_init(void);
void enc_http_deinit(void);

size_t enc_http_reply(enc_http_delegate_t * dg, void * data, size_t data_size);
size_t enc_http_reply_f(enc_http_delegate_t * dg, const char * data, ...);

void dap_enc_http_set_acl_callback(dap_enc_acl_callback_t a_callback);

enc_http_delegate_t *enc_http_request_decode(struct dap_http_simple *a_http_simple);

void enc_http_reply_encode(struct dap_http_simple *a_http_simple,enc_http_delegate_t * a_http_delegate);

void enc_http_delegate_delete(enc_http_delegate_t * dg);

void enc_http_add_proc(struct dap_http * sh, const char * url);

#endif
