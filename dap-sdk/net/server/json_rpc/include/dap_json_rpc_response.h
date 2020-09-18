/*
 * Authors:
 * Alexey V. Stratulat <alexey.stratulat@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2020
 * All rights reserved.

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

#pragma once

#include "dap_http_simple.h"
#include "dap_json_rpc_errors.h"
#include "json-c/json.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef enum dap_json_rpc_response_type_result{
    TYPE_RESPONSE_NULL,
    TYPE_RESPONSE_STRING,
    TYPE_RESPONSE_INTEGER,
    TYPE_RESPONSE_DOUBLE,
    TYPE_RESPONSE_BOOLEAN
}dap_json_rpc_response_type_result_t;

typedef struct dap_json_rpc_response_JSON
{
    json_object *obj_result;
    json_object *obj_error;
    dap_json_rpc_error_JSON_t *struct_error;
    json_object *obj_id;
}dap_json_rpc_request_JSON_t;

void dap_json_rpc_request_JSON_free(dap_json_rpc_request_JSON_t *l_request_JSON);

typedef struct dap_json_rpc_response
{
    dap_json_rpc_response_type_result_t type_result;
    char* result_string;
    int64_t result_int;
    double result_double;
    bool result_boolean;
    dap_json_rpc_error_t* error;
    int64_t id;
}dap_json_rpc_response_t;


void dap_json_rpc_response_free(dap_json_rpc_response_t *a_response);

void dap_json_rpc_response_send(dap_json_rpc_response_t *a_response, dap_http_simple_t *a_client);

dap_json_rpc_response_t *dap_json_rpc_response_from_json(char *a_data_json);


#ifdef __cplusplus
}
#endif
