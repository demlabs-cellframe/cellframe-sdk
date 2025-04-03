/*
 * Authors:
 * Alexey V. Stratulat <alexey.stratulat@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2020
 * All rights reserved.

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

#include "dap_json_rpc_errors.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef enum dap_json_rpc_response_type_result{
    TYPE_RESPONSE_STRING,
    TYPE_RESPONSE_NULL,
    TYPE_RESPONSE_JSON,
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
    dap_json_rpc_response_type_result_t type;
    union {
        char* result_string;
        int64_t result_int;
        double result_double;
        bool result_boolean;
        json_object *result_json_object;
    };
    uint64_t id;
}dap_json_rpc_response_t;

/**
 * Create a new JSON-RPC response structure.
 *
 * @param result A pointer to the dap_json_rpc_response_t
 * @param type The response type : TYPE_RESPONSE_NULL,
 *                                 TYPE_RESPONSE_STRING,
 *                                 TYPE_RESPONSE_INTEGER,
 *                                 TYPE_RESPONSE_DOUBLE,
 *                                 TYPE_RESPONSE_BOOLEAN,
 *                                 TYPE_RESPONSE_JSON
 * @param id The unique identifier associated with the REQUEST ID.
 * @return A pointer to the newly created `dap_json_rpc_response_t` structure. Don't forget about dap_json_rpc_response_free.
 *         Return NULL in case of memory allocation failure, an unsupported response type,
 *         or if `TYPE_RESPONSE_NULL` is specified as the response type.
 */
dap_json_rpc_response_t* dap_json_rpc_response_create(void * result, dap_json_rpc_response_type_result_t type, int64_t id);

/**
 * Free the dap_json_rpc_response_t structure.
 * @param response A pointer to the JSON-RPC response structure to be freed.
 */
void dap_json_rpc_response_free(dap_json_rpc_response_t *a_response);

/**
 * Convert a dap_json_rpc_response_t structure to a JSON string.
 *
 * @param response A pointer to the dap_json_rpc_response_t.
 * @return A pointer to the created dap_json_rpc_response_t string representation, 
 *         or NULL if parsing or memory allocation fails.
 */
char* dap_json_rpc_response_to_string(const dap_json_rpc_response_t* response);

/**
 * Convert a JSON string representation to a dap_json_rpc_response_t structure.
 *
 * @param json_string The JSON-formatted string.
 * @return A pointer to a DYNAMICALLY allocated dap_json_rpc_response_t structure
 *                                      created from the parsed JSON string.
 *         Returns NULL if the JSON parsing fails or memory allocation fails
 *                                      during structure creation.
 */
dap_json_rpc_response_t* dap_json_rpc_response_from_string(const char* json_string);

void json_print_object(struct json_object *obj, int indent_level);
void json_print_value(struct json_object *obj, const char *key, int indent_level, bool print_separator);

/**
 * Prints the result of a JSON-RPC response to the standard output.
 *
 * @param response A pointer to the dap_json_rpc_response_t instance.
 * @return 0 on success, 
 *         -1 if the response is empty, 
 *         -2 if the JSON object is NULL,
 *         and -3 if the JSON object length is 0.
 */
int dap_json_rpc_response_printf_result(dap_json_rpc_response_t* response, char * cmd_name);

#ifdef __cplusplus
}
#endif
