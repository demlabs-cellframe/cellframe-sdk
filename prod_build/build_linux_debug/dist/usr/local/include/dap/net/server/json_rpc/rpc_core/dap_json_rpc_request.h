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
#include "dap_json_rpc_response_handler.h"
#include "dap_json_rpc_params.h"
#include "dap_client_http.h"
#include "dap_client_pvt.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef struct dap_json_rpc_request
{
    char* method;
    dap_json_rpc_params_t *params;
    uint64_t id;
}dap_json_rpc_request_t;

typedef struct dap_json_rpc_http_request
{
    struct {
        uint32_t data_size;
        uint32_t signs_size;
    }  header;
    byte_t request_n_signs[];
} DAP_ALIGN_PACKED dap_json_rpc_http_request_t;

/**
 * Create a new dap_json_rpc_request_t instance.
 *
 * @param a_method
 * @param a_params
 * @param a_id The ID associated with the request.
 * @return A pointer to the newly allocated dap_json_rpc_request_t instance,
 *         or NULL on memory allocation error.
 */
dap_json_rpc_request_t *dap_json_rpc_request_creation(const char *a_method, dap_json_rpc_params_t *a_params, int64_t a_id);

void dap_json_rpc_request_free(dap_json_rpc_request_t *request);

/**
 * Convert a JSON-formatted string to a dap_json_rpc_request_t structure.
 *
 * @param a_data The JSON-formatted string representing the JSON-RPC request.
 * @return A pointer to a dap_json_rpc_request_t structure,
 *         or NULL on failure
 */
dap_json_rpc_request_t *dap_json_rpc_request_from_json(const char *a_data);

/**
 * Convert dap_json_rpc_request_t to JSON string representation.
 *
 * @param a_request The dap_json_rpc_request_t structure to be converted.
 * @return A JSON string representation of the request, 
 *         or NULL on failure.
 */
char *dap_json_rpc_request_to_json_string(const dap_json_rpc_request_t *a_request);
dap_json_rpc_http_request_t *dap_json_rpc_http_request_deserialize(const void *data, size_t data_size);
char * dap_json_rpc_http_request_serialize(dap_json_rpc_http_request_t *a_request, size_t *a_total_size);
void dap_json_rpc_http_request_free(dap_json_rpc_http_request_t *a_http_request);
char* dap_json_rpc_request_to_http_str(dap_json_rpc_request_t *a_request, size_t*output_data_size);

char * dap_json_rpc_enc_request(dap_client_pvt_t* a_client_internal, char * a_request_data_str, size_t a_request_data_size,
                                char ** a_path, size_t * a_enc_request_size, char ** a_custom_header);

int dap_json_rpc_request_send(dap_client_pvt_t*  a_client_internal, dap_json_rpc_request_t *a_request, json_object** a_response);

#ifdef __cplusplus
}
#endif
