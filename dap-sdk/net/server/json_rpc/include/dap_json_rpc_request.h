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
#include "dap_json_rpc_response_handler.h"
#include "dap_common.h"
#include "dap_json_rpc_params.h"
#include "json-c/json.h"
#include "dap_string.h"
#include "dap_client_http.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef struct dap_json_rpc_request
{
    char* method;
    dap_json_rpc_params_t *params;
    uint64_t id;
}dap_json_rpc_request_t;

int dap_json_rpc_request_init(const char *a_url_service);

dap_json_rpc_request_t *dap_json_rpc_request_creation(const char *a_method, dap_json_rpc_params_t *a_params, int64_t a_id);

dap_json_rpc_request_t *dap_json_rpc_request_from_json(const char *a_data);
char *dap_json_rpc_request_to_json(const dap_json_rpc_request_t *a_request);

void dap_json_rpc_request_send(dap_json_rpc_request_t *a_request, dap_json_rpc_response_handler_func_t *response_handler,
                               const char *a_uplink_addr, const uint16_t a_uplink_port,
                               dap_client_http_callback_error_t func_error);

#ifdef __cplusplus
}
#endif
