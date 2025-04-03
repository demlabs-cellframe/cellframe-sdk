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
#include "dap_http_simple.h"
#include "http_status_code.h"
#include "dap_strfuncs.h"
#include "dap_json_rpc_request.h"
#include "dap_json_rpc_request_handler.h"
#include "dap_config.h"
#include "dap_hash.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef enum dap_json_rpc_version{
    RPC_VERSION_1
}dap_json_rpc_version_t;

int dap_json_rpc_init(dap_server_t* a_http_server, dap_config_t *a_config);
void dap_json_rpc_deinit();
void dap_json_rpc_http_proc(dap_http_simple_t *a_http_simple, void *a_arg);
void dap_json_rpc_add_proc_http(struct dap_http_server*sh, const char *URL);
bool dap_check_node_pkey_in_map(dap_hash_fast_t *a_pkey);
bool dap_json_rpc_exec_cmd_inited();
dap_client_http_callback_error_t * dap_json_rpc_error_callback();

#ifdef __cplusplus
}
#endif
