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

#include "dap_json_rpc_response.h"
#include "uthash.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef void (dap_json_rpc_response_handler_func_t)(dap_json_rpc_response_t *a_response);

typedef struct dap_json_rpc_response_handler
{
    dap_json_rpc_response_handler_func_t *func;
    uint64_t id;
    UT_hash_handle hh;
}dap_json_rpc_response_handler_t;

int dap_json_rpc_response_registration_with_id(uint64_t a_id, dap_json_rpc_response_handler_func_t *func);
uint64_t dap_json_rpc_response_registration(dap_json_rpc_response_handler_func_t *func);
void dap_json_rpc_response_unregistration(uint64_t a_id);

void dap_json_rpc_response_handler(dap_json_rpc_response_t *a_response);

uint64_t dap_json_rpc_response_get_new_id(void);

void dap_json_rpc_response_accepted(void *a_data, size_t a_size_data, void *a_obj);

#ifdef __cplusplus
}
#endif
