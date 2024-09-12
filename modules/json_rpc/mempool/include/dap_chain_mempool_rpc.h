/*
 * Authors:
 * Alexey V. Stratulat <alexey.stratulat@demlabs.net>
 * Olzhas Zharasbaev <oljas.jarasbaev@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2023
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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
#include "dap_json_rpc_response.h"
#include "dap_json_rpc_params.h"


int dap_chain_mempool_rpc_init(void);
void dap_chain_mempool_rpc_handler_list(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_mempool_rpc_handler_test(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method);
