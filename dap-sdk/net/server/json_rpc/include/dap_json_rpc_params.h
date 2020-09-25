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
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "json-c/json.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef enum dap_json_rpc_type_param{
    TYPE_PARAM_NULL,
    TYPE_PARAM_STRING,
    TYPE_PARAM_INTEGER,
    TYPE_PARAM_DOUBLE,
    TYPE_PARAM_BOOLEAN
}dap_json_rpc_type_param_t;

typedef struct dap_json_rpc_param
{
    void *value_param;
    enum dap_json_rpc_type_param type;
}dap_json_rpc_param_t;

typedef struct dap_json_rpc_params
{
    uint32_t lenght;
    dap_json_rpc_param_t **params;
}dap_json_rpc_params_t;

dap_json_rpc_params_t* dap_json_rpc_params_create(void);

void dap_json_rpc_params_add_data(dap_json_rpc_params_t *a_params, const void *a_value,
                                  dap_json_rpc_type_param_t a_type);
void dap_json_rpc_params_add_param(dap_json_rpc_params_t *a_params, dap_json_rpc_param_t *a_param);

void dap_json_rpc_params_remove_all(dap_json_rpc_params_t *a_params);

uint32_t dap_json_rpc_params_lenght(dap_json_rpc_params_t *a_params);
void *dap_json_rpc_params_get(dap_json_rpc_params_t *a_params, uint32_t index);
dap_json_rpc_type_param_t dap_json_rpc_params_get_type_param(dap_json_rpc_params_t *a_params, uint32_t index);

void dap_json_rpc_param_remove(dap_json_rpc_param_t *param);

dap_json_rpc_params_t * dap_json_rpc_params_create_from_array_list(json_object *a_array_list);
char *dap_json_rpc_params_get_string_json(dap_json_rpc_params_t * a_params);

#ifdef __cplusplus
}
#endif
