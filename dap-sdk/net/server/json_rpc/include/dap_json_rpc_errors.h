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
#include "utlist.h"
#include "json-c/json.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef struct dap_json_rpc_error
{
    int code_error;
    char *msg;
    void *next;
}dap_json_rpc_error_t;

typedef struct dap_json_rpc_error_JSON
{
    json_object *obj_code;
    json_object *obj_msg;
}dap_json_rpc_error_JSON_t;

int dap_json_rpc_error_init(void);
void dap_json_rpc_error_deinit(void);

dap_json_rpc_error_JSON_t * dap_json_rpc_error_JSON_create();
void dap_json_rpc_error_JSON_free(dap_json_rpc_error_JSON_t *a_error_json);
dap_json_rpc_error_JSON_t * dap_json_rpc_error_JSON_add_data(int code, const char *msg);

int dap_json_rpc_error_add(int a_code_error, const char *a_msg);

dap_json_rpc_error_t *dap_json_rpc_error_search_by_code(int a_code_error);

char *dap_json_rpc_error_get_json(dap_json_rpc_error_t *a_error);

dap_json_rpc_error_t *dap_json_rpc_create_from_json(const char *a_json);

dap_json_rpc_error_t *dap_json_rpc_create_from_json_object(json_object *a_jobj);

void dap_json_rpc_add_standart_erros(void);

#ifdef __cplusplus
}
#endif
