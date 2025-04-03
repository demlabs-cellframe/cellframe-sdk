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
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "json.h"

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
    uint32_t length;
    dap_json_rpc_param_t **params;
}dap_json_rpc_params_t;

/**
 * Create a new dap_json_rpc_param_t instance.
 *
 * @param data The data value of the parameter.
 * @param type The type of the parameter: TYPE_PARAM_NULL,
                                          TYPE_PARAM_STRING,
                                          TYPE_PARAM_INTEGER,
                                          TYPE_PARAM_DOUBLE,
                                          TYPE_PARAM_BOOLEAN
 * 
 * @return A pointer to the newly allocated dap_json_rpc_param_t instance,
 *         or NULL if memory allocation fails.
 */
dap_json_rpc_param_t* dap_json_rpc_create_param(void * data, dap_json_rpc_type_param_t type);

/**
 * Create a new dap_json_rpc_params_t.
 *
 * @return A pointer to the newly created dap_json_rpc_params_t instance,
 *         or NULL if memory allocation fails.
 */
dap_json_rpc_params_t* dap_json_rpc_params_create(void);

/**
 * Add a parameter with data to a JSON-RPC parameters object.
 *
 * This function adds a new parameter to the JSON-RPC parameters object `a_params`
 * with the provided data value `a_value` and the specified parameter type `a_type`.
 *
 * @param a_params Pointer to the JSON-RPC parameters object.
 * @param a_value Pointer to the data value to be added as a parameter.
 * @param a_type Type of the parameter to be added: TYPE_PARAM_NULL,
                                                    TYPE_PARAM_STRING,
                                                    TYPE_PARAM_INTEGER,
                                                    TYPE_PARAM_DOUBLE,
                                                    TYPE_PARAM_BOOLEAN
 */
void dap_json_rpc_params_add_data(dap_json_rpc_params_t *a_params, const void *a_value,
                                  dap_json_rpc_type_param_t a_type);

/**
 * Add a new parameter to dap_json_rpc_params_t.
 *
 * @param a_params The dap_json_rpc_params_t structure to which the parameter will be added.
 * @param a_param The dap_json_rpc_param_t parameter to be added.
 */
void dap_json_rpc_params_add_param(dap_json_rpc_params_t *a_params, dap_json_rpc_param_t *a_param);


/**
 * Remove a JSON-RPC parameter and free associated memory.
 * @param param The JSON-RPC parameter to remove.
 */
void dap_json_rpc_param_remove(dap_json_rpc_param_t *param);

/**
 * Remove all JSON-RPC parameters in the list and free associated memory.
 * @param a_params The JSON-RPC parameter list to remove.
 */
void dap_json_rpc_params_remove_all(dap_json_rpc_params_t *a_params);


uint32_t dap_json_rpc_params_length(dap_json_rpc_params_t *a_params);

/**
 * Get the POINTER to the value of a JSON-RPC parameter at a specified index.
 *
 * @param a_params The JSON-RPC parameter list.
 * @param index The index of the parameter whose value to retrieve.
 * @return A pointer to the value of the parameter at the specified index, 
 *         or NULL if the index is out of bounds.
 */
void *dap_json_rpc_params_get(dap_json_rpc_params_t *a_params, uint32_t index);

dap_json_rpc_type_param_t dap_json_rpc_params_get_type_param(dap_json_rpc_params_t *a_params, uint32_t index);

/**
 * Create a dap_json_rpc_params_t structure from a JSON array.
 *
 * @param a_array_list The JSON array to convert into dap_json_rpc_params_t.
 * @return A pointer to the created dap_json_rpc_params_t structure;
 *         NULL if a_array_list is NULL.
 */
dap_json_rpc_params_t * dap_json_rpc_params_create_from_array_list(json_object *a_array_list);

dap_json_rpc_params_t * dap_json_rpc_params_create_from_subcmd_and_args(json_object *a_subcmd, json_object *a_args, const char* a_method);

/**
 * Get a JSON string representation of dap_json_rpc_params_t.
 *
 * @param a_params The dap_json_rpc_params_t structure to convert.
 * @return A JSON string representation of the parameters;
 *         NULL on error or invalid input.
 */
char *dap_json_rpc_params_get_string_json(dap_json_rpc_params_t * a_params);


#ifdef __cplusplus
}
#endif
