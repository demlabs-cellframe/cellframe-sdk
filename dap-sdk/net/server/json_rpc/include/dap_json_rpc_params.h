#pragma once
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "json-c/json.h"

typedef enum dap_json_rpc_type_param{
    TYPE_PARAM_NULL,
    //TYPE_PARAM_OBJECT,
    TYPE_PARAM_STRING,
    TYPE_PARAM_INTEGER,
    TYPE_PARAM_DOUBLE,
    //TYPE_PARAM_ARRAY,
    TYPE_PARAM_BOOLEAN
}dap_json_rpc_type_param_t;

typedef struct dap_json_rpc_param{
    //char *name_param;
    void *value_param;
    enum dap_json_rpc_type_param type;
}dap_json_rpc_param_t;

typedef struct dap_json_rpc_params{
    uint32_t lenght;
    dap_json_rpc_param_t **params;
}dap_json_rpc_params_t;

dap_json_rpc_params_t* dap_json_rpc_params_create(void);
//void dap_json_rpc_params_remove(dap_json_rpc_params_t* psrams);

void dap_json_rpc_params_add_data(dap_json_rpc_params_t *a_params, const void *a_value,
                                  dap_json_rpc_type_param_t a_type);
void dap_json_rpc_params_add_param(dap_json_rpc_params_t *a_params, dap_json_rpc_param_t *a_param);

void dap_json_rpc_params_remove_all(dap_json_rpc_params_t *a_params); ///!!!
//void dap_json_rpc_params_remove_param(dap_json_rpc_params_t *a_params, uint32_t index); /// !!!

//dap_json_rpc_param_t *dap_jdon_rpc_params_search_param

uint32_t dap_json_rpc_params_lenght(dap_json_rpc_params_t *a_params);
void *dap_json_rpc_params_get(dap_json_rpc_params_t *a_params, uint32_t index);
dap_json_rpc_type_param_t dap_json_rpc_params_get_type_param(dap_json_rpc_params_t *a_params, uint32_t index);

void dap_json_rpc_param_remove(dap_json_rpc_param_t *param);

dap_json_rpc_params_t * dap_json_rpc_params_create_from_array_list(json_object *a_array_list);
char *dap_json_rpc_params_get_string_json(dap_json_rpc_params_t * a_params);



