#include "dap_json_rpc_params.h"

dap_json_rpc_params_t* dap_json_rpc_params_create(void){
    dap_json_rpc_params_t *l_params = DAP_NEW(dap_json_rpc_params_t);
    l_params->lenght = 0;
    return l_params;
}


void dap_json_rpc_params_add_data(dap_json_rpc_params_t *a_params, const void *a_value,
                                  dap_json_rpc_type_param_t a_type){
    dap_json_rpc_param_t *l_param = DAP_NEW(dap_json_rpc_param_t);
    //l_param->name_param = dap_strdup(a_name);
    l_param->type = a_type;
    size_t l_len_value;
    switch (a_type) {
//    case TYPE_PARAM_ARRAY:
//        break;
//    case TYPE_PARAM_OBJECT:
//        break;
    case TYPE_PARAM_STRING:
        l_param->value_param = dap_strdup(a_value);
        break;
    case TYPE_PARAM_BOOLEAN:
        l_len_value = sizeof(bool);
        l_param->value_param = DAP_NEW(bool);
        memcpy(l_param->value_param, a_value, l_len_value);
        break;
    case TYPE_PARAM_INTEGER:
        l_len_value = sizeof(int64_t);
        l_param->value_param = DAP_NEW(int64_t);
        memcpy(l_param->value_param, a_value, l_len_value);
        break;
    case TYPE_PARAM_DOUBLE:
        l_len_value = sizeof(double);
        l_param->value_param = DAP_NEW(double);
        memcpy(l_param->value_param, a_value, l_len_value);
        break;
    default:
        l_param->value_param = NULL;
        break;
    }
    dap_json_rpc_params_add_param(a_params, l_param);
}
void dap_json_rpc_params_add_param(dap_json_rpc_params_t *a_params, dap_json_rpc_param_t *a_param){
    uint32_t l_len_new_params = a_params->lenght + 1;
    dap_json_rpc_param_t **l_new_params = DAP_NEW_SIZE(dap_json_rpc_param_t*, l_len_new_params);
    memcpy(l_new_params, a_params->params, sizeof(dap_json_rpc_param_t*) * a_params->lenght);
    memcpy(l_new_params+a_params->lenght, &a_param, sizeof(dap_json_rpc_param_t*));
    DAP_FREE(a_params->params);
    a_params->params = l_new_params;
    a_params->lenght = l_len_new_params;
}

void dap_json_rpc_params_remove_all(dap_json_rpc_params_t *a_params){
    for (uint32_t i=0 ; i < a_params->lenght; i++){
        dap_json_rpc_param_remove(a_params->params[i]);
    }
    DAP_FREE(a_params);
}

//void dap_json_rpc_params_remove_param(dap_json_rpc_params_t *a_params, uint32_t index){
//    if (a_params->lenght > index){
//        a_params->params[index]
//    }
//}

uint32_t dap_json_rpc_params_lenght(dap_json_rpc_params_t *a_params){
    return a_params->lenght;
}

void *dap_json_rpc_params_get(dap_json_rpc_params_t *a_params, uint32_t index){
    if (a_params->lenght > index)
        return a_params->params[index]->value_param;
    return NULL;
}

dap_json_rpc_type_param_t dap_json_rpc_params_get_type_param(dap_json_rpc_params_t *a_params, uint32_t index){
    if (a_params->lenght > index)
        return a_params->params[index]->type;
    return TYPE_PARAM_NULL;
}

void dap_json_rpc_param_remove(dap_json_rpc_param_t *param){
    DAP_FREE(param->value_param);
    //DAP_FREE(param->name_param);
    DAP_FREE(param);
}
