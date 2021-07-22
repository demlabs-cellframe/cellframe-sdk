#include "dap_json_rpc_params.h"

#define LOG_TAG "dap_json_rpc_params"

dap_json_rpc_params_t* dap_json_rpc_params_create(void)
{
    dap_json_rpc_params_t *l_params = DAP_NEW(dap_json_rpc_params_t);
    if(l_params)
        l_params->lenght = 0;
    return l_params;
}


void dap_json_rpc_params_add_data(dap_json_rpc_params_t *a_params, const void *a_value,
                                  dap_json_rpc_type_param_t a_type)
{
    log_it(L_DEBUG, "Add data in params");
    dap_json_rpc_param_t *l_param = DAP_NEW(dap_json_rpc_param_t);
    //l_param->name_param = dap_strdup(a_name);
    l_param->type = a_type;
    size_t l_len_value;
    switch (a_type) {
    case TYPE_PARAM_STRING:
        l_param->value_param = dap_strdup((char*)a_value);
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
void dap_json_rpc_params_add_param(dap_json_rpc_params_t *a_params, dap_json_rpc_param_t *a_param)
{
    uint32_t l_len_new_params = a_params->lenght + 1;
    dap_json_rpc_param_t **l_new_params = DAP_NEW_SIZE(dap_json_rpc_param_t*, l_len_new_params);
    if(a_params->lenght && a_params->params)
       memcpy(l_new_params, a_params->params, sizeof(dap_json_rpc_param_t*) * a_params->lenght);
    memcpy(l_new_params+a_params->lenght, &a_param, sizeof(dap_json_rpc_param_t*));
    if (a_params->lenght != 0)
        DAP_FREE(a_params->params);
    a_params->params = l_new_params;
    a_params->lenght++;
}

void dap_json_rpc_params_remove_all(dap_json_rpc_params_t *a_params)
{
    log_it(L_DEBUG, "Clean params");
    for (uint32_t i=0x0 ; i < dap_json_rpc_params_lenght(a_params); i++){
        dap_json_rpc_param_remove(a_params->params[i]);
    }
    DAP_FREE(a_params);
}

uint32_t dap_json_rpc_params_lenght(dap_json_rpc_params_t *a_params)
{
    return a_params->lenght;
}

void *dap_json_rpc_params_get(dap_json_rpc_params_t *a_params, uint32_t index)
{
    if (a_params->lenght > index)
        return a_params->params[index]->value_param;
    return NULL;
}

dap_json_rpc_type_param_t dap_json_rpc_params_get_type_param(dap_json_rpc_params_t *a_params, uint32_t index)
{
    if (a_params->lenght > index)
        return a_params->params[index]->type;
    return TYPE_PARAM_NULL;
}

void dap_json_rpc_param_remove(dap_json_rpc_param_t *param)
{
    DAP_FREE(param->value_param);
    DAP_FREE(param);
}

dap_json_rpc_params_t * dap_json_rpc_params_create_from_array_list(json_object *a_array_list)
{
    log_it(L_NOTICE, "Translation json_object to dap_json_rpc_params");
    if (a_array_list == NULL)
        return NULL;
    dap_json_rpc_params_t *l_params = dap_json_rpc_params_create();
    int l_lenght = json_object_array_length(a_array_list);
    for (int i = 0; i < l_lenght; i++){
        json_object *l_jobj = json_object_array_get_idx(a_array_list, i);
        json_type l_jobj_type = json_object_get_type(l_jobj);
        char *l_str_tmp = NULL;
        bool l_bool_tmp;
        int64_t l_int_tmp;
        double l_double_tmp;
        switch (l_jobj_type) {
        case json_type_string:
            l_str_tmp = dap_strdup(json_object_get_string(l_jobj));
            dap_json_rpc_params_add_data(l_params, l_str_tmp, TYPE_PARAM_STRING);
            DAP_FREE(l_str_tmp);
            break;
        case json_type_boolean:
            l_bool_tmp = json_object_get_boolean(l_jobj);
            dap_json_rpc_params_add_data(l_params, &l_bool_tmp, TYPE_PARAM_BOOLEAN);
            break;
        case json_type_int:
            l_int_tmp = json_object_get_int64(l_jobj);
            dap_json_rpc_params_add_data(l_params, &l_int_tmp, TYPE_PARAM_INTEGER);
            break;
        case json_type_double:
            l_double_tmp = json_object_get_double(l_jobj);
            dap_json_rpc_params_add_data(l_params, &l_double_tmp, TYPE_PARAM_DOUBLE);
            break;
        default:
            dap_json_rpc_params_add_data(l_params, NULL, TYPE_PARAM_NULL);
        }
    }
    return  l_params;
}

char *dap_json_rpc_params_get_string_json(dap_json_rpc_params_t * a_params)
{
    log_it(L_NOTICE, "Translation struct params to JSON string");
    json_object *l_jobj_array = json_object_new_array();
    for (uint32_t i = 0; i <= a_params->lenght; i++){
        json_object *l_jobj_tmp = NULL;
        switch (a_params->params[i]->type) {
        case TYPE_PARAM_NULL:
            l_jobj_tmp = json_object_new_object();
            break;
        case TYPE_PARAM_STRING:
            l_jobj_tmp = json_object_new_string((char*)a_params->params[i]->value_param);
            break;
        case TYPE_PARAM_INTEGER:
            l_jobj_tmp = json_object_new_int64(*((int64_t*)a_params->params[i]->value_param));
            break;
        case TYPE_PARAM_DOUBLE:
            l_jobj_tmp = json_object_new_double(*((double*)a_params->params[i]->value_param));
            break;
        case TYPE_PARAM_BOOLEAN:
            l_jobj_tmp = json_object_new_boolean(*((bool*)a_params->params[i]->value_param));
            break;
        }
        json_object_array_add(l_jobj_array, l_jobj_tmp);
        json_object_put(l_jobj_tmp);
    };
    char *l_str = dap_strjoin(NULL, "\"params\":", json_object_to_json_string(l_jobj_array), NULL);
    json_object_put(l_jobj_array);
    return l_str;
}
