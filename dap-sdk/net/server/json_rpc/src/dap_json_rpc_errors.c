#include "dap_json_rpc_errors.h"

static dap_json_rpc_error_t *s_errors;
int _dap_json_rpc_error_cmp_by_code(dap_json_rpc_error_t *a_error, int a_code_error);

int dap_json_rpc_error_init(void){
    s_errors = NULL;
    return  0;
}
void dap_json_rpc_error_deinit(void){
    dap_json_rpc_error_t *err, *tmp;
    if (s_errors != NULL){
        LL_FOREACH_SAFE(s_errors, err, tmp){
            LL_DELETE(s_errors, err);
            DAP_FREE(err->msg);
            DAP_FREE(err);
        }
    }
}

int dap_json_rpc_error_add(int a_code_error, const char *a_msg){
    dap_json_rpc_error_t *l_el_search =dap_json_rpc_error_search_by_code(a_code_error);
    if (l_el_search != NULL)
        return 1;
    dap_json_rpc_error_t *l_error = DAP_NEW(dap_json_rpc_error_t);
    l_error->code_error = a_code_error;
    l_error->msg = dap_strdup(a_msg);
    LL_APPEND(s_errors, l_error);
    return 0;
}

int _dap_json_rpc_error_cmp_by_code(dap_json_rpc_error_t *a_error, int a_code_error){
    if (a_error->code_error == a_code_error)
        return 0;
    if (a_error->code_error < a_code_error)
        return -1;
    if (a_error->code_error > a_code_error)
        return 1;
}

dap_json_rpc_error_t *dap_json_rpc_error_search_by_code(int a_code_error){
    dap_json_rpc_error_t *l_element = NULL;
    LL_SEARCH(s_errors, l_element, a_code_error, _dap_json_rpc_error_cmp_by_code);
    return l_element;
}

char *dap_json_rpc_error_get_json(dap_json_rpc_error_t *a_error){
    char *l_json_str = dap_strjoin(NULL, "error: {", "code: ", a_error->code_error, ",", "message:\"", a_error->msg, "\"}");
    return l_json_str;
}

dap_json_rpc_error_t *dap_json_rpc_create_from_json(const char *a_json){
    json_object *l_jobj = json_object_new_string(a_json);
    json_object *l_jobj_code_eror = json_object_object_get(l_jobj, "code");
    json_object *l_obj_msg = json_object_object_get(l_jobj, "message");
    dap_json_rpc_error_t *l_error = DAP_NEW(dap_json_rpc_error_t);
    l_error->code_error = json_object_get_int(l_jobj_code_eror);
    l_error->msg = dap_strdup(json_object_get_string(l_obj_msg));
    return l_error;
}
