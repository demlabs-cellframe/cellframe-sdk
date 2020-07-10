#include "dap_json_rpc_request.h"

dap_json_rpc_request_t *dap_json_rpc_request_creation(const char *a_method, dap_json_rpc_params_t *a_params, int64_t a_id){
    dap_json_rpc_request_t *l_request = DAP_NEW(dap_json_rpc_request_t);
    l_request->method = dap_strdup(a_method);
    //l_request->params
    l_request->id = a_id;
    return l_request;
}

dap_json_rpc_request_t *dap_json_rpc_request_from_json(const char *a_data){
    json_object *l_jobj = json_object_new_string(a_data);
    json_object *l_jobj_methods =json_object_object_get(l_jobj, "method");
    json_object *l_jobj_params = json_object_object_get(l_jobj, "params");
    json_object *l_jobj_id = json_object_object_get(l_jobj, "id");
    dap_json_rpc_request_t *l_request = DAP_NEW(dap_json_rpc_request_t);
    l_request->id = json_object_get_int64(l_jobj_id);
    l_request->method = (char*)json_object_get_string(l_jobj_methods);
    l_request->params = dap_json_rpc_params_create_from_array_list(l_jobj_params);
    return l_request;

}
char *dap_json_rpc_request_to_json(const dap_json_rpc_request_t *a_request){
    char *l_str = dap_strjoin(NULL, "{method:\"", a_request->method, "\"", "params:",
                              dap_json_rpc_params_get_string_json(a_request->params), ", id: ", a_request->id, "}", NULL);
    return l_str;
}
