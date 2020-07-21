#include "dap_json_rpc_request.h"

#define LOG_TAG "dap_json_rpc_request"

static char *s_url_service = NULL;

int dap_json_rpc_request_init(const char *a_url_service){
    if (s_url_service == NULL){
        s_url_service = dap_strdup(a_url_service);
        return  0;
    }
    return 1;
}

dap_json_rpc_request_t *dap_json_rpc_request_creation(const char *a_method, dap_json_rpc_params_t *a_params, int64_t a_id){
    dap_json_rpc_request_t *l_request = DAP_NEW(dap_json_rpc_request_t);
    l_request->method = dap_strdup(a_method);
    l_request->params = a_params;
    //l_request->params
    l_request->id = a_id;
    return l_request;
}

dap_json_rpc_request_t *dap_json_rpc_request_from_json(const char *a_data){
    log_it(L_DEBUG, "Translation JSON string to struct dap_json_rpc_request");
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
//    json_object *l_jobj = json_object_new_object();
    log_it(L_DEBUG, "Translation struct dap_json_rpc_request to JSON string");
    char *l_str = dap_strjoin(NULL, "{\"method=\":", "\"", a_request->method, "\"", "\"", "\"params\":",
                              dap_json_rpc_params_get_string_json(a_request->params), ", \"id\": ", a_request->id, "}", NULL);
    return l_str;
}

void dap_json_rpc_request_send(dap_json_rpc_request_t *a_request, dap_json_rpc_response_handler_func_t *response_handler,
                               const char *a_uplink_addr, const uint16_t a_uplink_port,
                               dap_client_http_callback_error_t func_error){
    uint64_t l_id_response = dap_json_rpc_response_registration(response_handler);
    a_request->id = l_id_response;
    char *l_str = dap_json_rpc_request_to_json(a_request);
    log_it(L_NOTICE, "Sending request in address: %s", a_uplink_addr);
    dap_client_http_request(a_uplink_addr, a_uplink_port, "POST", "application/json", s_url_service, l_str, strlen(l_str),
                            NULL, dap_json_rpc_response_accepted, func_error, NULL, NULL);
}
