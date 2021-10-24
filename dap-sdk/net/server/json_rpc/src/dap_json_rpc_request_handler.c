#include "dap_json_rpc_request_handler.h"

#define LOG_TAG "dap_json_rpc_request_handler"

static dap_json_rpc_request_handler_t *s_handler_hash_table = NULL;

int dap_json_rpc_registration_request_handler(const char *a_name, handler_func_t *a_func)
{
    dap_json_rpc_request_handler_t *l_handler;
    HASH_FIND_STR(s_handler_hash_table, a_name, l_handler);
    if (l_handler == NULL){
        l_handler = DAP_NEW(dap_json_rpc_request_handler_t);
        l_handler->name = dap_strdup(a_name);
        l_handler->func = a_func;
        HASH_ADD_STR(s_handler_hash_table, name, l_handler);
        log_it(L_NOTICE, "Registration handler for request name: %s", a_name);
        return 0;
    }
    return 1;
}
int dap_json_rpc_unregistration_request_handler(const char *a_name)
{
    dap_json_rpc_request_handler_t *l_handler;
    HASH_FIND_STR(s_handler_hash_table, a_name, l_handler);
    if (l_handler == NULL){
        return 1;
    } else {
    	log_it(L_NOTICE, "Unregistration for handler request name: %s", a_name);
        HASH_DEL(s_handler_hash_table, l_handler);
        DAP_FREE(l_handler->name);
        DAP_FREE(l_handler);
        return 0;
    }
}

void dap_json_rpc_request_handler(dap_json_rpc_request_t *a_request,  dap_http_simple_t *a_client)
{
	log_it(L_DEBUG, "Processing request");
    if (a_request->id == 0){
        dap_json_rpc_notification_handler(a_request->method, a_request->params);
    } else {
        dap_json_rpc_response_t *l_response = DAP_NEW(dap_json_rpc_response_t);
        l_response->id = a_request->id;
        dap_json_rpc_request_handler_t *l_handler = NULL;
        HASH_FIND_STR(s_handler_hash_table, a_request->method, l_handler);
        if (l_handler == NULL){
            dap_json_rpc_error_t *l_err = dap_json_rpc_error_search_by_code(1);
            l_response->type_result = TYPE_RESPONSE_NULL;
            l_response->error = l_err;
            log_it(L_NOTICE, "Can't processing the request. Handler %s not registration. ", a_request->method);
        } else {
            l_response->error = NULL;
            l_handler->func(a_request->params, l_response, a_request->method);
            log_it(L_NOTICE, "Calling handler request name: %s", a_request->method);
        }
        dap_json_rpc_response_send(l_response, a_client);
    }
}
