#include "dap_json_rpc_request_handler.h"

static dap_json_rpc_request_handler_t *s_handler_hash_table = NULL;

int dap_json_rpc_registration_request_handler(const char *a_name, handler_func *a_func){
    dap_json_rpc_request_handler_t *l_handler;
    HASH_FIND_STR(s_handler_hash_table, a_name, l_handler);
    if (l_handler == NULL){
        l_handler = DAP_NEW(dap_json_rpc_request_handler_t);
        l_handler->name = dap_strdup(a_name);
        l_handler->func = a_func;
        HASH_ADD_STR(s_handler_hash_table, name, l_handler);
        return 0;
    }
    return 1;
}
int dap_json_rpc_unregistration_request_handler(const char *a_name){
    dap_json_rpc_request_handler_t *l_handler;
    HASH_FIND_STR(s_handler_hash_table, a_name, l_handler);
    if (l_handler == NULL){
        return 1;
    } else {
        HASH_DEL(s_handler_hash_table, l_handler);
        DAP_FREE(l_handler->name);
        DAP_FREE(l_handler);
        return 0;
    }
}

void dap_json_rpc_request_handler(const char *a_method){

}
