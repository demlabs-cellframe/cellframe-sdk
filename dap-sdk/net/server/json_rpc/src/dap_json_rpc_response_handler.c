#include "dap_json_rpc_response_handler.h"

static dap_json_rpc_response_handler_t *s_response_handlers = NULL;

int dap_json_rpc_response_registration(int64_t a_id, dap_json_rpc_response_handler_func *func){
    dap_json_rpc_response_handler_t *l_handler = NULL;
//    HASH_FIND(hh, s_response_handlers, )
    HASH_FIND_INT(s_response_handlers, (void*)a_id, l_handler);
    if (l_handler == NULL){
        l_handler = DAP_NEW(dap_json_rpc_response_handler_t);
        l_handler->id = a_id;
        l_handler->func = func;
        HASH_ADD_INT(s_response_handlers, id, l_handler);
        return 0;
    }
    return 1;
}
void dap_json_rpc_response_unregistration(int64_t a_id){
    dap_json_rpc_response_handler_t *l_handler = NULL;
    HASH_FIND_INT(s_response_handlers, (void*)a_id, l_handler);
    if (l_handler != NULL){
        HASH_DEL(s_response_handlers, l_handler);
        DAP_FREE(l_handler);
    }
}

void dap_json_rpc_response_handler(int64_t a_id, dap_json_rpc_response_t *a_response){
    dap_json_rpc_response_handler_t *l_handler = NULL;
    HASH_FIND_INT(s_response_handlers, (void*)a_id, l_handler);
    if (l_handler != NULL){
        l_handler->func(a_response);
        dap_json_rpc_response_unregistration(a_id);
    }
}
