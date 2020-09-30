#include "dap_json_rpc_response_handler.h"

#define LOG_TAG "dap_json_rpc_response_handler"

static dap_json_rpc_response_handler_t *s_response_handlers = NULL;
static uint64_t s_delta = 0;

int dap_json_rpc_response_registration_with_id(uint64_t a_id, dap_json_rpc_response_handler_func_t *func)
{
    dap_json_rpc_response_handler_t *l_handler = NULL;
    HASH_FIND_INT(s_response_handlers, &a_id, l_handler);
    if (l_handler == NULL){
        l_handler = DAP_NEW(dap_json_rpc_response_handler_t);
        l_handler->id = a_id;
        l_handler->func = func;
        HASH_ADD_INT(s_response_handlers, id, l_handler);
        log_it(L_NOTICE, "Registrayion handler response with id: %d", a_id);
        return 0;
    }
    return 1;
}
uint64_t dap_json_rpc_response_registration(dap_json_rpc_response_handler_func_t *func)
{
    uint64_t l_id_registration_response = dap_json_rpc_response_get_new_id();
    int res = dap_json_rpc_response_registration_with_id(l_id_registration_response, func);
    return res;
}
void dap_json_rpc_response_unregistration(uint64_t a_id)
{
    dap_json_rpc_response_handler_t *l_handler = NULL;
    HASH_FIND_INT(s_response_handlers, &a_id, l_handler);
    if (l_handler != NULL){
        HASH_DEL(s_response_handlers, l_handler);
        DAP_FREE(l_handler);
        log_it(L_NOTICE, "Unregistrayion handler response with id: %d", a_id);
    }
}

void dap_json_rpc_response_handler(dap_json_rpc_response_t *a_response)
{
    dap_json_rpc_response_handler_t *l_handler = NULL;
    HASH_FIND_INT(s_response_handlers, (void*)a_response->id, l_handler);
    if (l_handler != NULL){
        log_it(L_NOTICE, "Calling handler response id: %d", a_response->id);
        l_handler->func(a_response);
        dap_json_rpc_response_unregistration(a_response->id);
    } else {
        log_it(L_NOTICE, "Can't calling handler response id: %d. This handler not found", a_response->id);
    }
}

uint64_t dap_json_rpc_response_get_new_id(void)
{
    uint64_t l_ret = s_delta;
    s_delta++;
    return l_ret;
}

void dap_json_rpc_response_accepted(void *a_data, size_t a_size_data, void *a_obj)
{
    (void) a_obj;
    log_it(L_NOTICE, "Pre handling response");
    char *l_str = DAP_NEW_SIZE(char, a_size_data);
    memcpy(l_str, a_data, a_size_data);
    dap_json_rpc_response_t *l_response = dap_json_rpc_response_from_json(l_str);
    DAP_FREE(l_str);
    dap_json_rpc_response_handler(l_response);
    dap_json_rpc_response_free(l_response);
}
