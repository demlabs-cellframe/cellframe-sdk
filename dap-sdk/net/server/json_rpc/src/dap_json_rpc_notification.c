#include "dap_json_rpc_notification.h"

#define LOG_TAG "dap_json_rpc_notification"

static dap_json_rpc_notification_handler_t *s_handler_notifications = NULL;


int dap_json_rpc_notification_registration(const char *a_method, notification_handler_func_t *a_notification_func)
{
    dap_json_rpc_notification_handler_t *l_handler;
    HASH_FIND_STR(s_handler_notifications, a_method, l_handler);
    if (l_handler == 0){
        l_handler = DAP_NEW(dap_json_rpc_notification_handler_t);
        l_handler->method = dap_strdup(a_method);
        l_handler->func = a_notification_func;
        HASH_ADD_STR(s_handler_notifications, method, l_handler);
        log_it(L_NOTICE, "Registration method %s for handler notification", a_method);
        return 0;
    }
    return 1;
}
void dap_json_rpc_notification_unregistration(const char *a_method)
{
    dap_json_rpc_notification_handler_t *l_handler;
    HASH_FIND_STR(s_handler_notifications, a_method, l_handler);
    if (l_handler != NULL){
        HASH_DEL(s_handler_notifications, l_handler);
        DAP_FREE(l_handler->method);
        DAP_FREE(l_handler);
        log_it(L_NOTICE, "Unregistration method %s. This method handler notification", a_method);
    }
}

void dap_json_rpc_notification_handler(const char *a_name_method, dap_json_rpc_params_t *a_params)
{
    dap_json_rpc_notification_handler_t *l_handler = NULL;
    HASH_FIND_STR(s_handler_notifications, a_name_method, l_handler);
    if (l_handler != NULL){
        l_handler->func(a_params);
        log_it(L_DEBUG, "Call method handling notfication: %s", a_name_method);
    } else {
        log_it(L_NOTICE, "Not found method %s. This method handler notification", a_name_method);
    }
}
