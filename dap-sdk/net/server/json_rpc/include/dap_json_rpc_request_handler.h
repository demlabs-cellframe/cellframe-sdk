#pragma once

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_json_rpc_request.h"
#include "dap_json_rpc_params.h"
#include "dap_http_client.h"
#include "dap_json_rpc_errors.h"
#include "dap_json_rpc_response.h"
#include "dap_json_rpc_notification.h"
#include "uthash.h"

typedef void handler_func(dap_json_rpc_params_t *a_params, dap_json_rpc_response_t *a_response);

typedef  struct dap_json_rpc_request_handler{
    char *name;
    handler_func *func;
    UT_hash_handle hh;
}dap_json_rpc_request_handler_t;

int dap_json_rpc_registration_request_handler(const char *a_name, handler_func *a_func);
int dap_json_rpc_unregistration_request_handler(const char *a_name);

void dap_json_rpc_request_handler(dap_json_rpc_request_t *a_request, dap_client_remote_t *a_client_remote);
