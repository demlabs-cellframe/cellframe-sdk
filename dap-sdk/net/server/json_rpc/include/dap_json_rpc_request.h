#pragma once
#include "dap_common.h"
#include "dap_json_rpc_params.h"
#include "json-c/json.h"
#include "dap_string.h"

typedef struct dap_json_rpc_request{
    char* method;
    dap_json_rpc_params_t *params;
    int64_t id;
}dap_json_rpc_request_t;

dap_json_rpc_request_t *dap_json_rpc_request_creation(const char *a_method, dap_json_rpc_params_t *a_params, int64_t a_id);

dap_json_rpc_request_t *dap_json_rpc_request_from_json(const char *a_data);
char *dap_json_rpc_request_to_json(const dap_json_rpc_request_t *a_request);
