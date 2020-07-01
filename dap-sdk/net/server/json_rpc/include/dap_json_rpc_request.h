#pragma once
#include "dap_common.h"
#include "dap_json_rpc_params.h"

typedef struct dap_json_rpc_request{
    char* method;
    dap_json_rpc_params_t *params;
    void* id;
}dap_json_rpc_request_t;

dap_json_rpc_request_t *dap_json_rpc_request_from_json(char *data);
char *dap_json_rpc_request_to_json(dap_json_rpc_request_t *data);
