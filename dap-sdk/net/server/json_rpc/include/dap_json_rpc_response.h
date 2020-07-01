#pragma once

#include "dap_json_rpc_errors.h"

typedef struct dap_json_rpc_response{
    void* result;
    dap_json_rpc_error_t* error;
    void* id;
}dap_json_rpc_response_t;
