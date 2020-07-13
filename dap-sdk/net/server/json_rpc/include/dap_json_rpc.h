#pragma once
#include "dap_http.h"
#include "dap_strfuncs.h"
#include "dap_json_rpc_request.h"
#include "dap_json_rpc_request_handler.h"

typedef enum dap_json_rpc_version{
    RPC_VERSION_1
}dap_json_rpc_version_t;

const char* v_specification = "1.0";

int dap_json_rpc_init();
void dap_json_rpc_deinit();
void dap_json_rpc_add_proc_http(struct dap_http *sh, const char *URL);
