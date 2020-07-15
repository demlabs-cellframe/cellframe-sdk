#pragma once

#include "dap_json_rpc_response.h"
#include "uthash.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef void dap_json_rpc_response_handler_func(dap_json_rpc_response_t *a_response);

typedef struct dap_json_rpc_response_handler{
    dap_json_rpc_response_handler_func *func;
    int64_t id;
    UT_hash_handle hh;
}dap_json_rpc_response_handler_t;

int dap_json_rpc_response_registration(int64_t a_id, dap_json_rpc_response_handler_func *func);
void dap_json_rpc_response_unregistration(int64_t a_id);

void dap_json_rpc_response_handler(int64_t a_id, dap_json_rpc_response_t *a_response);

#ifdef __cplusplus
}
#endif
