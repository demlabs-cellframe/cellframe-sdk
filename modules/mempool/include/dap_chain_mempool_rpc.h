#pragma once
#include "dap_json_rpc.h"

int dap_chain_mempool_rpc_init(void);

void dap_chain_mempool_rpc_handler_list(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method);
void dap_chain_mempool_rpc_handler_test(dap_json_rpc_params_t *a_params,
                                        dap_json_rpc_response_t *a_response, const char *a_method);
                                        
