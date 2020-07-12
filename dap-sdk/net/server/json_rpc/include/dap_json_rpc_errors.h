#pragma once

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "utlist.h"
#include "json-c/json.h"

#ifdef __cplusplus
extern "C"{
#endif

typedef struct dap_json_rpc_error{
    int code_error;
    char *msg;
    void *next;
}dap_json_rpc_error_t;

int dap_json_rpc_error_init(void);
void dap_json_rpc_error_deinit(void);

int dap_json_rpc_error_add(int a_code_error, const char *a_msg);

dap_json_rpc_error_t *dap_json_rpc_error_search_by_code(int a_code_error);

char *dap_json_rpc_error_get_json(dap_json_rpc_error_t *a_error);

dap_json_rpc_error_t *dap_json_rpc_create_from_json(const char *a_json);

#ifdef __cplusplus
}
#endif
