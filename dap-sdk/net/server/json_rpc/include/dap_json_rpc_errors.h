#pragma once

#include "dap_common.h"
#include "utlist.h"

typedef struct dap_json_rpc_error{
    int code_error;
    char *msg;
    void *next;
}dap_json_rpc_error_t;

dap_json_rpc_error_t *errors;


