#pragma once
#include "dap_common.h"

enum dap_json_rpc_type_param{
    null,
    object,
    string,
    integer,
    array,
    boolean
};

typedef struct dap_json_rpc_params{
    char *name_param;
    void *value_param;
    enum dap_json_rpc_type_param type;
    struct dap_json_rpc_params *next;
}dap_json_rpc_params_t;
