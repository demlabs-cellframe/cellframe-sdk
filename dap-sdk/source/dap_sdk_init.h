#pragma once

#include "dap_core.h"
#include "dap_crypto.h"
#include "json-c/json.h"
#include "dap_net.h"

typedef struct dap_sdk_init_arg{
    const char *param;
    void *value;
}dap_sdk_init_arg_t;

typedef struct dap_sdk_init_module{
    const char *module;
    dap_sdk_init_arg_t *argv;
}dap_sdk_init_module_t;

int dap_sdk_init(dap_sdk_init_module_t *a_modules);
