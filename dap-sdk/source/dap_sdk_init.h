#pragma once

#include "dap_core.h"
#include "dap_crypto.h"
#include "json-c/json.h"

typedef struct dap_sdk_init_arg{
    const char *param;
    void *value;
}dap_sdk_init_arg_t;

typedef struct dap_sdk_init_module{
    const char *module;
    dap_sdk_init_arg_t *argv;
}dap_sdk_init_module_t;

int dap_sdk_init(dap_sdk_init_module_t *a_modules);

//typedef enum dap_sdk_module_init_type_arg{
//    DAP_SDK_MODULE_INIT_ARG_STRING = 0xFF
////    DAP_SDK_MODULE_INIT_ARG_G_CONFIG
//}dap_sdk_module_init_type_arg_t;

//typedef struct dap_sdk_module_init{
//    const char *name_module;
//    void **argv;
//    dap_sdk_module_init_type_arg_t* types;
//}dap_sdk_module_init_t;

//typedef struct dap_sdk_module{
//    char *name;
//    void *init;
//    void *deinit;
//}dap_sdk_module_t;
//typedef struct dap_sdk_module_map{}dap_sdk_module_map_t;


//bool dap_sdk_init(char *json);
//bool dap_sdk_init(dap_sdk_module_init_t *a_initial_list);
//bool dap_sdk_init(void *a_initial_list);
