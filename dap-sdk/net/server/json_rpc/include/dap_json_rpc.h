#pragma once
#include "dap_common.h"
#include "dap_config.h"
#include "utlist.h"

#undef LOG_TAG
#define LOG_TAG "dap_json_rpc"

const char* v_specification = "1.0";

int dap_json_rpc_init();
void dap_json_rpc_deinit();
