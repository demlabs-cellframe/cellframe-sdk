#include "dap_json_rpc.h"

static bool init_module = false;

int dap_json_rpc_init(){
    init_module = true;
    return 0;
}

void dap_json_rpc_deinit(){
    //
}
