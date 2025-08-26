#include "dap_chain_btc_rpc.h"

int dap_chain_btc_rpc_init(){
    dap_chain_btc_rpc_registration_handlers();
    return 0;
}
void dap_chain_btc_rpc_deinit(){
    dap_chain_btc_rpc_unregistration_handlers();
}
