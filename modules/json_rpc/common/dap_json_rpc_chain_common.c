#include "dap_json_rpc_chain_common.h"
#include "json.h"

#define LOG_TAG "dap_json_rpc_chain_common"

/**
 * @brief dap_chain_addr_to_json
 * @param a_addr
 * @return
 */
json_object *dap_chain_addr_to_json(const dap_chain_addr_t *a_addr){
    char *l_addr_str = dap_chain_addr_to_str(a_addr);
    if (!l_addr_str) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    json_object *l_obj = json_object_new_string(l_addr_str);
    DAP_DELETE(l_addr_str);
    if (!l_obj) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    return l_obj;
}
