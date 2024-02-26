#include "dap_json_rpc_chain_common.h"
#include "json.h"

#define LOG_TAG "dap_json_rpc_chain_common"

/**
 * @brief dap_chain_addr_to_json
 * @param a_addr
 * @return
 */
json_object *dap_chain_addr_to_json(const dap_chain_addr_t *a_addr) {
    return json_object_new_string(dap_chain_addr_to_str(a_addr));
}
