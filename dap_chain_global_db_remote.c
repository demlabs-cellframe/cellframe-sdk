#include <string.h>
#include <stdlib.h>

//#include <dap_common.h>
#include <dap_strfuncs.h>
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

/**
 * Set last timestamp for remote node
 */
bool dap_db_log_set_last_timestamp_remote(uint64_t a_node_addr, time_t a_timestamp)
{
    dap_global_db_obj_t l_objs;
    l_objs.key = dap_strdup_printf("%lld", a_node_addr);
    l_objs.value = dap_strdup_printf("%lld", a_timestamp);
    bool l_ret = dap_chain_global_db_gr_save(&l_objs, 1, GROUP_REMOTE_NODE);
    DAP_DELETE(l_objs.key);
    DAP_DELETE(l_objs.value);
    return l_ret;
}

/**
 * Get last timestamp for remote node
 */
time_t dap_db_log_get_last_timestamp_remote(uint64_t a_node_addr)
{
    char *l_node_addr_str = dap_strdup_printf("%lld", a_node_addr);
    size_t l_node_addr_str_len = 0;
    char *l_timestamp_str = dap_chain_global_db_gr_get((const char*) l_node_addr_str, &l_node_addr_str_len, GROUP_REMOTE_NODE);
    time_t l_ret_timestamp = (l_timestamp_str) ? strtoll(l_timestamp_str, NULL,10) : 0;
    DAP_DELETE(l_node_addr_str);
    DAP_DELETE(l_timestamp_str);
    return l_ret_timestamp;
}
