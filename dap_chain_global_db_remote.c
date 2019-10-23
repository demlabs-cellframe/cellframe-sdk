#include <string.h>
#include <stdlib.h>
#include <time.h>

//#include <dap_common.h>
#include <dap_strfuncs.h>
//#include "dap_chain_node.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#define LOG_TAG "dap_chain_global_db_remote"
/**
 * Set addr for current node
 */
bool dap_db_set_cur_node_addr(uint64_t a_address, char *a_net_name)
{
    if(!a_net_name)
        return false;
    char *l_key = dap_strdup_printf("cur_node_addr_%s", a_net_name);
    bool l_ret = dap_chain_global_db_gr_set(l_key, (uint8_t*) &a_address, sizeof(a_address), GROUP_LOCAL_GENERAL);
    DAP_DELETE(l_key);
    return l_ret;
}

/**
 * Get addr for current node
 */
uint64_t dap_db_get_cur_node_addr(char *a_net_name)
{
    size_t l_node_addr_len = 0;
    if(!a_net_name)
        return 0;
    char *l_key = dap_strdup_printf("cur_node_addr_%s", a_net_name);
    uint8_t *l_node_addr = dap_chain_global_db_gr_get(l_key, &l_node_addr_len, GROUP_LOCAL_GENERAL);
    uint64_t l_node_addr_ret = 0;
    if(l_node_addr && l_node_addr_len == sizeof(uint64_t))
        memcpy(&l_node_addr_ret, l_node_addr, l_node_addr_len);
    DAP_DELETE(l_key);
    DAP_DELETE(l_node_addr);
    return l_node_addr_ret;
}

/**
 * Set last id for remote node
 */
bool dap_db_log_set_last_id_remote(uint64_t a_node_addr, uint64_t a_id)
{
    dap_global_db_obj_t l_objs;
    l_objs.key = dap_strdup_printf("%lld", a_node_addr);
    l_objs.value = (uint8_t*) &a_id;
    l_objs.value_len = sizeof(uint64_t);
    bool l_ret = dap_chain_global_db_gr_save(&l_objs, 1, GROUP_LOCAL_NODE_LAST_ID);
    DAP_DELETE(l_objs.key);
    log_it( L_NOTICE, "Node 0x%016X set last synced timestamp %llu",a_id);
    return l_ret;
}

/**
 * Get last id for remote node
 */
uint64_t dap_db_log_get_last_id_remote(uint64_t a_node_addr)
{
    char *l_node_addr_str = dap_strdup_printf("%lld", a_node_addr);
    size_t l_timestamp_len = 0;
    uint8_t *l_timestamp = dap_chain_global_db_gr_get((const char*) l_node_addr_str, &l_timestamp_len,
    GROUP_LOCAL_NODE_LAST_ID);
    uint64_t l_ret_timestamp = 0;
    if(l_timestamp && l_timestamp_len == sizeof(uint64_t))
        memcpy(&l_ret_timestamp, l_timestamp, l_timestamp_len);
    DAP_DELETE(l_node_addr_str);
    DAP_DELETE(l_timestamp);
    return l_ret_timestamp;
}
