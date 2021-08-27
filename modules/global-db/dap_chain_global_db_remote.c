#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <dap_common.h>
#include <dap_strfuncs.h>
#include <dap_string.h>
#include "dap_chain.h"
#include "dap_chain_global_db.h"
#include "dap_chain_global_db_remote.h"

#define LOG_TAG "dap_chain_global_db_remote"

// default time of node address expired in hours
#define NODE_TIME_EXPIRED_DEFAULT 720

static bool dap_db_set_cur_node_addr_common(uint64_t a_address, char *a_net_name, time_t a_expire_time)
{
    if(!a_net_name)
        return false;
    char *l_key = dap_strdup_printf("cur_node_addr_%s", a_net_name);
    uint64_t * l_address = DAP_NEW_Z(uint64_t);
    *l_address = a_address;
    bool l_ret = dap_chain_global_db_gr_set(l_key, (uint8_t*) l_address, sizeof(a_address), GROUP_LOCAL_GENERAL);
    //DAP_DELETE(l_key);
    if(l_ret) {
        time_t *l_cur_time = DAP_NEW_Z(time_t);
        *l_cur_time= a_expire_time;
        char *l_key_time = dap_strdup_printf("cur_node_addr_%s_time", a_net_name);
        l_ret = dap_chain_global_db_gr_set( dap_strdup(l_key_time), (uint8_t*) l_cur_time, sizeof(time_t), GROUP_LOCAL_GENERAL);
        DAP_DELETE(l_key_time);
    }
    return l_ret;
}

/**
 * Set addr for current node and no expire time
 */
bool dap_db_set_cur_node_addr(uint64_t a_address, char *a_net_name )
{
    return dap_db_set_cur_node_addr_common(a_address,a_net_name,0);
}

/**
 * Set addr for current node and expire time
 */
bool dap_db_set_cur_node_addr_exp(uint64_t a_address, char *a_net_name )
{
    time_t l_cur_time = time(NULL);
    return dap_db_set_cur_node_addr_common(a_address,a_net_name,l_cur_time);
}



/**
 * Get addr for current node
 */
uint64_t dap_db_get_cur_node_addr(char *a_net_name)
{
    size_t l_node_addr_len = 0, l_node_time_len = 0;
    if(!a_net_name)
        return 0;
    char *l_key = dap_strdup_printf("cur_node_addr_%s", a_net_name);
    char *l_key_time = dap_strdup_printf("cur_node_addr_%s_time", a_net_name);
    uint8_t *l_node_addr_data = dap_chain_global_db_gr_get(l_key, &l_node_addr_len, GROUP_LOCAL_GENERAL);
    uint8_t *l_node_time_data = dap_chain_global_db_gr_get(l_key_time, &l_node_time_len, GROUP_LOCAL_GENERAL);
    uint64_t l_node_addr_ret = 0;
    time_t l_node_time = 0;
    if(l_node_addr_data && l_node_addr_len == sizeof(uint64_t))
        memcpy(&l_node_addr_ret, l_node_addr_data, l_node_addr_len);
    if(l_node_time_data && l_node_time_len == sizeof(time_t))
        memcpy(&l_node_time, l_node_time_data, l_node_time_len);
    // time delta in seconds
    static int64_t addr_time_expired = -1;
    // read time-expired
    if(addr_time_expired == -1) {
        dap_string_t *l_cfg_path = dap_string_new("network/");
        dap_string_append(l_cfg_path, a_net_name);
        dap_config_t *l_cfg;
        if((l_cfg = dap_config_open(l_cfg_path->str)) == NULL) {
            log_it(L_ERROR, "Can't open default network config");
            addr_time_expired = 0;
        } else {
            addr_time_expired = 3600 *
                    dap_config_get_item_int64_default(l_cfg, "general", "node-addr-expired",
                    NODE_TIME_EXPIRED_DEFAULT);
        }
        dap_string_free(l_cfg_path, true);
    }
    time_t l_dt = time(NULL) - l_node_time;
    //NODE_TIME_EXPIRED
    if(l_node_time && l_dt > addr_time_expired) {
        //log_it(L_NOTICE, "Node 0x%016X set last synced timestamp %"DAP_UINT64_FORMAT_U"", a_id);
        l_node_addr_ret = 0;
    }
    DAP_DELETE(l_key);
    DAP_DELETE(l_key_time);
    DAP_DELETE(l_node_addr_data);
    DAP_DELETE(l_node_time_data);
    return l_node_addr_ret;
}

/**
 * Set last id for remote node
 */
bool dap_db_set_last_id_remote(uint64_t a_node_addr, uint64_t a_id)
{
    //log_it( L_DEBUG, "Node 0x%016X set last synced timestamp %"DAP_UINT64_FORMAT_U"", a_node_addr, a_id);
    uint64_t *l_id = DAP_NEW(uint64_t);
    *l_id = a_id;
    return dap_chain_global_db_gr_set(dap_strdup_printf("%ju", a_node_addr),
                                      l_id, sizeof(uint64_t),
                                      GROUP_LOCAL_NODE_LAST_ID);
}

/**
 * Get last id for remote node
 */
uint64_t dap_db_get_last_id_remote(uint64_t a_node_addr)
{
    char *l_node_addr_str = dap_strdup_printf("%ju", a_node_addr);
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

/**
 * Set last hash for chain for remote node
 */
bool dap_db_set_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_hash)
{
    //log_it( L_DEBUG, "Node 0x%016X set last synced timestamp %"DAP_UINT64_FORMAT_U"", a_id);
    return dap_chain_global_db_gr_set(dap_strdup_printf("%ju%s%s", a_node_addr, a_chain->net_name, a_chain->name),
                                      a_hash, sizeof(*a_hash), GROUP_LOCAL_NODE_LAST_ID);
}

/**
 * Get last hash for chain for remote node
 */
dap_chain_hash_fast_t *dap_db_get_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain)
{
    char *l_node_chain_str = dap_strdup_printf("%ju%s%s", a_node_addr, a_chain->net_name, a_chain->name);
    size_t l_hash_len = 0;
    uint8_t *l_hash = dap_chain_global_db_gr_get((const char*)l_node_chain_str, &l_hash_len,
                                                 GROUP_LOCAL_NODE_LAST_ID);
    DAP_DELETE(l_node_chain_str);
    return (dap_chain_hash_fast_t *)l_hash;
}
