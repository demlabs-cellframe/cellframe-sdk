/*
 * Authors:
 * Pavel Uhanov <pavel.uhanov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_chain_node_rpc.h"
#include "dap_global_db.h"
#include "dap_global_db_cluster.h"
#include "dap_stream.h"
#include "dap_cli_server.h"

#define LOG_TAG "dap_chain_node_rpc"
#define DAP_CHAIN_NODE_RPC_STATES_INFO_CURRENT_VERSION 1

typedef enum {
    RPC_ROLE_INVALID = 0,
    RPC_ROLE_USER,
    RPC_ROLE_BALANCER,
    RPC_ROLE_SERVER,
    RPC_ROLE_ROOT
} rpc_role_t;

struct cmd_call_stat {
    atomic_int_fast32_t count;
    atomic_int_fast64_t time;
};

static const uint64_t s_timer_update_states_info = 10 /*sec*/ * 1000;
static const char s_rpc_server_states_group[] = "rpc.states";
static const char s_rpc_node_list_group[] = "rpc.list";
static dap_global_db_cluster_t *s_rpc_server_states_cluster = NULL;
static dap_global_db_cluster_t *s_rpc_node_list_cluster = NULL;
static rpc_role_t s_curretn_role = RPC_ROLE_INVALID;


static struct cmd_call_stat *s_cmd_call_stat = NULL;

DAP_STATIC_INLINE s_get_role_from_str(const char *a_str)
{
    if (!a_str) return RPC_ROLE_INVALID;
    if (!strcmp(a_str, "user")) return RPC_ROLE_USER;
    if (!strcmp(a_str, "balancer")) return RPC_ROLE_BALANCER;
    if (!strcmp(a_str, "server")) return RPC_ROLE_SERVER;
    if (!strcmp(a_str, "root")) return RPC_ROLE_SERVER;
    return RPC_ROLE_INVALID;
}

static void s_collect_cmd_stat_info(int16_t a_cmd_num, int64_t a_call_time)
{
    dap_return_if_pass(a_cmd_num >= DAP_CHAIN_NODE_CLI_CMD_ID_TOTAL);
    atomic_fetch_add(&(s_cmd_call_stat + a_cmd_num)->count, 1);
    atomic_fetch_add(&(s_cmd_call_stat + a_cmd_num)->time, a_call_time);
}

#ifdef UNIX
/**
 * @brief get states info about current
 * @param a_arg - pointer to callback arg
 */
static void s_update_node_rpc_states_info(UNUSED_ARG void *a_arg)
{
    dap_chain_node_rpc_states_info_t *l_info = DAP_NEW_Z_RET_IF_FAIL(dap_chain_node_rpc_states_info_t);
    l_info->version = DAP_CHAIN_NODE_RPC_STATES_INFO_CURRENT_VERSION;
    l_info->address.uint64 = g_node_addr.uint64;
    l_info->links_count = dap_stream_get_links_count();
    l_info->cli_thread_count = dap_cli_get_cmd_thread_count();
    sysinfo(&l_info->sysinfo);
    for(int16_t i = 0; i < DAP_CHAIN_NODE_CLI_CMD_ID_TOTAL; ++i) {
        int32_t l_count = atomic_load(&(s_cmd_call_stat + i)->count);
        int64_t l_time = atomic_load(&(s_cmd_call_stat + i)->time);
        l_info->cmd_info.time_stat[i] = l_count ? l_time / l_count : 0;
    }

    const char *l_node_addr_str = dap_stream_node_addr_to_str_static(l_info->address);
    dap_global_db_set_sync(s_rpc_server_states_group, l_node_addr_str, l_info, sizeof(dap_chain_node_rpc_states_info_t), false);
    DAP_DELETE(l_info);
}
#endif

static int s_rpc_node_cmp(dap_list_t *a_list1, dap_list_t *a_list2)
{
    return 0;
}

void dap_chain_node_rpc_init(dap_config_t *a_cfg)
{
    rpc_role_t l_role = s_get_role_from_str(dap_config_get_item_str(a_cfg, "rpc", "role"));
    
    if (l_role != RPC_ROLE_INVALID) {
        if (!(s_rpc_node_list_cluster = dap_global_db_cluster_add(
                dap_global_db_instance_get_default(), DAP_STREAM_CLUSTER_GLOBAL,
                *(dap_guuid_t *)&uint128_0, s_rpc_node_list_group,
                0,
                true, DAP_GDB_MEMBER_ROLE_GUEST, DAP_CLUSTER_TYPE_EMBEDDED)))
        {
            log_it(L_ERROR, "Can't create rpc node list cluster");
            return;
        }
        dap_stream_node_addr_t *l_authorized_nodes = NULL;
        uint16_t l_authorized_nodes_count = 0;
        dap_config_stream_addrs_parse(a_cfg, "rpc", "authorized_nodes_addrs", &l_authorized_nodes, &l_authorized_nodes_count);
        for (uint16_t i = 0; i < l_authorized_nodes_count; ++i)
            dap_global_db_cluster_member_add(s_rpc_node_list_cluster, l_authorized_nodes + i, DAP_GDB_MEMBER_ROLE_ROOT);
        DAP_DELETE(l_authorized_nodes);
    } else {
        log_it(L_ERROR, "Can't recognized rpc role, please check config");
        return;
    }
    if (l_role == RPC_ROLE_SERVER || l_role == RPC_ROLE_BALANCER || l_role == RPC_ROLE_USER) {
        if (!(s_rpc_server_states_cluster = dap_global_db_cluster_add(
            dap_global_db_instance_get_default(), DAP_STREAM_CLUSTER_GLOBAL,
            *(dap_guuid_t *)&uint128_0, s_rpc_server_states_group,
            0,
            true, DAP_GDB_MEMBER_ROLE_USER, DAP_CLUSTER_TYPE_EMBEDDED)))
        {
            log_it(L_ERROR, "Can't create rpc server states cluster");
            return;
        }
        if (l_role == RPC_ROLE_SERVER) {
#ifdef UNIX
            if (dap_proc_thread_timer_add(NULL, s_update_node_rpc_states_info, NULL, s_timer_update_states_info)) {
                log_it(L_ERROR, "Can't activate timer on node states update");
            } else {
                s_cmd_call_stat = DAP_NEW_Z_COUNT_RET_IF_FAIL(struct cmd_call_stat, DAP_CHAIN_NODE_CLI_CMD_ID_TOTAL);
                dap_cli_server_statistic_callback_add(s_collect_cmd_stat_info);
            }
#else
            log_it(L_ERROR, "RPC server role avaible only on unix system");
#endif
        }
    }
    if (l_role == RPC_ROLE_ROOT && !dap_chain_node_rpc_is_my_node_authorized())
        log_it(L_WARNING, "Your addres not finded in authorized rpc node list"); 
}

void dap_chain_node_rpc_deinit()
{
    DAP_DELETE(s_cmd_call_stat);
}

/**
 * @brief get states rpc info about current
 * @param a_arg - pointer to callback arg
 */
dap_string_t *dap_chain_node_rpc_states_info_read(dap_stream_node_addr_t a_addr)
{
    dap_nanotime_t l_timestamp = 0;
    size_t l_data_size = 0;
    dap_string_t *l_ret = dap_string_new("");
    const char *l_node_addr_str = dap_stream_node_addr_to_str_static(a_addr.uint64 ? a_addr : g_node_addr);
    dap_chain_node_rpc_states_info_t *l_node_info = (dap_chain_node_rpc_states_info_t *)dap_global_db_get_sync(s_rpc_server_states_group, l_node_addr_str, &l_data_size, NULL, &l_timestamp);
    if (!l_node_info) {
        log_it(L_ERROR, "Can't find state of rpc node %s", l_node_addr_str);
        dap_string_append_printf(l_ret, "Can't find state of %s rpc node", l_node_addr_str);
        return l_ret;
    }
    char l_ts[80] = { '\0' };
    dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), l_timestamp);
    dap_string_append_printf(l_ret,
        "Record timestamp: %s\nRecord version: %u\nNode addr: %s\n"
        "Location: %s\nCli thread count: %u\nLinks count: %u\n",
        l_ts, l_node_info->version, l_node_addr_str,
        l_node_info->location, l_node_info->cli_thread_count, l_node_info->links_count);
    return l_ret;
}


bool dap_chain_node_rpc_is_my_node_authorized()
{
    return dap_cluster_member_find_role(s_rpc_node_list_cluster->role_cluster, &g_node_addr) == DAP_GDB_MEMBER_ROLE_ROOT;
}

/**
 * @brief save rpc node info to gdb
 * @param node_info
 * @return
 */
int dap_chain_node_rpc_info_save(dap_chain_node_info_t *a_node_info)
{
    return !a_node_info || !a_node_info->address.uint64
        ? log_it(L_ERROR,"Can't save node rpc info, %s", a_node_info ? "null arg" : "zero address"), -1
        : dap_global_db_set_sync( s_rpc_node_list_group,
                                 dap_stream_node_addr_to_str_static(a_node_info->address),
                                 a_node_info,
                                 dap_chain_node_info_get_size(a_node_info), false );
}

/**
 * @brief Return string by rpc nore list
 * @return pointer to dap_string_t if Ok, NULL if error
 */
dap_string_t *dap_chain_node_rpc_list()
{
    dap_string_t *l_ret = dap_string_new("RPC node list:\n");
    size_t l_nodes_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(s_rpc_node_list_group, &l_nodes_count);

    if(!l_nodes_count || !l_objs) {
        dap_string_append_printf(l_ret, "No records\n");
        return NULL;
    } else {
        dap_string_append_printf(l_ret, "Got %zu nodes:\n", l_nodes_count);
        dap_string_append_printf(l_ret, "%-26s%-20s%-8s%s", "Address", "IPv4", "Port", "Timestamp\n");

        for (size_t i = 0; i < l_nodes_count; i++) {
            dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t*)l_objs[i].value;
            if (dap_chain_node_addr_is_blank(&l_node_info->address)){
                log_it(L_ERROR, "Node address is empty");
                continue;
            }

            char l_ts[DAP_TIME_STR_SIZE] = { '\0' };
            dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), l_objs[i].timestamp);

            dap_string_append_printf(l_ret, NODE_ADDR_FP_STR"    %-20s%-8d%-32s\n",
                                        NODE_ADDR_FP_ARGS_S(l_node_info->address),
                                        l_node_info->ext_host, l_node_info->ext_port,
                                        l_ts);
        }
    }
    dap_global_db_objs_delete(l_objs, l_nodes_count);
    return l_ret;
}

/**
 * @brief get states rpc info about current
 * @param a_arg - pointer to callback arg
 */
dap_list_t *dap_chain_node_rpc_get_states_list_sort(size_t *a_count)
{
    size_t l_count = 0;
    dap_list_t *l_ret = NULL;
    dap_global_db_obj_t *l_nodes_obj = dap_global_db_get_all_sync(s_rpc_node_list_group, &l_count);
    for (size_t i = 0; i < l_count; ++i) {
        size_t l_data_size = 0;
        dap_chain_node_info_t *l_node_info_curr = dap_global_db_get_sync(s_rpc_server_states_group, (l_nodes_obj + i)->key, &l_data_size, NULL, NULL);
        if (!l_node_info_curr) {
            log_it(L_ERROR, "Can't find info about rpc node %s", (l_nodes_obj + i)->key);
            continue;
        }
        if (l_data_size != sizeof(l_node_info_curr)) {
            log_it(L_ERROR, "Error data size in rpc node state, get %zu expected %zu", l_data_size, sizeof(l_node_info_curr));
            continue;
        }
        l_ret = dap_list_insert_sorted(l_ret, (void *)l_node_info_curr, s_rpc_node_cmp);
    }
    if (a_count)
        *a_count = l_count;
    return l_ret;
}

dap_chain_node_rpc_states_info_t *dap_chain_node_rpc_get_states_sort(size_t *a_count)
{
    size_t l_count = 0;
    dap_list_t *l_nodes_list = dap_chain_node_rpc_get_states_list_sort(&l_count);
    if(!l_nodes_list || !l_count) {
        log_it(L_DEBUG, "No any information about rpc states");
        return NULL;
    }
    // memory alloc
    dap_chain_node_rpc_states_info_t *l_ret = DAP_NEW_Z_COUNT(dap_chain_node_rpc_states_info_t, l_count);
    if (!l_ret) {
        log_it(L_ERROR, "%s", c_error_memory_alloc);
        dap_list_free_full(l_nodes_list, NULL);
        return NULL;
    }
// func work
    size_t j = 0;
    for(dap_list_t *i = l_nodes_list; i && j < l_count; i = i->next, ++j) {
        dap_mempcpy(l_ret + j, i->data, sizeof(dap_chain_node_rpc_states_info_t));
    }
    dap_list_free_full(l_nodes_list, NULL);
    if (a_count)
        *a_count = l_count;
    return l_ret;
}

DAP_INLINE bool dap_chain_node_rpc_is_balancer_node()
{
    return s_curretn_role == RPC_ROLE_BALANCER;
}