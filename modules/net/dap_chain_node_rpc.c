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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>


#include <sys/sysinfo.h>
#include <sys/vfs.h>

#include "dap_chain_net.h"
#include "dap_global_db.h"
#include "dap_stream.h"

#define LOG_TAG "dap_chain_node_rpc"
#define DAP_CHAIN_NODE_RPC_STATES_INFO_CURRENT_VERSION 1
typedef struct dap_chain_node_rpc_states_info
{
    uint32_t version;
    dap_chain_node_addr_t address;
    uint32_t location;
    uint32_t links_count;
    uint32_t cli_thread_count;
    struct sysinfo sysinfo;
} DAP_ALIGN_PACKED dap_chain_node_rpc_states_info_t;

static const uint64_t s_timer_update_states_info = 10 /*sec*/ * 1000;
static const char s_rpc_states_group[] = "rpc.states";
static const char s_rpc_list_group[] = "rpc.list";
static dap_global_db_cluster_t *s_rpc_states_cluster = NULL;
static dap_global_db_cluster_t *s_rpc_list_cluster = NULL;

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
    sysinfo(&l_info->sysinfo);

    const char *l_node_addr_str = dap_stream_node_addr_to_str_static(l_info->address);
    dap_global_db_set_sync(s_rpc_states_group, l_node_addr_str, l_info, sizeof(dap_chain_node_rpc_states_info_t), false);
    DAP_DELETE(l_info);
}

void dap_chain_node_rpc_init(dap_config_t *a_cfg)
{
    if (!(s_rpc_states_cluster = dap_global_db_cluster_add(
              dap_global_db_instance_get_default(), DAP_STREAM_CLUSTER_GLOBAL,
              *(dap_guuid_t *)&uint128_0, s_rpc_states_group,
              0,
              true, DAP_GDB_MEMBER_ROLE_USER, DAP_CLUSTER_TYPE_EMBEDDED)))
        return;
    if (!(s_rpc_list_cluster = dap_global_db_cluster_add(
              dap_global_db_instance_get_default(), DAP_STREAM_CLUSTER_GLOBAL,
              *(dap_guuid_t *)&uint128_0, s_rpc_list_group,
              0,
              true, DAP_GDB_MEMBER_ROLE_GUEST, DAP_CLUSTER_TYPE_EMBEDDED)))
        return;
    dap_stream_node_addr_t *l_authorized_nodes = NULL;
    uint16_t l_authorized_nodes_count = 0;
    dap_config_stream_addrs_parse(a_cfg, "cli-server", "authorized_nodes_addrs_rpc", &l_authorized_nodes, &l_authorized_nodes_count);
    for (uint16_t i = 0; i < l_authorized_nodes_count; ++i)
        dap_global_db_cluster_member_add(s_rpc_list_cluster, l_authorized_nodes + i, DAP_GDB_MEMBER_ROLE_ROOT);
    DAP_DELETE(l_authorized_nodes);
    if (dap_proc_thread_timer_add(NULL, s_update_node_rpc_states_info, NULL, s_timer_update_states_info))
        log_it(L_ERROR, "Can't activate timer on node states update");
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
    dap_chain_node_rpc_states_info_t *l_node_info = (dap_chain_node_rpc_states_info_t *)dap_global_db_get_sync(s_rpc_states_group, l_node_addr_str, &l_data_size, NULL, &l_timestamp);
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
    return dap_cluster_member_find_role(s_rpc_list_cluster->role_cluster, &g_node_addr) == DAP_GDB_MEMBER_ROLE_ROOT;
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
        : dap_global_db_set_sync( s_rpc_list_group,
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
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(s_rpc_list_group, &l_nodes_count);

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