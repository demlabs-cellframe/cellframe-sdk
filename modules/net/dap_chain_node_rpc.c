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

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <pthread.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "dap_hash.h"
#include "dap_chain_net.h"
#include "dap_global_db.h"
#include "dap_chain_node.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_node_rpc"
#define DAP_RPC_CLUSTER_GLOBAL           ".rpc"
#define DAP_RPC_DB_CLUSTER_GLOBAL       DAP_RPC_CLUSTER_GLOBAL ".*"
#define DAP_CHAIN_NODE_RPC_STATES_INFO_CURRENT_VERSION 1
typedef struct dap_chain_node_rpc_states_info {
    uint32_t version;
    dap_chain_node_addr_t address;
    uint32_t cli_thread_count;
    uint32_t cpu;
    uint64_t mem;
} DAP_ALIGN_PACKED dap_chain_node_rpc_states_info_t;


static const uint64_t s_timer_update_states_info = 10 /*sec*/ * 1000;
static const char s_states_group[] = ".rpc.states";
static dap_global_db_cluster_t *s_global_cluster = NULL;

/**
 * @brief get states info about current
 * @param a_arg - pointer to callback arg
 */
static void s_update_node_rpc_states_info(UNUSED_ARG void *a_arg)
{
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        if(dap_chain_net_get_state(l_net) == NET_STATE_ONLINE) {
            size_t
                l_uplinks_count = 0,
                l_downlinks_count = 0,
                l_info_size = 0;
            dap_chain_node_rpc_states_info_t *l_info = DAP_NEW_Z_RET_IF_FAIL(dap_chain_node_rpc_states_info_t);
            l_info->version = DAP_CHAIN_NODE_RPC_STATES_INFO_CURRENT_VERSION;
            l_info->address.uint64 = g_node_addr.uint64;

            char *l_gdb_group = dap_strdup_printf("%s%s", l_net->pub.gdb_groups_prefix, s_states_group);
            const char *l_node_addr_str = dap_stream_node_addr_to_str_static(l_info->address);
            dap_global_db_set_sync(l_gdb_group, l_node_addr_str, l_info, l_info_size, false);
            DAP_DEL_MULTY(l_info, l_gdb_group);
        }
    }
}

static void s_states_info_to_str(dap_chain_net_t *a_net, const char *a_node_addr_str, dap_string_t *l_info_str)
{
// sanity check
    dap_return_if_pass(!a_net || !a_node_addr_str || !l_info_str);
// func work
    // dap_nanotime_t l_timestamp = 0;
    // size_t l_data_size = 0;
    // char *l_gdb_group = dap_strdup_printf("%s%s", a_net->pub.gdb_groups_prefix, s_states_group);
    // byte_t *l_node_info_data = dap_global_db_get_sync(l_gdb_group, a_node_addr_str, &l_data_size, NULL, &l_timestamp);
    // DAP_DELETE(l_gdb_group);
    // dap_chain_node_rpc_states_info_t *l_node_info = NULL;
    // if (!l_node_info_data)
    //     return log_it(L_ERROR, "Can't find state of node %s in net %s", a_node_addr_str, a_net->pub.name);
    // if ( (l_data_size - sizeof(dap_chain_node_rpc_states_info_t)) % sizeof(dap_chain_node_addr_t) ) {
    //     if ( (l_data_size - sizeof(dap_chain_node_net_states_info_v1_t)) % sizeof(dap_chain_node_addr_t) )
    //         return DAP_DELETE(l_node_info_data), log_it(L_ERROR, "Irrelevant size of node %s info", a_node_addr_str);
    //     dap_chain_node_net_states_info_v1_t *l_info_old = (dap_chain_node_net_states_info_v1_t*)l_node_info_data;
    //     l_node_info = DAP_NEW_Z_SIZE( dap_chain_node_rpc_states_info_t, sizeof(dap_chain_node_rpc_states_info_t) 
    //                                   + (l_info_old->uplinks_count + l_info_old->downlinks_count) * sizeof(dap_chain_node_addr_t) );
    //     l_node_info->version_info = 1;
    //     memcpy( (byte_t*)l_node_info + node_info_v1_shift, l_info_old, l_data_size );
    //     DAP_DELETE(l_node_info_data);
    // } else
    //     l_node_info = (dap_chain_node_rpc_states_info_t*)l_node_info_data;
    // char l_ts[80] = { '\0' };
    // dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), l_timestamp);
    // dap_string_append_printf(l_info_str,
    //     "Record timestamp: %s\nRecord version: %u\nNode version: %s\nNode addr: %s\nNet: %s\nRole: %s\n"
    //     "Events count: %"DAP_UINT64_FORMAT_U"\nAtoms count: %"DAP_UINT64_FORMAT_U"\nUplinks count: %u\nDownlinks count: %u\n",
    //     l_ts, l_node_info->version_info, l_node_info->version_node, a_node_addr_str, a_net->pub.name, 
    //     dap_chain_node_role_to_str(l_node_info->role), l_node_info->info_v1.events_count, l_node_info->info_v1.atoms_count,
    //     l_node_info->info_v1.uplinks_count, l_node_info->info_v1.downlinks_count);
    // size_t l_max_links = dap_max(l_node_info->info_v1.uplinks_count, l_node_info->info_v1.downlinks_count);
    // if(l_max_links) {
    //     dap_string_append_printf(l_info_str,
    //     "-----------------------------------------------------------------\n"
    //     "|\tUplinks node addrs\t|\tDownlinks node addrs\t|\n"
    //     "-----------------------------------------------------------------\n");
    // }
    // for (size_t i = 0; i < l_max_links; ++i) {
    //     char *l_upnlink_str = i < l_node_info->info_v1.uplinks_count 
    //         ? dap_stream_node_addr_to_str(l_node_info->info_v1.links_addrs[i], false)
    //         : dap_strdup("\t\t");
    //     char *l_downlink_str = i < l_node_info->info_v1.downlinks_count 
    //         ? dap_stream_node_addr_to_str(l_node_info->info_v1.links_addrs[i + l_node_info->info_v1.uplinks_count], false)
    //         : dap_strdup("\t\t");
    //     dap_string_append_printf(l_info_str, "|\t%s\t|\t%s\t|\n", l_upnlink_str, l_downlink_str);
    //     DAP_DEL_MULTY(l_upnlink_str, l_downlink_str);
    // }
    // dap_string_append_printf(l_info_str, "-----------------------------------------------------------------\n");
    // DAP_DELETE(l_node_info);
}


void dap_chain_node_rpc_init()
{
    if ( !(s_global_cluster = dap_global_db_cluster_add(
        dap_global_db_instance_get_default(), DAP_RPC_CLUSTER_GLOBAL,
        *(dap_guuid_t*)&uint128_0, DAP_RPC_DB_CLUSTER_GLOBAL,
        0,
        true, DAP_GDB_MEMBER_ROLE_GUEST, DAP_CLUSTER_TYPE_VIRTUAL)))
        return;
    if (dap_proc_thread_timer_add(NULL, s_update_node_rpc_states_info, NULL, s_timer_update_states_info))
        log_it(L_ERROR, "Can't activate timer on node states update");
}

// /**
//  * @brief get states info about current
//  * @param a_arg - pointer to callback arg
//  */
// dap_string_t *dap_chain_node_states_info_read(dap_chain_net_t *a_net, dap_stream_node_addr_t a_addr)
// {
//     dap_string_t *l_ret = dap_string_new("");
//     const char *l_node_addr_str = dap_stream_node_addr_to_str_static(a_addr.uint64 ? a_addr : g_node_addr);
//     if(!a_net) {
//         for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
//             s_states_info_to_str(l_net, l_node_addr_str, l_ret);
//         }
//     } else {
//         s_states_info_to_str(a_net, l_node_addr_str, l_ret);
//     }
//     if (!l_ret->len) {
//         const char *l_prefix = !a_addr.uint64 ? "my" : a_addr.uint64 == g_node_addr.uint64 ? "my" : "";
//         if (a_net) {
//             dap_string_append_printf(l_ret, "Can't find rpc state of %s node %s in net %s", l_prefix, l_node_addr_str, a_net->pub.name);
//         } else {
//             dap_string_append_printf(l_ret, "Can't find rpc state of %s node %s in nets ", l_prefix, l_node_addr_str);
//             dap_chain_net_t *l_current_net = NULL, *l_next_net = dap_chain_net_iter_start();
//             while(l_next_net) {
//                 l_current_net = l_next_net;
//                 l_next_net = dap_chain_net_iter_next(l_next_net);
//                 dap_string_append_printf(l_ret, l_next_net ? "%s, " : "%s", l_current_net->pub.name);
//             }
//         }
//     }
//     return l_ret;
// }

