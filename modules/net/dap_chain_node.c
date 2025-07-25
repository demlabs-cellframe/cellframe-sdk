/*
 * Authors:
 * Dmitriy A. Gerasimov <naeper@demlabs.net>
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
#include "dap_chain_node_client.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_balancer.h"

#define LOG_TAG "dap_chain_node"
#define DAP_CHAIN_NODE_NET_STATES_INFO_CURRENT_VERSION 2
typedef struct dap_chain_node_net_states_info_v1 {
    dap_chain_node_addr_t address;
    uint64_t events_count;
    uint64_t atoms_count;
    uint32_t uplinks_count;
    uint32_t downlinks_count;
    dap_chain_node_addr_t links_addrs[];
} DAP_ALIGN_PACKED dap_chain_node_net_states_info_v1_t;

typedef struct dap_chain_node_net_states_info {
    uint16_t version_info;
    char version_node[16];
    dap_chain_node_role_t role;
    dap_chain_node_net_states_info_v1_t info_v1;
} DAP_ALIGN_PACKED dap_chain_node_net_states_info_t;

#define node_info_v1_shift ( sizeof(uint16_t) + 16 + sizeof(dap_chain_node_role_t) )

static const uint64_t s_cmp_delta_timestamp = (uint64_t)1000 /*sec*/ * (uint64_t)1000000000;
static const uint64_t s_cmp_delta_event = 0;
static const uint64_t s_cmp_delta_atom = 10;
static const uint64_t s_timer_update_states_info = 10 /*sec*/ * 1000;
static const char s_states_group[] = ".nodes.states";

/**
 * @brief get states info about current
 * @param a_arg - pointer to callback arg
 */
static void s_update_node_states_info(UNUSED_ARG void *a_arg)
{
#ifndef DAP_VERSION
#pragma message "[!WRN!] DAP_VERSION IS NOT DEFINED. Manual override engaged."
#define DAP_VERSION "0.9-15"
#endif
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        if(dap_chain_net_get_state(l_net) != NET_STATE_OFFLINE) {
            size_t
                l_uplinks_count = 0,
                l_downlinks_count = 0,
                l_info_size = 0;
            dap_stream_node_addr_t *l_linked_node_addrs = dap_link_manager_get_net_links_addrs(l_net->pub.id.uint64, &l_uplinks_count, &l_downlinks_count, true);
            l_info_size = sizeof(dap_chain_node_net_states_info_t) + (l_uplinks_count + l_downlinks_count) * sizeof(dap_chain_node_addr_t);
            dap_chain_node_net_states_info_t *l_info = DAP_NEW_Z_SIZE_RET_IF_FAIL(dap_chain_node_net_states_info_t, l_info_size, l_linked_node_addrs);
            l_info->version_info = DAP_CHAIN_NODE_NET_STATES_INFO_CURRENT_VERSION;
            dap_strncpy(l_info->version_node, DAP_VERSION, sizeof(l_info->version_node) - 1);
            l_info->role = dap_chain_net_get_role(l_net);
            l_info->info_v1.address.uint64 = g_node_addr.uint64;
            l_info->info_v1.uplinks_count = l_uplinks_count;
            l_info->info_v1.downlinks_count = l_downlinks_count;

            dap_chain_t *l_chain = dap_chain_find_by_id(l_net->pub.id, (dap_chain_id_t){ .uint64 = 0 });  // zerochain
            l_info->info_v1.events_count = (l_chain && l_chain->callback_count_atom) ? l_chain->callback_count_atom(l_chain) : 0;
            l_chain = l_chain ? l_chain->next : NULL;  // mainchain
            l_info->info_v1.atoms_count = (l_chain && l_chain->callback_count_atom) ? l_chain->callback_count_atom(l_chain) : 0;
            
            memcpy( l_info->info_v1.links_addrs, l_linked_node_addrs,
                   (l_info->info_v1.uplinks_count + l_info->info_v1.downlinks_count) * sizeof(dap_chain_node_addr_t) );
            // DB write
            char *l_gdb_group = dap_strdup_printf("%s%s", l_net->pub.gdb_groups_prefix, s_states_group);
            const char *l_node_addr_str = dap_stream_node_addr_to_str_static(l_info->info_v1.address);
            dap_global_db_set_sync(l_gdb_group, l_node_addr_str, l_info, l_info_size, false);
            DAP_DEL_MULTY(l_linked_node_addrs, l_info, l_gdb_group);
        }
    }
}

static void s_states_info_to_str(dap_chain_net_t *a_net, const char *a_node_addr_str, dap_string_t *l_info_str)
{
// sanity check
    dap_return_if_pass(!a_net || !a_node_addr_str || !l_info_str);
// func work
    dap_nanotime_t l_timestamp = 0;
    size_t l_data_size = 0;
    char *l_gdb_group = dap_strdup_printf("%s%s", a_net->pub.gdb_groups_prefix, s_states_group);
    byte_t *l_node_info_data = dap_global_db_get_sync(l_gdb_group, a_node_addr_str, &l_data_size, NULL, &l_timestamp);
    DAP_DELETE(l_gdb_group);
    dap_chain_node_net_states_info_t *l_node_info = NULL;
    if (!l_node_info_data)
        return log_it(L_ERROR, "Can't find state of node %s in net %s", a_node_addr_str, a_net->pub.name);
    if ( (l_data_size - sizeof(dap_chain_node_net_states_info_t)) % sizeof(dap_chain_node_addr_t) ) {
        if ( (l_data_size - sizeof(dap_chain_node_net_states_info_v1_t)) % sizeof(dap_chain_node_addr_t) )
            return DAP_DELETE(l_node_info_data), log_it(L_ERROR, "Irrelevant size of node %s info", a_node_addr_str);
        dap_chain_node_net_states_info_v1_t *l_info_old = (dap_chain_node_net_states_info_v1_t*)l_node_info_data;
        l_node_info = DAP_NEW_Z_SIZE( dap_chain_node_net_states_info_t, sizeof(dap_chain_node_net_states_info_t) 
                                      + (l_info_old->uplinks_count + l_info_old->downlinks_count) * sizeof(dap_chain_node_addr_t) );
        l_node_info->version_info = 1;
        memcpy( (byte_t*)l_node_info + node_info_v1_shift, l_info_old, l_data_size );
        DAP_DELETE(l_node_info_data);
    } else
        l_node_info = (dap_chain_node_net_states_info_t*)l_node_info_data;
    char l_ts[80] = { '\0' };
    dap_nanotime_to_str_rfc822(l_ts, sizeof(l_ts), l_timestamp);
    dap_string_append_printf(l_info_str,
        "Record timestamp: %s\nRecord version: %u\nNode version: %s\nNode addr: %s\nNet: %s\nRole: %s\n"
        "Events count: %"DAP_UINT64_FORMAT_U"\nAtoms count: %"DAP_UINT64_FORMAT_U"\nUplinks count: %u\nDownlinks count: %u\n",
        l_ts, l_node_info->version_info, l_node_info->version_node, a_node_addr_str, a_net->pub.name, 
        dap_chain_node_role_to_str(l_node_info->role), l_node_info->info_v1.events_count, l_node_info->info_v1.atoms_count,
        l_node_info->info_v1.uplinks_count, l_node_info->info_v1.downlinks_count);
    size_t l_max_links = dap_max(l_node_info->info_v1.uplinks_count, l_node_info->info_v1.downlinks_count);
    if(l_max_links) {
        dap_string_append_printf(l_info_str,
        "-----------------------------------------------------------------\n"
        "|\tUplinks node addrs\t|\tDownlinks node addrs\t|\n"
        "-----------------------------------------------------------------\n");
    }
    for (size_t i = 0; i < l_max_links; ++i) {
        char *l_upnlink_str = i < l_node_info->info_v1.uplinks_count 
            ? dap_stream_node_addr_to_str(l_node_info->info_v1.links_addrs[i], false)
            : dap_strdup("\t\t");
        char *l_downlink_str = i < l_node_info->info_v1.downlinks_count 
            ? dap_stream_node_addr_to_str(l_node_info->info_v1.links_addrs[i + l_node_info->info_v1.uplinks_count], false)
            : dap_strdup("\t\t");
        dap_string_append_printf(l_info_str, "|\t%s\t|\t%s\t|\n", l_upnlink_str, l_downlink_str);
        DAP_DEL_MULTY(l_upnlink_str, l_downlink_str);
    }
    dap_string_append_printf(l_info_str, "-----------------------------------------------------------------\n");
    DAP_DELETE(l_node_info);
}

/**
 * @brief get states info about current
 * @param a_arg - pointer to callback arg
 */
dap_string_t *dap_chain_node_states_info_read(dap_chain_net_t *a_net, dap_stream_node_addr_t a_addr)
{
    dap_string_t *l_ret = dap_string_new("");
    const char *l_node_addr_str = dap_stream_node_addr_to_str_static(a_addr.uint64 ? a_addr : g_node_addr);
    if(!a_net) {
        for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
            s_states_info_to_str(l_net, l_node_addr_str, l_ret);
        }
    } else {
        s_states_info_to_str(a_net, l_node_addr_str, l_ret);
    }
    if (!l_ret->len) {
        const char *l_prefix = !a_addr.uint64 ? "my" : a_addr.uint64 == g_node_addr.uint64 ? "my" : "";
        if (a_net){
            dap_string_append_printf(l_ret, "Can't find state of %s node %s in net %s", l_prefix, l_node_addr_str, a_net->pub.name);
        } else {
            dap_string_append_printf(l_ret, "Can't find state of %s node %s in nets ", l_prefix, l_node_addr_str);
            dap_chain_net_t *l_current_net = NULL, *l_next_net = dap_chain_net_iter_start();
            while(l_next_net) {
                l_current_net = l_next_net;
                l_next_net = dap_chain_net_iter_next(l_next_net);
                dap_string_append_printf(l_ret, l_next_net ? "%s, " : "%s", l_current_net->pub.name);
            }
        }
    }
    return l_ret;
}

void dap_chain_node_list_cluster_del_callback(dap_store_obj_t *a_obj, void *a_arg) {
    const char *l_net_name = (const char*)a_arg;
    if (dap_store_obj_get_type(a_obj) == DAP_GLOBAL_DB_OPTYPE_DEL) {
        log_it(L_DEBUG, "Delete node list hole %s key %s", a_obj->group, a_obj->key);
        dap_global_db_driver_delete(a_obj, 1);
        return;
    }
    log_it(L_DEBUG, "Start check node list %s group %s key", a_obj->group, a_obj->key);

    if (!a_obj->value) {
        log_it(L_DEBUG, "Can't find value in %s group %s key delete from node list", a_obj->group, a_obj->key);
        dap_global_db_driver_delete(a_obj, 1);
        return;
    }
    
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    dap_return_if_fail(l_net);
    
    dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t*)a_obj->value;
    if (!l_node_info || a_obj->value_len < sizeof(dap_chain_node_info_t)) {
        log_it(L_ERROR, "Invalid node info for key %s", a_obj->key);
        return;
    }
    
    // check node in nodes.states
    bool l_state_active = false;
    dap_nanotime_t l_info_state_timestamp = 0;
    size_t l_data_size = 0;
    char *l_gdb_group = dap_strdup_printf("%s%s", l_net->pub.gdb_groups_prefix, s_states_group);
    byte_t *l_node_info_states_data = dap_global_db_get_sync(l_gdb_group, a_obj->key, &l_data_size, NULL, &l_info_state_timestamp);
    DAP_DELETE(l_gdb_group);
    dap_chain_node_net_states_info_t *l_node_info_states = NULL;
    if (l_node_info_states_data) {
        if ( (l_data_size - sizeof(dap_chain_node_net_states_info_t)) % sizeof(dap_chain_node_addr_t) ) {
            if ( (l_data_size - sizeof(dap_chain_node_net_states_info_v1_t)) % sizeof(dap_chain_node_addr_t) ) {
                DAP_DELETE(l_node_info_states_data);
                log_it(L_ERROR, "Irrelevant size of node %s info", a_obj->key);
                return;
            }
            dap_chain_node_net_states_info_v1_t *l_info_old = (dap_chain_node_net_states_info_v1_t*)l_node_info_states_data;
            l_node_info_states = DAP_NEW_Z_SIZE( dap_chain_node_net_states_info_t, sizeof(dap_chain_node_net_states_info_t) 
                                        + (l_info_old->uplinks_count + l_info_old->downlinks_count) * sizeof(dap_chain_node_addr_t) );
            if (!l_node_info_states) {
                DAP_DELETE(l_node_info_states_data);
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return;
            }
            l_node_info_states->version_info = 1;
            memcpy( (byte_t*)l_node_info_states + node_info_v1_shift, l_info_old, l_data_size );
            DAP_DELETE(l_node_info_states_data);
        } else
            l_node_info_states = (dap_chain_node_net_states_info_t*)l_node_info_states_data;
    }

    // check is node active for last two hours
    if (l_info_state_timestamp > (dap_nanotime_now() - dap_nanotime_from_sec(7200)) 
        && l_node_info_states && l_node_info_states->info_v1.downlinks_count > 0) {
            l_state_active = true;
            log_it(L_DEBUG, "Node %s [ %s : %u ] is active in nodes.states, rewrite to node list", a_obj->key, l_node_info->ext_host, l_node_info->ext_port);
    }

    // if no data in nodes.state do handshake
    if (!l_state_active) {
        int l_ret = -1;
        for (size_t i = 0; i < 3 && l_ret != 0; i++) {
            dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(l_net, l_node_info);
            if (l_client) {
                l_ret = dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, 30000);
                dap_chain_node_client_close_mt(l_client);
            }
        }
        if (l_ret == 0) {
            l_state_active = true;
            log_it(L_DEBUG, "Node %s [ %s : %u ] is answered for handshake, rewrite to node list", a_obj->key, l_node_info->ext_host, l_node_info->ext_port);
        }
    }

    if (l_state_active) {
        dap_global_db_set_sync(a_obj->group, a_obj->key, a_obj->value, a_obj->value_len, a_obj->flags & DAP_GLOBAL_DB_RECORD_PINNED);
    } else {
        log_it(L_DEBUG, "Node %s [ %s : %u ] is not active, delete them from node list", a_obj->key, l_node_info->ext_host, l_node_info->ext_port);
        dap_global_db_driver_delete(a_obj, 1);
    }
    
    DAP_DELETE(l_node_info_states);
}

int dap_chain_node_list_clean_init() {
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net);
        if (l_role.enums == NODE_ROLE_ROOT) {
            dap_global_db_cluster_t *l_cluster = dap_global_db_cluster_by_group(dap_global_db_instance_get_default(), l_net->pub.gdb_nodes);
            if ( !l_cluster ) {
                log_it(L_ERROR, "Cluster for nodelist group \"%s\" not found", l_net->pub.gdb_nodes);
                return -1;
            }
            l_cluster->del_callback = dap_chain_node_list_cluster_del_callback;
            l_cluster->del_arg = l_net->pub.name;
            log_it(L_DEBUG, "Node list clean inited for net %s", l_net->pub.name);
        }
    }
    dap_proc_thread_timer_add_pri(NULL, (dap_thread_timer_callback_t)dap_chain_net_announce_addr_all, NULL, 300000, true, DAP_QUEUE_MSG_PRIORITY_NORMAL);
    return 0;
}

int dap_chain_node_init()
{
    if (dap_proc_thread_timer_add(NULL, s_update_node_states_info, NULL, s_timer_update_states_info)) {
        // log_it(L_ERROR, "Can't activate timer on node states update");
        return -1;
    }
    return 0;
}

/**
 * Register alias in base
 */
bool dap_chain_node_alias_register(dap_chain_net_t *a_net, const char *a_alias, dap_chain_node_addr_t *a_addr)
{
    // TODO
    return false;
}

/**
 * @brief dap_chain_node_alias_find
 * @param alias
 * @return
 */
dap_chain_node_addr_t *dap_chain_node_alias_find(dap_chain_net_t *a_net, const char *a_alias)
{
    dap_return_val_if_fail(a_alias && a_net, NULL);
    // TODO
    return NULL;
}

/**
 * Delete alias from base
 */
bool dap_chain_node_alias_delete(dap_chain_net_t *a_net, const char *a_alias)
{
    // TODO
    return false;
}

/**
 * Compare addresses of two dap_chain_node_info_t structures
 *
 * @return True if addresses are equal, otherwise false
 */
bool dap_chain_node_info_addr_match(dap_chain_node_info_t *node_info1, dap_chain_node_info_t *node_info2)
{
    return node_info1 && node_info2
        && !dap_strcmp(node_info1->ext_host, node_info2->ext_host)
        && node_info1->ext_port == node_info2->ext_port;
}


/**
 * @brief dap_chain_node_info_save
 * @param node_info
 * @return
 */
int dap_chain_node_info_save(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info)
{
    return !a_node_info || !a_node_info->address.uint64
        ? log_it(L_ERROR,"Can't save node info, %s", a_node_info ? "null arg" : "zero address"), -1
        : dap_global_db_set_sync( a_net->pub.gdb_nodes,
                                 dap_stream_node_addr_to_str_static(a_node_info->address),
                                 a_node_info,
                                 dap_chain_node_info_get_size(a_node_info), false );
}

int dap_chain_node_info_del(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info) {
    return !a_node_info || !a_node_info->address.uint64
        ? log_it(L_ERROR,"Can't delete node info, %s", a_node_info ? "null arg" : "zero address"), -1
        : dap_global_db_del_sync( a_net->pub.gdb_nodes,
                                 dap_stream_node_addr_to_str_static(a_node_info->address) );
}

/**
 * Read node from base
 */
dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_net_t *a_net, dap_chain_node_addr_t *a_address)
{
    const char *l_key = dap_stream_node_addr_to_str_static(*a_address);
    size_t l_node_info_size = 0;
    dap_chain_node_info_t *l_node_info
        = (dap_chain_node_info_t*)dap_global_db_get_sync(a_net->pub.gdb_nodes, l_key, &l_node_info_size, NULL, NULL);

    if (!l_node_info) {
        log_it(L_NOTICE, "Node with address %s not found in base of %s network", l_key, a_net->pub.name);
        return NULL;
    }
    size_t l_node_info_size_calced = dap_chain_node_info_get_size(l_node_info);
    if (l_node_info_size_calced != l_node_info_size) {
        log_it(L_ERROR, "Bad node \"%s\" record size, %zu != %zu", l_key, l_node_info_size_calced, l_node_info_size);
        DAP_DELETE(l_node_info);
        return NULL;
    }
    return l_node_info;
}

bool dap_chain_node_mempool_need_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum) {
    for (uint16_t j = 0; j < a_chain->autoproc_datum_types_count; j++)
        if (a_datum->header.type_id == a_chain->autoproc_datum_types[j])
            return true;
    return false;
}

/* Return true if processed datum should be deleted from mempool */
bool dap_chain_node_mempool_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_datum_hash_str, int * a_ret)
{
    if (!a_chain->callback_add_datums) {
        log_it(L_ERROR, "Not found chain callback for datums processing");
        return false;
    }
    dap_hash_fast_t l_datum_hash, l_real_hash;
    if (dap_chain_hash_fast_from_hex_str(a_datum_hash_str, &l_datum_hash)) {
        log_it(L_WARNING, "Can't get datum hash from hash string");
        return false;
    }
    dap_chain_datum_calc_hash(a_datum, &l_real_hash);
    if (!dap_hash_fast_compare(&l_datum_hash, &l_real_hash)) {
        log_it(L_WARNING, "Datum hash from mempool key and real datum hash are different");
        return false;
    }
    int l_verify_datum = dap_chain_net_verify_datum_for_add(a_chain, a_datum, &l_datum_hash);
    if (!l_verify_datum
#ifdef DAP_TPS_TEST
            || l_verify_datum == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS
#endif
            )
    {
        a_chain->callback_add_datums(a_chain, &a_datum, 1);
    }
    if (l_verify_datum != 0 &&
            l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS &&
            l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION &&
            l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS &&
            l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE) {
                if (a_ret)
                    *a_ret = l_verify_datum;
                return true;
        }
    return false;
}

void dap_chain_node_mempool_process_all(dap_chain_t *a_chain, bool a_force)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!a_force && !l_net->pub.mempool_autoproc)
        return;
#ifdef DAP_TPS_TEST
    FILE *l_file = fopen("/opt/cellframe-node/share/ca/mempool_start.txt", "r");
    if (l_file) {
        fclose(l_file);
        l_file = fopen("/opt/cellframe-node/share/ca/mempool_finish.txt", "r");
        if(!l_file) {
            log_it(L_TPS, "Wait mempool");
            return;
        }
        log_it(L_TPS, "Mempool ready");
        fclose(l_file);
        l_file = fopen("/opt/cellframe-node/share/ca/tps_start.txt", "r");
        if (!l_file) {
            l_file = fopen("/opt/cellframe-node/share/ca/tps_start.txt", "w");
            char l_from_str[50];
            const char c_time_fmt[]="%Y-%m-%d_%H:%M:%S";
            struct tm l_from_tm = {};
            time_t l_ts_now = time(NULL);
            localtime_r(&l_ts_now, &l_from_tm);
            strftime(l_from_str, sizeof(l_from_str), c_time_fmt, &l_from_tm);
            fputs(l_from_str, l_file);
        }
        fclose(l_file);
    }
#endif
    char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    size_t l_objs_size = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_size);
    if (l_objs_size) {
#ifdef DAP_TPS_TEST
        log_it(L_TPS, "Get %zu datums from mempool", l_objs_size);
#endif
        for (size_t i = 0; i < l_objs_size; i++) {           
            if (l_objs[i].value_len < sizeof(dap_chain_datum_t))
                continue;
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
            if (dap_chain_datum_size(l_datum) != l_objs[i].value_len)
                continue;
            if (dap_chain_node_mempool_need_process(a_chain, l_datum)) {

                if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX &&
                        !dap_strcmp(dap_chain_get_cs_type(a_chain), "esbocs")) {
                    uint256_t l_tx_fee = {};
                    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
                    if (dap_chain_datum_tx_get_fee_value (l_tx, &l_tx_fee) ||
                            IS_ZERO_256(l_tx_fee)) {
                        if (!dap_ledger_tx_poa_signed(l_net->pub.ledger, l_tx)) {
                            log_it(L_WARNING, "Can't get fee value from tx %s", l_objs[i].key);
                            continue;
                        } else
                            log_it(L_DEBUG, "Process service tx without fee");
                    } else {
                        uint256_t l_min_fee = dap_chain_esbocs_get_fee(a_chain->net_id);
                        if (compare256(l_tx_fee, l_min_fee) < 0) {
                            char *l_tx_fee_str = dap_chain_balance_to_coins(l_tx_fee);
                            char *l_min_fee_str = dap_chain_balance_to_coins(l_min_fee);
                            log_it(L_WARNING, "Fee %s is lower than minimum fee %s for tx %s",
                                   l_tx_fee_str, l_min_fee_str, l_objs[i].key);
                            DAP_DELETE(l_tx_fee_str);
                            DAP_DELETE(l_min_fee_str);
                            continue;
                        }
                    }
                }
                int l_ret = 0;
                if (dap_chain_node_mempool_process(a_chain, l_datum, l_objs[i].key, &l_ret)) {
                    // Delete processed objects
                    log_it(L_INFO, " ! Delete datum %s from mempool", l_objs[i].key);
                    char* l_ret_str = dap_strdup_printf("%d", l_ret);
                    dap_global_db_del_ex(l_gdb_group_mempool, l_objs[i].key, l_ret_str, strlen(l_ret_str)+1 , NULL, NULL);
                    DAP_DELETE(l_ret_str);
                } else {
                    log_it(L_INFO, " ! Datum %s remains in mempool", l_objs[i].key);
                }
            }
        }
        dap_global_db_objs_delete(l_objs, l_objs_size);
    }
    DAP_DELETE(l_gdb_group_mempool);
}

/**
 * @brief
 * get automatic mempool processing, when network config contains mempool_auto_types for specific datums
 * @return true
 * @return false
 */
bool dap_chain_node_mempool_autoproc_init()
{
    if (!dap_config_get_item_bool_default(g_config, "mempool", "auto_proc", false))
        return false;
    
    for (dap_chain_net_t *it = dap_chain_net_iter_start(); it; it = dap_chain_net_iter_next(it)) {
        switch (dap_chain_net_get_role(it).enums) {
            case NODE_ROLE_ROOT:
            case NODE_ROLE_MASTER:
            case NODE_ROLE_ROOT_MASTER:
            case NODE_ROLE_CELL_MASTER:
                it->pub.mempool_autoproc = true;
                break;
            default:
                it->pub.mempool_autoproc = false;
                continue;
        }
    }

    return true;
}

/**
 * @brief comparing dap_chain_node_states_info_t
 * @param a_first - pointer to first item
 * @param a_second - pointer to second 
 * @return a_first < a_second -1, a_first > a_second 1, a_first = a_second 0
 */
static int s_node_states_info_cmp(dap_list_t *a_first, dap_list_t *a_second)
{
  dap_chain_node_states_info_t *a = (dap_chain_node_states_info_t *)a_first->data;
  dap_chain_node_states_info_t *b = (dap_chain_node_states_info_t *)a_second->data;

  if(a->timestamp > b->timestamp && a->timestamp - b->timestamp > s_cmp_delta_timestamp) return -1;
  if(b->timestamp > a->timestamp && b->timestamp - a->timestamp > s_cmp_delta_timestamp) return 1;
  if(a->events_count > b->events_count && a->events_count - b->events_count > s_cmp_delta_event) return -1;
  if(b->events_count > a->events_count && b->events_count - a->events_count > s_cmp_delta_event) return 1;
  if(a->atoms_count > b->atoms_count && a->atoms_count - b->atoms_count > s_cmp_delta_atom) return -1;
  if(b->atoms_count > a->atoms_count && b->atoms_count - a->atoms_count > s_cmp_delta_atom) return 1;
  if(a->role.enums == NODE_ROLE_ROOT) return 1;
  if(b->role.enums == NODE_ROLE_ROOT) return -1;
  if(a->downlinks_count < b->downlinks_count) return -1;
  if(b->downlinks_count < a->downlinks_count) return 1;
  return 0;
}

/**
 * @brief geting sorted list with nodes states
 * @param a_net - pointer to net
 * @return pointer to sorted list or NULL if error
 */
dap_list_t *dap_chain_node_get_states_list_sort(dap_chain_net_t *a_net, dap_chain_node_addr_t *a_ignored, size_t a_ignored_count)
{
// sanity check
    dap_return_val_if_pass(!a_net || (a_ignored_count && !a_ignored), NULL);
// func work
    size_t l_node_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_net->pub.gdb_nodes, &l_node_count);
    if (!l_node_count || !l_objs) {        
        log_it(L_ERROR, "Node list in net %s is empty", a_net->pub.name);
        return NULL;
    }
    char *l_gdb_group = dap_strdup_printf("%s%s", a_net->pub.gdb_groups_prefix, s_states_group);
    dap_list_t *l_ret = NULL;
    for (size_t i = 0; i < l_node_count; ++i) {
        if (!l_objs[i].value) {
            log_it(L_ERROR, "Invalid record, key %s", l_objs[i].key);
            continue;
        }
        bool l_ignored = false;
        for(size_t j = 0; !l_ignored && j < a_ignored_count; ++j) {
            l_ignored = a_ignored[j].uint64 == ((dap_chain_node_info_t*)(l_objs + i)->value)->address.uint64;
        }
        if (l_ignored) {
            log_it(L_DEBUG, "Link to "NODE_ADDR_FP_STR" ignored", NODE_ADDR_FP_ARGS_S(((dap_chain_node_info_t*)(l_objs + i)->value)->address));
            continue;
        }
        dap_chain_node_states_info_t *l_item = DAP_NEW_Z(dap_chain_node_states_info_t);
        if(!l_item) {
            log_it(L_ERROR, "%s", c_error_memory_alloc);
            break;
        }
        l_item->link_info.node_addr.uint64 = ((dap_chain_node_info_t*)(l_objs + i)->value)->address.uint64;
        l_item->link_info.uplink_port = ((dap_chain_node_info_t*)(l_objs + i)->value)->ext_port;
        dap_strncpy(l_item->link_info.uplink_addr, ((dap_chain_node_info_t*)(l_objs + i)->value)->ext_host, sizeof(l_item->link_info.uplink_addr) - 1);

        dap_nanotime_t l_state_timestamp = 0;
        size_t l_data_size = 0;
        dap_chain_node_net_states_info_t *l_node_info = NULL;
        byte_t *l_node_info_data = dap_global_db_get_sync(l_gdb_group, l_objs[i].key, &l_data_size, NULL, &l_state_timestamp);
        if (!l_node_info_data) {
            log_it(L_DEBUG, "Can't find state about %s node, apply low priority", l_objs[i].key);
            l_item->downlinks_count = (uint32_t)(-1);
        } else {
            if ( (l_data_size - sizeof(dap_chain_node_net_states_info_t)) % sizeof(dap_chain_node_addr_t) ) {
                if ( (l_data_size - sizeof(dap_chain_node_net_states_info_v1_t)) % sizeof(dap_chain_node_addr_t) ) {
                    log_it(L_ERROR, "Irrelevant size of node %s info, ignore it", l_objs[i].key);
                    DAP_DEL_MULTY(l_node_info_data, l_item);
                    continue;
                }
                dap_chain_node_net_states_info_v1_t *l_info_old = (dap_chain_node_net_states_info_v1_t*)l_node_info_data;
                l_node_info = DAP_NEW_Z_SIZE( dap_chain_node_net_states_info_t, sizeof(dap_chain_node_net_states_info_t) 
                                            + (l_info_old->uplinks_count + l_info_old->downlinks_count) * sizeof(dap_chain_node_addr_t) );
                l_node_info->version_info = 1;
                memcpy( (byte_t*)l_node_info + node_info_v1_shift, l_info_old, l_data_size );
                DAP_DELETE(l_node_info_data);
            } else
                l_node_info = (dap_chain_node_net_states_info_t*)l_node_info_data;
            l_item->role.enums = l_node_info->role.enums;
            l_item->atoms_count = l_node_info->info_v1.atoms_count;
            l_item->events_count = l_node_info->info_v1.events_count;
            l_item->downlinks_count = l_node_info->info_v1.downlinks_count;
        }
        l_item->timestamp = l_state_timestamp;
        l_ret = dap_list_insert_sorted(l_ret, (void *)l_item, s_node_states_info_cmp);
        DAP_DELETE(l_node_info);
    }
    DAP_DELETE(l_gdb_group);
    dap_global_db_objs_delete(l_objs, l_node_count);
    return l_ret;
}
