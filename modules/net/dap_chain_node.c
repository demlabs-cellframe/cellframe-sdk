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

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_cell.h"
#include "dap_chain_net.h"
#include "dap_global_db.h"
#include "dap_chain_node.h"
#include "dap_chain_node_client.h"
#include "dap_chain_cs_esbocs.h" // TODO set RPC callbacks for exclude consensus specific dependency
#include "dap_chain_cs_blocks.h" // TODO set RPC callbacks for exclude storage type specific dependency
#include "dap_chain_net_srv_stake_pos_delegate.h" // TODO set RPC callbacks for exclude service specific dependency
#include "dap_chain_ledger.h"
#include "dap_chain_net_balancer.h"
#include "dap_cli_server.h"
#include "dap_chain_srv.h"
#include "dap_chain_mempool.h"
#include "dap_chain_datum_service_state.h"
#include "dap_chain_node_client.h"

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

enum hardfork_state {
    STATE_ANCHORS = 0,
    STATE_BALANCES,
    STATE_CONDOUTS,
    STATE_FEES,
    STATE_SERVICES,
    STATE_MEMPOOL
};

struct hardfork_states {
    enum hardfork_state state_current;
    size_t iterator;
    dap_ledger_hardfork_anchors_t  *anchors;
    dap_ledger_hardfork_balances_t *balances;
    dap_ledger_hardfork_condouts_t *condouts;
    dap_chain_cs_blocks_hardfork_fees_t *fees;
    dap_chain_srv_hardfork_state_t *service_states;
    dap_list_t *trusted_addrs;
};

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
            dap_strncpy(l_info->version_node, DAP_VERSION, sizeof(l_info->version_node));
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
    UNUSED(a_arg);
    dap_return_if_fail(a_obj);
    log_it(L_DEBUG, "Start check node list %s group %s key", a_obj->group, a_obj->key);

    if (a_obj->value_len == 0) {
        dap_global_db_del_sync(a_obj->group, a_obj->key);
        log_it(L_DEBUG, "Can't find value in %s group %s key delete from node list", a_obj->group, a_obj->key);
        return;
    }
    dap_chain_node_info_t *l_node_info = (dap_chain_node_info_t*)a_obj->value;
    dap_return_if_fail(l_node_info);
    char ** l_group_strings = dap_strsplit(a_obj->group, ".", 3);
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_group_strings[0]);
    if (dap_strcmp("nodes", l_group_strings[1]) || dap_strcmp("list", l_group_strings[2])) {
        log_it(L_ERROR, "Try to delete from nodelist by the %s group %s key", a_obj->group, a_obj->key);
        dap_strfreev(l_group_strings);
        return;
    }
    int l_ret = -1;
    for (size_t i = 0; i < 3 && l_ret != 0; i++) {
        dap_chain_node_client_t *l_client = dap_chain_node_client_connect_default_channels(l_net, l_node_info);
        if (l_client)
            l_ret = dap_chain_node_client_wait(l_client, NODE_CLIENT_STATE_ESTABLISHED, 30000);
        // dap_chain_node_client_close_unsafe(l_client); TODO unexpected del in s_go_stage_on_client_worker_unsafe
    }
    if (l_ret == 0) {
        dap_global_db_set_sync(a_obj->group, a_obj->key, a_obj->value, a_obj->value_len, a_obj->flags & DAP_GLOBAL_DB_RECORD_PINNED);
    } else {
        log_it(L_DEBUG, "Can't do handshake with %s [ %s : %u ] delete from node list", a_obj->key, l_node_info->ext_host, l_node_info->ext_port);
        dap_del_global_db_obj_by_ttl(a_obj);
    }
    dap_strfreev(l_group_strings);
}

int dap_chain_node_list_clean_init() {
    for (dap_chain_net_t *l_net = dap_chain_net_iter_start(); l_net; l_net = dap_chain_net_iter_next(l_net)) {
        dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net);
        if (l_role.enums == NODE_ROLE_ROOT) {
            char * l_group_name = dap_strdup_printf("%s.nodes.list", l_net->pub.name);
            dap_global_db_cluster_t *l_cluster = dap_global_db_cluster_by_group(dap_global_db_instance_get_default(), l_group_name);
            l_cluster->del_callback = dap_chain_node_list_cluster_del_callback;
            log_it(L_DEBUG, "Node list clean inited for net %s", l_net->pub.name);
        }
    }
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
    char *l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_count);
    if (l_objs_count) {
#ifdef DAP_TPS_TEST
        log_it(L_TPS, "Get %zu datums from mempool", l_objs_count);
#endif
        for (size_t i = 0; i < l_objs_count; i++) {
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
                            char *l_tx_fee_str = dap_chain_balance_coins_print(l_tx_fee);
                            char *l_min_fee_str = dap_chain_balance_coins_print(l_min_fee);
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
        dap_global_db_objs_delete(l_objs, l_objs_count);
    }
    DAP_DELETE(l_gdb_group_mempool);
}

dap_chain_datum_t **s_service_state_datums_create(dap_chain_srv_hardfork_state_t *a_state, size_t *a_datums_count)
{
    dap_chain_datum_t **ret = NULL;
    size_t l_datums_count = 0;
    const uint64_t l_max_step_size = DAP_CHAIN_ATOM_MAX_SIZE - sizeof(dap_chain_datum_service_state_t);
    uint64_t l_step_size = dap_min(l_max_step_size, a_state->size);
    byte_t *l_offset = a_state->data, *l_ptr = l_offset, *l_end = a_state->data + a_state->size * a_state->count;
    while (l_offset < l_end) {
        size_t l_cur_step_size = 0, i = 0;
        while (l_cur_step_size < l_max_step_size && l_offset < l_end) {
            size_t l_addition = dap_min((uint64_t)(l_end - l_offset), l_step_size);
            l_cur_step_size += l_addition;
            l_offset += l_addition;
            i++;
        }
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_SERVICE_STATE, l_ptr, sizeof(dap_chain_datum_service_state_t) + l_cur_step_size);
        ((dap_chain_datum_service_state_t *)l_datum->data)->srv_uid = a_state->uid;
        ((dap_chain_datum_service_state_t *)l_datum->data)->state_size = a_state->size;
        ((dap_chain_datum_service_state_t *)l_datum->data)->states_count = i;
        ret = DAP_REALLOC_RET_VAL_IF_FAIL(ret, sizeof(dap_chain_datum_t *) * (++l_datums_count), NULL, NULL);
        ret[l_datums_count - 1] = l_datum;
        l_ptr = l_offset;
    }
    assert(l_offset == l_end);
    if (a_datums_count)
        *a_datums_count = l_datums_count;
    return ret;
}

int dap_chain_node_hardfork_prepare(dap_chain_t *a_chain, dap_time_t a_last_block_timestamp, dap_list_t *a_trusted_addrs, json_object * a_changed_addrs)
{
    if (dap_strcmp(dap_chain_get_cs_type(a_chain), DAP_CHAIN_ESBOCS_CS_TYPE_STR))
        return log_it(L_ERROR, "Can't prepare harfork for chain type %s is not supported", dap_chain_get_cs_type(a_chain)), -2;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    assert(l_net);
    if (dap_chain_net_srv_stake_hardfork_data_verify(l_net, &a_chain->hardfork_decree_hash)) {
        log_it(L_ERROR, "Stake delegate data verifying with hardfork decree failed");
        return -3;
    }
    log_it(L_ATT, "Starting data prepare for hardfork of chain '%s' for net '%s'", a_chain->name, l_net->pub.name);
    struct hardfork_states *l_states = DAP_NEW_Z_RET_VAL_IF_FAIL(struct hardfork_states, -1, NULL);
    l_states->balances = dap_ledger_states_aggregate(l_net->pub.ledger, a_last_block_timestamp, &l_states->condouts, a_changed_addrs);
    l_states->anchors = dap_ledger_anchors_aggregate(l_net->pub.ledger, a_chain->id);
    l_states->fees = dap_chain_cs_blocks_fees_aggregate(a_chain);
    size_t l_state_size = 0;
    l_states->service_states = dap_chain_srv_hardfork_all(l_net->pub.id);
    dap_chain_srv_hardfork_state_t *it, *tmp;
    DL_FOREACH_SAFE(l_states->service_states, it, tmp) {
        if (it->uid.uint64 < (uint64_t)INT64_MIN)       // MSB is not set
            continue;
        size_t l_datums_count = 0;
        dap_chain_datum_t **l_datums = s_service_state_datums_create(it, &l_datums_count);
        for (size_t i = 0; i < l_datums_count; i++)
            DAP_DELETE(dap_chain_mempool_datum_add(l_datums[i], a_chain, "hex"));
        DL_DELETE(l_states->service_states, it);
        DAP_DELETE(it);
    }
    l_states->trusted_addrs = a_trusted_addrs;
    a_chain->hardfork_data = l_states;
    dap_chain_cell_create(a_chain, c_dap_chain_cell_id_hardfork);
    return 0;
}

dap_chain_datum_t *s_datum_tx_create(dap_chain_addr_t *a_addr, const char *a_ticker, uint256_t a_value, dap_list_t *a_trackers)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        return NULL;
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr, a_value, a_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    for (dap_list_t *it = a_trackers; it; it = it->next) {
        dap_ledger_tracker_t *l_tracker = it->data;
        dap_chain_tx_tsd_t *l_tracker_tsd = dap_chain_datum_tx_item_tsd_create(l_tracker, DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TRACKER, sizeof(dap_ledger_tracker_t));
        if (!l_tracker_tsd) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        if (dap_chain_datum_tx_add_item(&l_tx, l_tracker_tsd) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));
    dap_chain_datum_tx_delete(l_tx);
    return l_datum_tx;
}

dap_chain_datum_t *s_cond_tx_create(dap_chain_tx_out_cond_t *a_cond, dap_chain_tx_sig_t *a_sign, dap_hash_fast_t *a_hash, const char *a_ticker, dap_list_t *a_trackers)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        return NULL;
    if (dap_chain_datum_tx_add_item(&l_tx, a_cond) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    if (dap_chain_datum_tx_add_item(&l_tx, a_sign) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    dap_chain_tx_tsd_t *l_tx_hash_tsd = dap_chain_datum_tx_item_tsd_create(a_hash, DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TX_HASH, sizeof(dap_hash_fast_t));
    if (!l_tx_hash_tsd) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    if (dap_chain_datum_tx_add_item(&l_tx, l_tx_hash_tsd) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    dap_chain_tx_tsd_t *l_ticker_tsd = dap_chain_datum_tx_item_tsd_create(a_ticker, DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TICKER, DAP_CHAIN_TICKER_SIZE_MAX);
    if (!l_ticker_tsd) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    if (dap_chain_datum_tx_add_item(&l_tx, l_ticker_tsd) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    for (dap_list_t *it = a_trackers; it; it = it->next) {
        dap_ledger_tracker_t *l_tracker = it->data;
        dap_chain_tx_tsd_t *l_tracker_hash_tsd = dap_chain_datum_tx_item_tsd_create(&l_tracker->voting_hash, DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_VOTING_HASH, sizeof(dap_hash_fast_t));
        if (!l_tracker_hash_tsd) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        if (dap_chain_datum_tx_add_item(&l_tx, l_tracker_hash_tsd) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        for (dap_ledger_tracker_item_t *l_item = l_tracker->items; l_item; l_item = l_item->next) {
            dap_ledger_hardfork_tracker_t l_hardfork_tracker = { .pkey_hash = l_item->pkey_hash, .coloured_value = l_item->coloured_value };
            dap_chain_tx_tsd_t *l_tracker_tsd = dap_chain_datum_tx_item_tsd_create(&l_hardfork_tracker, DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TRACKER, sizeof(dap_ledger_hardfork_tracker_t));
            if (!l_tracker_tsd) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
            if (dap_chain_datum_tx_add_item(&l_tx, l_tracker_tsd) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));
    dap_chain_datum_tx_delete(l_tx);
    return l_datum_tx;
}

dap_chain_datum_t *s_fee_tx_create(uint256_t a_value, dap_sign_t *a_owner_sign)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx)
        return NULL;
    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_item_out_cond_create_fee_stack(a_value);
    if (dap_chain_datum_tx_add_item(&l_tx, l_cond) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    dap_chain_tx_sig_t *l_tx_sig = dap_chain_tx_sig_create(a_owner_sign);
    if (dap_chain_datum_tx_add_item(&l_tx, l_tx_sig) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, dap_chain_datum_tx_get_size(l_tx));
    dap_chain_datum_tx_delete(l_tx);
    return l_datum_tx;
}

int dap_chain_node_hardfork_process(dap_chain_t *a_chain)
{
    dap_return_val_if_fail(a_chain, -1);
    if (!dap_chain_net_by_id(a_chain->net_id)->pub.mempool_autoproc)
        return -2;
    if (!a_chain->hardfork_data)
        return log_it(L_ERROR, "Can't process chain with no harfork data. Use dap_chain_node_hardfork_prepare() for collect it first"), -2;
    struct hardfork_states *l_states = a_chain->hardfork_data;
    switch (l_states->state_current) {
    case STATE_ANCHORS:
        for (dap_ledger_hardfork_anchors_t *it = l_states->anchors; it; it = it->next) {
            dap_chain_datum_t *l_datum_anchor = dap_chain_datum_create(DAP_CHAIN_DATUM_ANCHOR, it->anchor, dap_chain_datum_anchor_get_size(it->anchor));
            if (!l_datum_anchor)
                return -2;
            if (!a_chain->callback_add_datums(a_chain, &l_datum_anchor, 1)) {
                dap_hash_fast_t l_decree_hash;
                dap_chain_datum_anchor_get_hash_from_data(it->anchor, &l_decree_hash);
                log_it(L_NOTICE, "Hardfork processed to datum anchor for decree hash %s", dap_hash_fast_to_str_static(&l_decree_hash));
                DAP_DELETE(l_datum_anchor);
                break;
            }
            DAP_DELETE(l_datum_anchor);
        }
    case STATE_BALANCES:
        for (dap_ledger_hardfork_balances_t *it = l_states->balances; it; it = it->next) {
            dap_chain_datum_t *l_tx = s_datum_tx_create(&it->addr, it->ticker, it->value, it->trackers);
            if (!l_tx)
                return -3;
            if (!a_chain->callback_add_datums(a_chain, &l_tx, 1)) {
                DAP_DELETE(l_tx);
                log_it(L_NOTICE, "Hardfork processed to datum tx with addr %s", dap_chain_addr_to_str_static(&it->addr));
                break;
            }
            DAP_DELETE(l_tx);
        }
    case STATE_CONDOUTS:
        for (dap_ledger_hardfork_condouts_t *it = l_states->condouts; it; it = it->next) {
            dap_chain_datum_t *l_cond_tx = s_cond_tx_create(it->cond, it->sign, &it->hash, it->ticker, it->trackers);
            if (!l_cond_tx)
                return -4;
            if (!a_chain->callback_add_datums(a_chain, &l_cond_tx, 1)) {
                DAP_DELETE(l_cond_tx);
                log_it(L_NOTICE, "Hardfork processed to datum cond_tx with hash %s", dap_hash_fast_to_str_static(&it->hash));
                break;
            }
            DAP_DELETE(l_cond_tx);
        }
    case STATE_FEES:
        for (dap_chain_cs_blocks_hardfork_fees_t *it = l_states->fees; it; it = it->next) {
            dap_chain_datum_t *l_fee_tx = s_fee_tx_create(it->fees_n_rewards_sum, it->owner_sign);
            if (!l_fee_tx)
                return -4;
            if (!a_chain->callback_add_datums(a_chain, &l_fee_tx, 1)) {
                DAP_DELETE(l_fee_tx);
                dap_hash_fast_t l_pkey_hash; dap_sign_get_pkey_hash(it->owner_sign, &l_pkey_hash);
                log_it(L_NOTICE, "Hardfork processed to datum fee_tx with hash %s", dap_hash_fast_to_str_static(&l_pkey_hash));
                break;
            }
            DAP_DELETE(l_fee_tx);
        }
    case STATE_SERVICES:
        for (dap_chain_srv_hardfork_state_t *it = l_states->service_states; it; it = it->next) {
            if (it->uid.uint64 >= (uint64_t)INT64_MIN)       // MSB is set
                continue;
            bool l_break = false;
            size_t l_datums_count = 0;
            dap_chain_datum_t **l_datums = s_service_state_datums_create(it, &l_datums_count);
            for (size_t i = l_states->iterator; i < l_datums_count; i++) {
                if (!a_chain->callback_add_datums(a_chain, l_datums + i, 1)) {
                    log_it(L_NOTICE, "Hardfork processed to datum service_state with uid %" DAP_UINT64_FORMAT_x " and number %zu",
                                        it->uid.uint64, i);
                    // save iterator to state machine
                    l_states->iterator = i;
                    l_break = true;
                    break;
                }

            }
            for (size_t i = 0; i < l_datums_count; i++)
                DAP_DELETE(l_datums[i]);
            DAP_DEL_Z(l_datums);
            if (l_break)
                break;
        }
    case STATE_MEMPOOL: {
        char *l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
        size_t l_objs_count = 0;
        dap_store_obj_t *l_objs = dap_global_db_get_all_raw_sync(l_gdb_group_mempool, &l_objs_count);
        for (size_t i = 0; i < l_objs_count; i++) {
            if (dap_store_obj_get_type(l_objs +i) == DAP_GLOBAL_DB_OPTYPE_DEL)
                continue;
            if (l_objs[i].value_len < sizeof(dap_chain_datum_t))
                continue;
            if (!l_objs[i].sign)
                continue;
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
            if (l_datum->header.type_id != DAP_CHAIN_DATUM_SERVICE_STATE)
                continue;
            dap_stream_node_addr_t l_addr = dap_stream_node_addr_from_sign(l_objs[i].sign);
            bool l_addr_match = false;
            for (dap_list_t *it = l_states->trusted_addrs; it; it = it->next) {
                if (((dap_stream_node_addr_t *)it->data)->uint64 != l_addr.uint64)
                    continue;
                l_addr_match = true;
                break;
            }
            if (!l_addr_match) {
                log_it(L_WARNING, "Trying to inject hardfork service state datum from addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_addr));
                continue;
            }
            dap_hash_str_t l_key = dap_get_data_hash_str(l_datum->data, l_datum->header.data_size);
            if (dap_chain_datum_size(l_datum) != l_objs[i].value_len) {
                log_it(L_WARNING, "Trying to process hardfork service state datum with incorrect size %zu (expect %zu)",
                                                                            dap_chain_datum_size(l_datum), l_objs[i].value_len);
                continue;
            }
            if (dap_strcmp(l_objs[i].key, l_key.s)) {
                log_it(L_WARNING, "Trying to process hardfork service state datum with hash mismatch");
                continue;
            }
            if (dap_chain_node_mempool_process(a_chain, l_datum, l_objs[i].key, NULL))
                dap_global_db_del(l_gdb_group_mempool, l_objs[i].key, NULL, NULL);
        }
        dap_store_obj_free(l_objs, l_objs_count);
        DAP_DELETE(l_gdb_group_mempool);
    } break;
    // No default here
    }
    return 0;
}

static int s_compare_trackers(dap_list_t *a_list1, dap_list_t *a_list2)
{
    int ret = 0;
    for (dap_list_t *it1 = a_list1, *it2 = a_list2; it1 && it2; it1 = it1->next, it2 = it2->next) {
        dap_ledger_tracker_t *l_tracker1 = it1->data,
                             *l_tracker2 = it2->data;
        ret = memcmp(&l_tracker1->voting_hash, &l_tracker1->voting_hash, sizeof(dap_hash_fast_t));
        if (ret)            // hash mismatch
            break;
        dap_ledger_tracker_item_t *it1 = l_tracker1->items, *it2 = l_tracker2->items;
        for (; it1 && it2; it1 = it1->next, it2 = it2->next) {
            ret = memcmp(&it1->pkey_hash, &it2->pkey_hash, sizeof(dap_hash_fast_t));
            if (ret)        // pkey mismatch
                break;
            ret = compare256(it1->coloured_value, it2->coloured_value);
            if (ret)        // value mismatch
                break;
        }
        if (it1 || it2)     // count mismatch
            return 1;
    }
    return ret;
}

static int s_compare_balances(dap_ledger_hardfork_balances_t *a_list1, dap_ledger_hardfork_balances_t *a_list2)
{
    int ret = memcmp(&a_list1->addr, &a_list2->addr, sizeof(dap_chain_addr_t));
    if (ret)
        return ret;
    ret = memcmp(a_list1->ticker, a_list2->ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    if (ret)
        return ret;
    ret = compare256(a_list1->value, a_list2->value);
    if (ret)
        return ret;
    return s_compare_trackers(a_list1->trackers, a_list2->trackers);
}

static int s_compare_condouts(dap_ledger_hardfork_condouts_t *a_list1, dap_ledger_hardfork_condouts_t *a_list2)
{
    int ret = memcmp(&a_list1->hash, &a_list2->hash, sizeof(dap_hash_fast_t));
    if (ret)
        return ret;
    ret = memcmp(a_list1->ticker, a_list2->ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    if (ret)
        return ret;
    ret = a_list1->sign->header.sig_size != a_list2->sign->header.sig_size;
    if (ret)
        return ret;
    ret = memcmp(a_list1->sign->sig, a_list2->sign->sig, a_list1->sign->header.sig_size);
    if (ret)
        return ret;
    size_t l_cond_size = dap_chain_datum_item_tx_get_size((const byte_t *)a_list1->cond, 0);
    ret = l_cond_size != dap_chain_datum_item_tx_get_size((const byte_t *)a_list2->cond, 0);
    if (ret)
        return ret;
    ret = memcmp(a_list1->cond, a_list2->cond, l_cond_size);
    if (ret)
        return ret;
    return s_compare_trackers(a_list1->trackers, a_list2->trackers);
}

static int s_compare_fees(dap_chain_cs_blocks_hardfork_fees_t *a_list1, dap_chain_cs_blocks_hardfork_fees_t *a_list2)
{
    int ret = compare256(a_list1->fees_n_rewards_sum, a_list2->fees_n_rewards_sum);
    if (ret)
        return ret;
    size_t l_sign_size = dap_sign_get_size(a_list1->owner_sign);
    ret = l_sign_size != dap_sign_get_size(a_list2->owner_sign);
    if (ret)
        return ret;
    return memcmp(a_list1->owner_sign, a_list2->owner_sign, l_sign_size);
}

static int s_compare_anchors(dap_ledger_hardfork_anchors_t *a_list1, dap_ledger_hardfork_anchors_t *a_list2)
{
    size_t l_anchor_size = dap_chain_datum_anchor_get_size(a_list1->anchor);
    int ret = l_anchor_size != dap_chain_datum_anchor_get_size(a_list2->anchor);
    if (ret)
        return ret;
    return memcmp(a_list1->anchor, a_list1->anchor, l_anchor_size);
}

static int s_compare_service_states(dap_chain_srv_hardfork_state_t *a_list1, dap_chain_srv_hardfork_state_t *a_list2)
{
    return a_list1->uid.uint64 != a_list2->uid.uint64;
}

int s_hardfork_check(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, size_t a_datum_size, bool a_remove)
{
    if (a_datum_size <= sizeof(dap_chain_datum_t) || dap_chain_datum_size(a_datum) != a_datum_size) {
        log_it(L_WARNING, "Incorrect harfork datum size %zu", a_datum_size <= sizeof(dap_chain_datum_t) ? a_datum_size : dap_chain_datum_size(a_datum));
        return -1;
    }
    switch (a_datum->header.type_id) {

    case DAP_CHAIN_DATUM_ANCHOR: {
        dap_ledger_hardfork_anchors_t *l_found = NULL,
                                       l_sought = { .anchor = (dap_chain_datum_anchor_t *)a_datum->data };

        DL_SEARCH(a_chain->hardfork_data->anchors, l_found, &l_sought, s_compare_anchors);
        if (l_found) {
            if (a_remove) {
                DL_DELETE(a_chain->hardfork_data->anchors, l_found);
                DAP_DELETE(l_found);
                if (!a_chain->hardfork_data->anchors)
                    a_chain->hardfork_data->state_current = STATE_BALANCES;
            }
            break;
        }
    } break;

#define m_ret_clear(rc) {                                                               \
        if (l_regular.trackers)                                                         \
            dap_list_free_full(l_regular.trackers, dap_ledger_colour_clear_callback);   \
        if (l_conitional.trackers)                                                      \
            dap_list_free_full(l_conitional.trackers, dap_ledger_colour_clear_callback);\
        return rc;                                                                      \
    }

    case DAP_CHAIN_DATUM_TX: {
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_datum->data;
        if (!l_tx->header.ts_created /* TODO add || l_tx->header.ts_created other criteria */) {
            char l_time[DAP_TIME_STR_SIZE]; dap_time_to_str_rfc822(l_time, DAP_TIME_STR_SIZE, l_tx->header.ts_created);
            log_it(L_WARNING, "Incorrect harfork datum timestamp %s", l_time);
            return -3;
        }
        // Parse datum
        dap_ledger_hardfork_balances_t l_regular = {};
        dap_ledger_hardfork_condouts_t l_conitional = {};
        dap_ledger_tracker_t *l_tracker_current = NULL;
        bool l_out = false;
        byte_t *l_item; size_t l_size;
        TX_ITEM_ITER_TX(l_item, l_size, l_tx) {
            switch (*l_item) {
            case TX_ITEM_TYPE_OUT_EXT:
                if (l_out || l_conitional.cond) {
                    log_it(L_WARNING, "Additional OUT_EXT item for harfork datum tx is forbidden");
                    m_ret_clear(-4);
                }
                l_out = true;
                dap_chain_tx_out_ext_t *l_out_ext = (dap_chain_tx_out_ext_t *)l_item;
                l_regular.addr = l_out_ext->addr;
                dap_stpcpy(l_regular.ticker, l_out_ext->token);
                l_regular.value = l_out_ext->header.value;
                break;
            case TX_ITEM_TYPE_OUT_COND:
                if (l_out || l_conitional.cond) {
                    log_it(L_WARNING, "Additional OUT_COND item for harfork datum tx is forbidden");
                    m_ret_clear(-5);
                }
                l_conitional.cond = (dap_chain_tx_out_cond_t *)l_item;
                break;
            case TX_ITEM_TYPE_SIG:
                if (l_conitional.sign) {
                    log_it(L_WARNING, "Additional SIG item for harfork datum tx is forbidden");
                    m_ret_clear(-6);
                }
                l_conitional.sign = (dap_chain_tx_sig_t *)l_item;
                break;
            case TX_ITEM_TYPE_TSD: {
                dap_chain_tx_tsd_t *l_tx_tsd = (dap_chain_tx_tsd_t *)l_item;
                if (l_tx_tsd->header.size < sizeof(dap_tsd_t)) {
                    log_it(L_WARNING, "Illegal harfork datum tx TSD header size %" DAP_UINT64_FORMAT_U, l_tx_tsd->header.size);
                    m_ret_clear(-8);
                }
                dap_tsd_t *l_tsd = (dap_tsd_t *)l_tx_tsd->tsd;
                switch (l_tsd->type) {
                case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TX_HASH:
                    l_conitional.hash = *(dap_hash_fast_t *)l_tsd->data;
                    break;
                case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TICKER:
                    if (!l_tsd->size || l_tsd->size > DAP_CHAIN_TICKER_SIZE_MAX) {
                        log_it(L_WARNING, "Illegal harfork datum tx TSD TICKER size %u", l_tsd->size);
                        m_ret_clear(-8);
                    }
                    dap_strncpy(l_conitional.ticker, (char *)l_tsd->data, DAP_CHAIN_TICKER_SIZE_MAX);
                    break;
                case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_VOTING_HASH: {
                    if (l_tsd->size != sizeof(dap_hash_fast_t)) {
                        log_it(L_WARNING, "Illegal harfork datum tx TSD VOTING_HASH size %u", l_tsd->size);
                        m_ret_clear(-8);
                    }
                    l_tracker_current = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_tracker_t, -2);
                    l_tracker_current->voting_hash = *(dap_hash_fast_t *)l_tsd->data;
                    if (l_out)
                        l_regular.trackers = dap_list_append(l_regular.trackers, l_tracker_current);
                    else
                        l_conitional.trackers = dap_list_append(l_conitional.trackers, l_tracker_current);
                } break;
                case DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TRACKER: {
                    if (l_tsd->size != sizeof(dap_ledger_hardfork_tracker_t)) {
                        log_it(L_WARNING, "Illegal harfork datum tx TSD VOTING_HASH size %u", l_tsd->size);
                        m_ret_clear(-8);
                    }
                    if (!l_tracker_current) {
                        log_it(L_WARNING, "No voting hash defined for tracking item");
                        m_ret_clear(-19);
                    }
                    dap_ledger_hardfork_tracker_t *l_tsd_item = (dap_ledger_hardfork_tracker_t *)l_tsd->data;
                    dap_ledger_tracker_item_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_ledger_tracker_item_t, -2);
                    l_item->pkey_hash = l_tsd_item->pkey_hash;
                    l_item->coloured_value = l_tsd_item->coloured_value;
                    DL_APPEND(l_tracker_current->items, l_item);
                } break;
                default:
                    log_it(L_WARNING, "Illegal harfork datum tx TSD item type 0x%X", l_tsd->type);
                    m_ret_clear(-7);
                }
            } break;
            default:
                log_it(L_WARNING, "Illegal harfork datum tx item type %d", *l_item);
                m_ret_clear(-4);
            }
        }
        // Call comparators
        if (l_out) {
            dap_ledger_hardfork_balances_t *l_found = NULL;
            DL_SEARCH(a_chain->hardfork_data->balances, l_found, &l_regular, s_compare_balances);
            if (l_found) {
                if (a_remove) {
                    DL_DELETE(a_chain->hardfork_data->balances, l_found);
                    dap_list_free_full(l_found->trackers, dap_ledger_colour_clear_callback);
                    DAP_DELETE(l_found);
                    if (!a_chain->hardfork_data->balances)
                        a_chain->hardfork_data->state_current = STATE_CONDOUTS;
                }
                break;
            }
        } else if (l_conitional.cond) {
            if (l_conitional.cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE_STACK) {
                dap_ledger_hardfork_condouts_t *l_found = NULL;
                DL_SEARCH(a_chain->hardfork_data->condouts, l_found, &l_conitional, s_compare_condouts);
                if (l_found) {
                    if (a_remove) {
                        DL_DELETE(a_chain->hardfork_data->condouts, l_found);
                        dap_list_free_full(l_found->trackers, dap_ledger_colour_clear_callback);
                        DAP_DELETE(l_found);
                        if (!a_chain->hardfork_data->condouts)
                            a_chain->hardfork_data->state_current = STATE_FEES;
                    }
                    break;
                }
            } else {
                dap_chain_cs_blocks_hardfork_fees_t *l_found = NULL,
                                                     l_sought = { .fees_n_rewards_sum = l_conitional.cond->header.value,
                                                                  .owner_sign = dap_chain_datum_tx_item_sig_get_sign(l_conitional.sign) };
                DL_SEARCH(a_chain->hardfork_data->fees, l_found, &l_sought, s_compare_fees);
                if (l_found) {
                    if (a_remove) {
                        DL_DELETE(a_chain->hardfork_data->fees, l_found);
                        DAP_DELETE(l_found);
                        if (!a_chain->hardfork_data->fees)
                            a_chain->hardfork_data->state_current = STATE_SERVICES;
                    }
                    break;
                }
            }
        } else {
            log_it(L_WARNING, "Illegal harfork datum tx item with no OUT");
            m_ret_clear(-18);
        }
        // Clean memory
        if (l_regular.trackers)
            dap_list_free_full(l_regular.trackers, dap_ledger_colour_clear_callback);
        if (l_conitional.trackers)
            dap_list_free_full(l_conitional.trackers, dap_ledger_colour_clear_callback);
    } break;
#undef m_ret_clear

    case DAP_CHAIN_DATUM_SERVICE_STATE: {
        dap_chain_srv_hardfork_state_t *l_found = NULL,
                                        l_sought = { .uid = ((dap_chain_datum_service_state_t *)a_datum->data)->srv_uid };

        DL_SEARCH(a_chain->hardfork_data->service_states, l_found, &l_sought, s_compare_service_states);
        if (l_found) {
            if (a_remove) {
                DL_DELETE(a_chain->hardfork_data->service_states, l_found);
                DAP_DEL_MULTY(l_found->data, l_found);
                if (!a_chain->hardfork_data->service_states)
                    a_chain->hardfork_data->state_current = STATE_MEMPOOL;
            }
            break;
        }
        dap_hash_str_t l_key = dap_get_data_hash_str(a_datum->data, a_datum->header.data_size);
        char *l_gdb_group_mempool = dap_chain_mempool_group_new(a_chain);
        size_t l_objs_count = 0;
        dap_store_obj_t *l_objs = dap_global_db_get_all_raw_sync(l_gdb_group_mempool, &l_objs_count);
        for (size_t i = 0; i < l_objs_count; i++) {
            if (dap_strcmp(l_objs[i].key, l_key.s))
                continue;
            if (a_remove) {
                dap_global_db_del(l_gdb_group_mempool, l_objs[i].key, NULL, NULL);
                break;
            }

#define m_ret(rc) { \
        dap_store_obj_free(l_objs, l_objs_count); \
        DAP_DELETE(l_gdb_group_mempool); \
        return rc; \
    }
            if (dap_store_obj_get_type(l_objs +i) == DAP_GLOBAL_DB_OPTYPE_DEL) {
                log_it(L_WARNING, "Mempool record %s already deleted, can' process", l_objs[i].key);
                m_ret(-8);
            }
            if (l_objs[i].value_len < sizeof(dap_chain_datum_t)) {
                log_it(L_WARNING, "Can't process hardfork service state datum %s with too small size %zu", l_objs[i].key, l_objs[i].value_len);
                m_ret(-9);
            }
            if (!l_objs[i].sign) {
                log_it(L_WARNING, "Can't process unsigned hardfork service state datum %s with too small size %zu", l_objs[i].key, l_objs[i].value_len);
                m_ret(-10);
            }
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
            if (dap_chain_datum_size(l_datum) != l_objs[i].value_len) {
                log_it(L_WARNING, "Harfork datum service state with incorrect size %zu", dap_chain_datum_size(l_datum));
                m_ret(-13);
            }
            dap_hash_str_t l_key = dap_get_data_hash_str(a_datum->data, a_datum->header.data_size);
            if (l_datum->header.type_id != DAP_CHAIN_DATUM_SERVICE_STATE) {
                log_it(L_WARNING, "Mempool record %s isn't service state hardfork datum, can' process", l_objs[i].key);
                m_ret(-14);
            }
            dap_hash_str_t l_key_hash = dap_get_data_hash_str(l_datum->data, l_datum->header.data_size);
            if (l_datum->header.data_size != a_datum->header.data_size ||
                    dap_strcmp(l_key_hash.s, l_key.s)) {
                log_it(L_WARNING, "Mempool record %s datum is corrupted, can' process", l_objs[i].key);
                m_ret(-15);
            }
            dap_stream_node_addr_t l_addr = dap_stream_node_addr_from_sign(l_objs[i].sign);
            bool l_addr_match = false;
            for (dap_list_t *it = a_chain->hardfork_data->trusted_addrs; it; it = it->next) {
                if (((dap_stream_node_addr_t *)it->data)->uint64 != l_addr.uint64)
                    continue;
                l_addr_match = true;
                break;
            }
            if (!l_addr_match) {
                log_it(L_WARNING, "Trying to inject hardfork service state datum from addr " NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS_S(l_addr));
                m_ret(-16);
            }
            m_ret(0);
        }

    } break;
#undef m_ret

    default:
        log_it(L_WARNING, "Incorrect harfork datum type %u", a_datum->header.type_id);
        return -2;
    }

    return 0;
}

int dap_chain_node_hardfork_check(dap_chain_t *a_chain, dap_chain_datum_t *a_datum)
{
    return s_hardfork_check(a_chain, a_datum, dap_chain_datum_size(a_datum), false);
}

int dap_chain_node_hardfork_confirm(dap_chain_t *a_chain, dap_chain_datum_t *a_datum)
{
    return s_hardfork_check(a_chain, a_datum, dap_chain_datum_size(a_datum), true);
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
        dap_strncpy(l_item->link_info.uplink_addr, ((dap_chain_node_info_t*)(l_objs + i)->value)->ext_host, sizeof(l_item->link_info.uplink_addr));

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

int dap_chain_node_cli_cmd_values_parse_net_chain_for_json(json_object *a_json_arr_reply, int *a_arg_index,
                                                           int a_argc, char **a_argv,
                                                           dap_chain_t **a_chain, dap_chain_net_t **a_net,
                                                           dap_chain_type_t a_default_chain_type)
{
    const char *l_chain_str = NULL, *l_net_str = NULL;

    // Net name
    if(a_net)
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-net", &l_net_str);
    else {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_INTERNAL_COMMAND_PROCESSING,
                               "Error in internal command processing.");
        return DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_INTERNAL_COMMAND_PROCESSING;
    }

    // Select network
    if(!l_net_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_STR_IS_NUL, "%s requires parameter '-net'", a_argv[0]);
        return DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_STR_IS_NUL;
    }

    if (! (*a_net = dap_chain_net_by_name(l_net_str)) ) { // Can't find such network
        return dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_NOT_FOUND,
                                                        "Network %s not found", l_net_str),
                DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_NET_NOT_FOUND;
    }

    // Chain name
    if(a_chain) {
        dap_cli_server_cmd_find_option_val(a_argv, *a_arg_index, a_argc, "-chain", &l_chain_str);

        // Select chain
        if(l_chain_str) {
            if ((*a_chain = dap_chain_net_get_chain_by_name(*a_net, l_chain_str)) == NULL) { // Can't find such chain
                dap_string_t *l_reply = dap_string_new("");
                dap_string_append_printf(l_reply, "Invalid '-chain' parameter \"%s\", not found in net %s\n"
                                                  "Available chains:",
                                                  l_chain_str, l_net_str);
                dap_chain_t *l_chain;
                DL_FOREACH((*a_net)->pub.chains, l_chain) {
                    dap_string_append_printf(l_reply, "\n\t%s", l_chain->name);
                }
                char *l_str_reply = dap_string_free(l_reply, false);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CHAIN_NOT_FOUND, "%s", l_str_reply);
                return DAP_DELETE(l_str_reply), DAP_CHAIN_NODE_CLI_CMD_VALUES_PARSE_NET_CHAIN_ERR_CHAIN_NOT_FOUND;
            }
        } else if (a_default_chain_type != CHAIN_TYPE_INVALID) {
            if (( *a_chain = dap_chain_net_get_default_chain_by_chain_type(*a_net, a_default_chain_type) ))
                return 0;
            else {
                dap_json_rpc_error_add(a_json_arr_reply, 
                        DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_CAN_NOT_FIND_DEFAULT_CHAIN_WITH_TYPE,
                        "Unable to get the default chain of type %s for the network.", dap_chain_type_to_str(a_default_chain_type));
                return DAP_CHAIN_NODE_CLI_CMD_VALUE_PARSE_CAN_NOT_FIND_DEFAULT_CHAIN_WITH_TYPE;
            }
        }
    }
    return 0;
}
