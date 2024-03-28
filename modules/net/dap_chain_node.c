/*
 * Authors:
 * Dmitriy A. Gerasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Demlabs Application Protocol) the open source project

 DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#include "utlist.h"
#include "dap_hash.h"
#include "rand/dap_rand.h"
#include "dap_chain_net.h"
#include "dap_global_db.h"
#include "dap_chain_node.h"
#include "dap_chain_cell.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "chain_node"

typedef struct dap_chain_node_net_states_info {
    dap_chain_node_addr_t address;
    uint64_t atoms_count;
    uint32_t uplinks_count;
    uint32_t downlinks_count;
    dap_chain_node_addr_t links_addrs[];
} DAP_ALIGN_PACKED dap_chain_node_net_states_info_t;

/**
 * Register alias in base
 */
bool dap_chain_node_alias_register(dap_chain_net_t *a_net, const char *a_alias, dap_chain_node_addr_t *a_addr)
{
    return dap_global_db_set_sync(a_net->pub.gdb_nodes_aliases, a_alias, a_addr, sizeof(dap_chain_node_addr_t), false) == 0;
}

/**
 * @brief dap_chain_node_alias_find
 * @param alias
 * @return
 */
dap_chain_node_addr_t *dap_chain_node_alias_find(dap_chain_net_t *a_net, const char *a_alias)
{
    dap_return_val_if_fail(a_alias && a_net, NULL);
    size_t l_size = 0;
    dap_chain_node_addr_t *l_addr = (dap_chain_node_addr_t*)dap_global_db_get_sync(a_net->pub.gdb_nodes_aliases,
                                                                                   a_alias, &l_size, NULL, NULL);
    return l_addr && l_size != sizeof(dap_chain_node_addr_t)
        ? log_it(L_WARNING, "Node record is corrupted for alias %s: %zu != %zu",
                 a_alias, l_size, sizeof(dap_chain_node_addr_t)), DAP_DELETE(l_addr), NULL
        : l_addr;
}

/**
 * Delete alias from base
 */
bool dap_chain_node_alias_delete(dap_chain_net_t * a_net,const char *a_alias)
{
    return dap_global_db_del_sync(a_net->pub.gdb_nodes_aliases, a_alias) == 0;
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
                                 dap_chain_node_addr_to_str_static(&a_node_info->address),
                                 a_node_info,
                                 dap_chain_node_info_get_size(a_node_info), false );
}

int dap_chain_node_info_del(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info) {
    return !a_node_info || !a_node_info->address.uint64
        ? log_it(L_ERROR,"Can't delete node info, %s", a_node_info ? "null arg" : "zero address"), -1
        : dap_global_db_del_sync( a_net->pub.gdb_nodes,
                                 dap_chain_node_addr_to_str_static(&a_node_info->address) );
}

/**
 * Read node from base
 */
dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_net_t *a_net, dap_chain_node_addr_t *a_address)
{
    char *l_key = dap_chain_node_addr_to_str_static(a_address);
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
bool dap_chain_node_mempool_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum, const char *a_datum_hash_str)
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
    dap_hash_fast(a_datum->data, a_datum->header.data_size, &l_real_hash);
    if (!dap_hash_fast_compare(&l_datum_hash, &l_real_hash)) {
        log_it(L_WARNING, "Datum hash from mempool key and real datum hash are different");
        return false;
    }
    int l_verify_datum = dap_chain_net_verify_datum_for_add(a_chain, a_datum, &l_datum_hash);
    if (l_verify_datum != 0 &&
            l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS &&
            l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION &&
            l_verify_datum != DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE)
        return true;
    if (!l_verify_datum
#ifdef DAP_TPS_TEST
            || l_verify_datum == DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS
#endif
            )
    {
        a_chain->callback_add_datums(a_chain, &a_datum, 1);
    }
    return false;
}

void dap_chain_node_mempool_process_all(dap_chain_t *a_chain, bool a_force)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!a_force && !l_net->pub.mempool_autoproc)
        return;
    char *l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    size_t l_objs_size = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_gdb_group_mempool, &l_objs_size);
    if (l_objs_size) {
        for (size_t i = 0; i < l_objs_size; i++) {
            if (!l_objs[i].value_len)
                continue;
            dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
            if (dap_chain_node_mempool_need_process(a_chain, l_datum)) {

                if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX &&
                        a_chain->callback_get_minimum_fee){
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
                        uint256_t l_min_fee = a_chain->callback_get_minimum_fee(a_chain);
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

                if (dap_chain_node_mempool_process(a_chain, l_datum, l_objs[i].key)) {
                    // Delete processed objects
                    log_it(L_INFO, " ! Delete datum %s from mempool", l_objs[i].key);
                    dap_global_db_del(l_gdb_group_mempool, l_objs[i].key, NULL, NULL);
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
 * @brief get states info about current
 * @param a_net - net to update states info
 */
void dap_chain_node_update_node_states_info(dap_chain_net_t *a_net)
{
// sanity check
    dap_return_if_pass(!a_net);
    size_t
        l_uplinks_count = 0,
        l_downlinks_count = 0,
        l_info_size = 0,
        l_info_signed_size = 0;
    dap_chain_t *l_chain = dap_chain_find_by_id(a_net->pub.id, (dap_chain_id_t){ .uint64 = 1 });
    dap_stream_node_addr_t *l_linked_node_addrs = dap_link_manager_get_net_links_addrs(a_net->pub.id.uint64, &l_uplinks_count, &l_downlinks_count );
    dap_cert_t *l_cert = dap_cert_find_by_name(DAP_STREAM_NODE_ADDR_CERT_NAME);
    dap_return_if_pass(!l_chain || !l_linked_node_addrs || !l_cert);
// memory alloc first
    dap_chain_node_net_states_info_t *l_info = NULL;
    l_info_size = sizeof(dap_chain_node_net_states_info_t) + (l_uplinks_count + l_downlinks_count) * sizeof(dap_chain_node_addr_t);
    DAP_NEW_Z_SIZE_RET(l_info, dap_chain_node_net_states_info_t, l_info_size, l_linked_node_addrs);
// func work
    // data preparing
    l_info->address.uint64 = g_node_addr.uint64;
    l_info->uplinks_count = l_uplinks_count;
    l_info->downlinks_count = l_downlinks_count;
    l_info->atoms_count = l_chain->callback_count_atom ? l_chain->callback_count_atom(l_chain) : 0;
    memcpy(l_info->links_addrs, l_linked_node_addrs, (l_info->uplinks_count + l_info->downlinks_count) * sizeof(dap_chain_node_addr_t));
    // DB write
    char *l_gdb_group = dap_strdup_printf("%s.nodes.states", a_net->pub.gdb_groups_prefix);
    char *l_node_addr_str = dap_stream_node_addr_to_str(l_info->address, false);
    dap_global_db_set_sync(l_gdb_group, l_node_addr_str, l_info, l_info_signed_size, false);
    DAP_DEL_MULTY(l_linked_node_addrs, l_info, l_gdb_group, l_node_addr_str);
}


/**
 * @brief comparing dap_chain_node_states_info_t
 * @param a_first - pointer to first item
 * @param a_second - pointer to second 
 * @return a_first < a_second -1, a_first > a_second 1, a_first = a_second 0
 */
static int s_node_states_info_cmp(void *a_first, void *a_second)
{
  dap_chain_node_states_info_t *a = a_first;
  dap_chain_node_states_info_t *b = a_second;

  if(a->timestamp > b->timestamp && a->timestamp - b->timestamp > 1000000) return -1;
  if(b->timestamp > a->timestamp && b->timestamp - a->timestamp > 1000000) return 1;
  if(a->atoms_count > b->atoms_count && a->atoms_count - b->atoms_count > 100) return -1;
  if(b->atoms_count > a->atoms_count && b->atoms_count - a->atoms_count > 100) return 1;
  if(a->downlinks_count < b->downlinks_count) return -1;
  if(b->downlinks_count < a->downlinks_count) return 1;
  return 0;
}

/**
 * @brief geting sorted list with nodes states
 * @param a_net - pointer to net
 * @return pointer to sorted list or NULL if error
 */
dap_list_t *dap_get_nodes_states_list_sort(dap_chain_net_t *a_net)
{
// sanity check
    dap_return_val_if_pass(!a_net, NULL);
// func work
    size_t l_node_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_net->pub.gdb_nodes, &l_node_count);
    if (!l_node_count || !l_objs) {        
        log_it(L_ERROR, "Node list in net %s is empty", a_net->pub.name);
        return NULL;
    }
    char *l_group = NULL;  // TODO
    dap_list_t *l_ret = NULL;
    for (size_t i = 0; i < l_node_count; ++i) {
        if (!l_objs[i].value) {
            log_it(L_ERROR, "Invalid record, key %s", l_objs[i].key);
            continue;
        }
        dap_nanotime_t l_timestamp = 0;
        dap_chain_node_net_states_info_t *l_store_obj = dap_global_db_get_sync(l_group, l_objs[i].key, NULL, NULL, &l_timestamp);
        if (l_store_obj) {
            log_it(L_ERROR, "Can't find state about %s node", l_objs[i].key);
            continue;
        }
        dap_chain_node_states_info_t *l_item = DAP_NEW_Z(dap_chain_node_states_info_t);
        if(!l_item) {
            log_it(L_ERROR, "%s", g_error_memory_alloc);
            break;
        }
        l_item->link_info.node_addr.uint64 = ((dap_chain_node_info_t*)(l_objs + i)->value)->address.uint64;
        l_item->link_info.uplink_port = ((dap_chain_node_info_t*)(l_objs + i)->value)->ext_port;
        dap_strncpy(l_item->link_info.uplink_addr, ((dap_chain_node_info_t*)(l_objs + i)->value)->ext_host, sizeof(l_item->link_info.uplink_addr) - 1);
        l_item->atoms_count = l_store_obj->atoms_count;
        l_item->downlinks_count = l_store_obj->downlinks_count;
        l_item->timestamp = l_timestamp;
        l_ret = dap_list_insert_sorted(l_ret, (void *)l_item, s_node_states_info_cmp);
        DAP_DELETE(l_store_obj);
    }
    dap_global_db_objs_delete(l_objs, l_node_count);
    return l_ret;
}