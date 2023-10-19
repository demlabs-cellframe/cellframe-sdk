/*
 * Authors:
 * Dmitriy A. Gerasimov <naeper@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#define LOG_TAG "chain_node"

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
dap_chain_node_addr_t * dap_chain_node_alias_find(dap_chain_net_t * a_net,const char *a_alias)
{
    size_t l_addr_size =0;
    return (dap_chain_node_addr_t*)dap_global_db_get_sync(a_net->pub.gdb_nodes_aliases,
                                                          a_alias, &l_addr_size, NULL, NULL);
}

/**
 * Delete alias from base
 */
bool dap_chain_node_alias_delete(dap_chain_net_t * a_net,const char *a_alias)
{
    return dap_global_db_del_sync(a_net->pub.gdb_nodes_aliases, a_alias) == 0;
}

/**
 * Calculate size of struct dap_chain_node_info_t
 */
size_t dap_chain_node_info_get_size(dap_chain_node_info_t *node_info)
{
    if(!node_info)
        return 0;
    return (sizeof(dap_chain_node_info_t) + node_info->hdr.links_number * sizeof(dap_chain_node_addr_t));
}

/**
 * Compare addresses of two dap_chain_node_info_t structures
 *
 * @return True if addresses are equal, otherwise false
 */
bool dap_chain_node_info_addr_match(dap_chain_node_info_t *node_info1, dap_chain_node_info_t *node_info2)
{
    if(!node_info1 || !node_info2) {
        return false;
    }
    //if(memcmp(&node_info1->hdr.address, &node_info2->hdr.address, sizeof(dap_chain_addr_t))) {
    //    return false;
    //}
    if(memcmp(&node_info1->hdr.ext_addr_v6, &node_info2->hdr.ext_addr_v6, sizeof(struct in6_addr)) ||
            memcmp(&node_info1->hdr.ext_addr_v4, &node_info2->hdr.ext_addr_v4, sizeof(struct in_addr)) ||
            (node_info1->hdr.ext_port != node_info2->hdr.ext_port)) {
        return false;
    }
    return true;
}


/**
 * @brief dap_chain_node_info_save
 * @param node_info
 * @return
 */
int dap_chain_node_info_save(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info)
{
    if(!a_node_info || !a_node_info->hdr.address.uint64){
        log_it(L_ERROR,"Can't save node info: %s", a_node_info? "null address":"null object" );
        return  -1;
    }
    char *l_key = dap_chain_node_addr_to_hash_str(&a_node_info->hdr.address);

    if(!l_key){
        log_it(L_ERROR,"Can't produce key to save node info ");
        return -2;
    }
    //char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    size_t l_node_info_size = dap_chain_node_info_get_size(a_node_info);
    int l_res = dap_global_db_set_sync( a_net->pub.gdb_nodes, l_key, a_node_info, l_node_info_size, false);

    DAP_DELETE(l_key);

    return l_res;
}

/**
 * Read node from base
 */
dap_chain_node_info_t* dap_chain_node_info_read( dap_chain_net_t * a_net,dap_chain_node_addr_t *l_address)
{
    char *l_key = dap_chain_node_addr_to_hash_str(l_address);
    if(!l_key) {
        log_it(L_WARNING,"Can't calculate hash of addr");
        return NULL;
    }
    size_t node_info_size = 0;
    dap_chain_node_info_t *l_node_info;
    // read node
    l_node_info = (dap_chain_node_info_t *) dap_global_db_get_sync(a_net->pub.gdb_nodes, l_key, &node_info_size, NULL, NULL);

    if(!l_node_info) {
        log_it(L_INFO, "node with key %s (addr " NODE_ADDR_FP_STR ") not found in base",l_key, NODE_ADDR_FP_ARGS(l_address));
        DAP_DELETE(l_key);
        return NULL;
    }

    size_t node_info_size_must_be = dap_chain_node_info_get_size(l_node_info);
    if(node_info_size_must_be != node_info_size) {
        log_it(L_ERROR, "Node has bad size in base=%zu (must be %zu)", node_info_size, node_info_size_must_be);
        DAP_DELETE(l_node_info);
        DAP_DELETE(l_key);
        return NULL;
    }

    DAP_DELETE(l_key);
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
                        if (!dap_chain_ledger_tx_poa_signed(l_net->pub.ledger, l_tx)) {
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
    uint16_t l_net_count;
    if (!dap_config_get_item_bool_default(g_config, "mempool", "auto_proc", false))
        return false;
    dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_count);
    for (uint16_t i = 0; i < l_net_count; i++) {
        dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net_list[i]);
        switch (l_role.enums) {
            case NODE_ROLE_ROOT:
            case NODE_ROLE_MASTER:
            case NODE_ROLE_ROOT_MASTER:
            case NODE_ROLE_CELL_MASTER:
                l_net_list[i]->pub.mempool_autoproc = true;
                break;
            default:
                l_net_list[i]->pub.mempool_autoproc = false;
                continue;
        }
    }
    DAP_DELETE(l_net_list);
    return true;
}

