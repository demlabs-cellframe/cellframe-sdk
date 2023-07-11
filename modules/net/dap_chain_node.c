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
 * Generate node address
 */
dap_chain_node_addr_t* dap_chain_node_gen_addr(dap_chain_net_id_t a_net_id)
{
    dap_chain_node_addr_t *l_addr = DAP_NEW_Z(dap_chain_node_addr_t);
    dap_chain_hash_fast_t l_hash;
    dap_hash_fast(&a_net_id, sizeof(dap_chain_net_id_t), &l_hash);
    // first 4 bytes is last 4 bytes of shard id hash
    memcpy(l_addr->raw, l_hash.raw + sizeof(l_hash.raw) - sizeof(uint64_t) / 2, sizeof(uint64_t) / 2);
    // last 4 bytes is random
    randombytes(l_addr->raw + sizeof(uint64_t) / 2, sizeof(uint64_t) / 2);
    // for LITTLE_ENDIAN (Intel), do nothing, otherwise swap bytes
    l_addr->uint64 = le64toh(l_addr->uint64); // l_addr->raw the same l_addr->uint64
    return l_addr;
}

/**
 * Check the validity of the node address by cell id
 */
bool dap_chain_node_check_addr(dap_chain_net_t *a_net, dap_chain_node_addr_t *a_addr)
{
    if (!a_addr || !a_net)
        return false;
    dap_chain_hash_fast_t l_hash;
    dap_hash_fast(&a_net->pub.id, sizeof(dap_chain_net_id_t), &l_hash);
    // first 4 bytes is last 4 bytes of shard id hash
    return !memcmp(a_addr->raw, l_hash.raw + sizeof(l_hash.raw) - sizeof(uint64_t) / 2, sizeof(uint64_t) / 2);
}

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
                            log_it(L_WARNING, "Can't get fee value from tx");
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

/**
 * @brief dap_chain_node_mempool_deinit
 */
void dap_chain_node_mempool_autoproc_deinit()
{
}


/**
 * @brief Sets a current node adress.
 * @param a_address a current node adress
 * @param a_net_name a net name string
 * @return True if success, otherwise false
 */
static bool dap_db_set_cur_node_addr_common(uint64_t a_address, char *a_net_name, time_t a_expire_time)
{
char	l_key [DAP_GLOBAL_DB_KEY_MAX];
bool	l_ret;

    if(!a_net_name)
        return false;

    snprintf(l_key, sizeof(l_key) - 1, "cur_node_addr_%s", a_net_name);

    if ( (l_ret = dap_global_db_set(DAP_GLOBAL_DB_LOCAL_GENERAL, l_key, &a_address, sizeof(a_address),
                                    true, NULL, NULL)) == 0 ) {
        snprintf(l_key, sizeof(l_key) - 1, "cur_node_addr_%s_time", a_net_name);
        l_ret = dap_global_db_set(DAP_GLOBAL_DB_LOCAL_GENERAL, l_key, &a_expire_time, sizeof(time_t),
                                   true, NULL, NULL) == DAP_GLOBAL_DB_RC_SUCCESS;
    }

    return l_ret;
}

/**
 * @brief Sets an adress of a current node and no expire time.
 *
 * @param a_address an adress of a current node
 * @param a_net_name a net name string
 * @return Returns true if siccessful, otherwise false
 */
bool dap_db_set_cur_node_addr(uint64_t a_address, char *a_net_name )
{
    return dap_db_set_cur_node_addr_common(a_address,a_net_name,0);
}

/**
 * @brief Sets an address of a current node and expire time.
 *
 * @param a_address an address of a current node
 * @param a_net_name a net name string
 * @return Returns true if successful, otherwise false
 */
bool dap_db_set_cur_node_addr_exp(uint64_t a_address, char *a_net_name )
{
    return dap_db_set_cur_node_addr_common(a_address,a_net_name, time(NULL));
}

/**
 * @brief Gets an adress of current node by a net name.
 *
 * @param a_net_name a net name string
 * @return Returns an adress if successful, otherwise 0.
 */
uint64_t dap_chain_net_get_cur_node_addr_gdb_sync(char *a_net_name)
{
char	l_key[DAP_GLOBAL_DB_KEY_MAX], l_key_time[DAP_GLOBAL_DB_KEY_MAX];
uint8_t *l_node_addr_data, *l_node_time_data;
size_t l_node_addr_len = 0, l_node_time_len = 0;
uint64_t l_node_addr_ret = 0;
time_t l_node_time = 0;

    if(!a_net_name)
        return 0;

    snprintf(l_key, sizeof(l_key) - 1, "cur_node_addr_%s", a_net_name);
    snprintf(l_key_time, sizeof(l_key_time) - 1, "cur_node_addr_%s_time", a_net_name);

    l_node_addr_data = dap_global_db_get_sync(DAP_GLOBAL_DB_LOCAL_GENERAL, l_key, &l_node_addr_len, NULL, NULL);
    l_node_time_data = dap_global_db_get_sync(DAP_GLOBAL_DB_LOCAL_GENERAL, l_key_time, &l_node_time_len, NULL, NULL);

    if(l_node_addr_data && (l_node_addr_len == sizeof(uint64_t)) )
        l_node_addr_ret = *( (uint64_t *) l_node_addr_data );

    if(l_node_time_data && (l_node_time_len == sizeof(time_t)) )
        l_node_time = *( (time_t *) l_node_time_data );

    DAP_DELETE(l_node_addr_data);
    DAP_DELETE(l_node_time_data);

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
        l_node_addr_ret = 0;
    }

    return l_node_addr_ret;
}
