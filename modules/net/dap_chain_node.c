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
#include "dap_chain_global_db.h"
#include "dap_chain_node.h"

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
    return dap_chain_global_db_gr_set( a_alias, a_addr, sizeof(dap_chain_node_addr_t), a_net->pub.gdb_nodes_aliases);
}

/**
 * @brief dap_chain_node_alias_find
 * @param alias
 * @return
 */
dap_chain_node_addr_t * dap_chain_node_alias_find(dap_chain_net_t * a_net,const char *a_alias)
{
    size_t l_addr_size =0;
    dap_chain_node_addr_t * l_addr = (dap_chain_node_addr_t *)
            dap_chain_global_db_gr_get(a_alias, &l_addr_size, a_net->pub.gdb_nodes_aliases);
    return  l_addr;
}

/**
 * Delete alias from base
 */
bool dap_chain_node_alias_delete(dap_chain_net_t * a_net,const char *a_alias)
{
    return  dap_chain_global_db_gr_del(a_alias, a_net->pub.gdb_nodes_aliases);
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
    bool res = dap_chain_global_db_gr_set(l_key, a_node_info, l_node_info_size, a_net->pub.gdb_nodes);

    DAP_DELETE(l_key);

    return res ? 0 : -3;
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
    l_node_info = (dap_chain_node_info_t *) dap_chain_global_db_gr_get(l_key, &node_info_size, a_net->pub.gdb_nodes);

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


/**
 * Serialize dap_chain_node_info_t
 * size[out] - length of output string
 * return data or NULL if error
 */
/*uint8_t* dap_chain_node_info_serialize(dap_chain_node_info_t *node_info, size_t *size)
{
    if(!node_info)
        return NULL;
    size_t node_info_size = dap_chain_node_info_get_size(node_info);
    size_t node_info_str_size = 2 * node_info_size + 1;
    uint8_t *node_info_str = DAP_NEW_Z_SIZE(uint8_t, node_info_str_size);
    if(bin2hex(node_info_str, (const unsigned char *) node_info, node_info_size) == -1) {
        DAP_DELETE(node_info_str);
        return NULL;
    }

    if(size)
        *size = node_info_str_size;
    return node_info_str;
}*/

/**
 * Deserialize dap_chain_node_info_t
 * size[in] - length of input string
 * return data or NULL if error
 */
/*dap_chain_node_info_t* dap_chain_node_info_deserialize(uint8_t *node_info_str, size_t size)
{
    if(!node_info_str || size<=0)
        return NULL;
    dap_chain_node_info_t *node_info = DAP_NEW_Z_SIZE(dap_chain_node_info_t, (size / 2 + 1));
    if(hex2bin((char*) node_info, (const unsigned char *) node_info_str, size) == -1 ||
            (size / 2) != dap_chain_node_info_get_size(node_info)) {
        log_it(L_ERROR, "node_info_deserialize - incorrect node_info size (%ld!=%ld)",
                size / 2, dap_chain_node_info_get_size(node_info));
        DAP_DELETE(node_info);
        return NULL;
    }
    return node_info;
}*/

int dap_chain_node_mempool_process(dap_chain_t *a_chain, dap_chain_datum_t *a_datum)
{
    bool l_need_process = false;
    for (uint16_t j = 0; j < a_chain->autoproc_datum_types_count; j++) {
        if (a_datum->header.type_id == a_chain->autoproc_datum_types[j]) {
            l_need_process = true;
            break;
        }
    }
    if (!l_need_process)
        return -1;
    // Auth signs for emissions already verified by this callback
    return (int)a_chain->callback_add_datums(a_chain, &a_datum, 1);
}

static void s_chain_node_mempool_autoproc_notify(void *a_arg, const char a_op_code, const char *a_group,
                                             const char *a_key, const void *a_value, const size_t a_value_len)
{
    UNUSED(a_value_len);
    if (!a_arg || !a_value || a_op_code != 'a') {
        return;
    }
    dap_chain_t *l_chain =(dap_chain_t *)a_arg;
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_chain->net_id);
    if (!l_net->pub.mempool_autoproc)
        return;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)a_value;
    if (dap_chain_node_mempool_process(l_chain, l_datum) >= 0) {
        dap_chain_global_db_gr_del(a_key, a_group);
    }
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
        dap_chain_t *l_chain;
        DL_FOREACH(l_net_list[i]->pub.chains, l_chain) {
            if (!l_chain) {
                continue;
            }
            char *l_gdb_group_mempool = NULL;
            l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
            size_t l_objs_size = 0;
            dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_gdb_group_mempool, &l_objs_size);
            if (l_objs_size) {
                for (size_t i = 0; i < l_objs_size; i++) {
                    if (!l_objs[i].value_len)
                        continue;
                    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)l_objs[i].value;
                    if (dap_chain_node_mempool_process(l_chain, l_datum) >= 0) {
                        // Delete processed objects
                        dap_chain_global_db_gr_del( l_objs[i].key, l_gdb_group_mempool);
                    }
                }
                dap_chain_global_db_objs_delete(l_objs, l_objs_size);
            }
            DAP_DELETE(l_gdb_group_mempool);
            dap_chain_add_mempool_notify_callback(l_chain, s_chain_node_mempool_autoproc_notify, l_chain);
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
