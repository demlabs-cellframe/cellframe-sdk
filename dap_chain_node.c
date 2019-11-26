/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
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
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <wepoll.h>
#include <pthread.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "dap_hash.h"
#include "rand/dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node.h"

#define LOG_TAG "chain_node"

/**
 * Generate node address by shard id
 */
dap_chain_node_addr_t* dap_chain_node_gen_addr(dap_chain_net_t * a_net,dap_chain_cell_id_t *shard_id)
{
    if(!shard_id)
        return NULL;
    dap_chain_node_addr_t *a_addr = DAP_NEW_Z(dap_chain_node_addr_t);
    dap_chain_hash_fast_t a_hash;
    dap_hash_fast(shard_id, sizeof(dap_chain_cell_id_t), &a_hash);
    // first 4 bytes is last 4 bytes of shard id hash
    memcpy(a_addr->raw, a_hash.raw + sizeof(a_hash.raw) - sizeof(uint64_t) / 2, sizeof(uint64_t) / 2);
    // last 4 bytes is random
    randombytes(a_addr->raw + sizeof(uint64_t) / 2, sizeof(uint64_t) / 2);
    // for LITTLE_ENDIAN (Intel), do nothing, otherwise swap bytes
    a_addr->uint64 = le64toh(a_addr->uint64); // a_addr->raw the same a_addr->uint64
    return a_addr;
}

/**
 * Check the validity of the node address by cell id
 */
bool dap_chain_node_check_addr(dap_chain_net_t * a_net,dap_chain_node_addr_t *addr, dap_chain_cell_id_t *shard_id)
{
    bool ret = false;
    if(!addr || !shard_id)
        ret= false;

    return ret;
}

/**
 * Register alias in base
 */
bool dap_chain_node_alias_register(dap_chain_net_t * a_net,const char *alias, dap_chain_node_addr_t *addr)
{
    char *a_key = strdup(alias);
//    char a_value[2 * sizeof(dap_chain_node_addr_t) + 1];
//    if(bin2hex(a_value, (const unsigned char *) addr, sizeof(dap_chain_node_addr_t)) == -1)
//        return false;
//    a_value[2 * sizeof(dap_chain_node_addr_t)] = '\0';
    bool res = dap_chain_global_db_gr_set(a_key,  addr, sizeof(dap_chain_node_addr_t)
                                          , a_net->pub.gdb_nodes_aliases);
    return res;
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
    char *a_key = strdup(a_alias);
    bool res = dap_chain_global_db_gr_del(a_key, a_net->pub.gdb_nodes_aliases);
    return res;
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
int dap_chain_node_info_save(dap_chain_net_t * a_net, dap_chain_node_info_t *node_info)
{
    if(!node_info || !node_info->hdr.address.uint64){
        log_it(L_ERROR,"Can't save node info: %s", node_info? "null address":"null object" );
        return  -1;
    }
    char *l_key = dap_chain_node_addr_to_hash_str(&node_info->hdr.address);

    if(!l_key){
        log_it(L_ERROR,"Can't produce key to save node info ");
        return -2;
    }
    //char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    size_t node_info_size = dap_chain_node_info_get_size(node_info);
    bool res = dap_chain_global_db_gr_set(l_key, node_info, node_info_size, a_net->pub.gdb_nodes);
    DAP_DELETE(l_key);
    //DAP_DELETE(a_value);
    return res?0:-3;
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
        log_it(L_ERROR, "node with key %s (addr " NODE_ADDR_FP_STR ") not found in base",l_key, NODE_ADDR_FP_ARGS(l_address));
        DAP_DELETE(l_key);
        return NULL;
    }

    size_t node_info_size_must_be = dap_chain_node_info_get_size(l_node_info);
    if(node_info_size_must_be != node_info_size) {
        log_it(L_ERROR, "Node has bad size in base=%u (must be %u)", node_info_size, node_info_size_must_be);
        DAP_DELETE(l_node_info);
        DAP_DELETE(l_key);
        return NULL;
    }

//    dap_chain_node_info_t *node_info = dap_chain_node_info_deserialize(str, (str) ? strlen(str) : 0);
//    if(!node_info) {
//        set_reply_text(str_reply, "node has invalid format in base");
//    }
//    DAP_DELETE(str);
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

