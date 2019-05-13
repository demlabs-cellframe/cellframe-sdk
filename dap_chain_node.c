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

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "dap_hash.h"
#include "rand/dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_global_db.h"
#include "dap_chain_node.h"

#define LOG_TAG "chain_node"

/**
 * Generate node address by shard id
 */
dap_chain_node_addr_t* dap_chain_node_gen_addr(dap_chain_cell_id_t *shard_id)
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
 * Check the validity of the node address by shard id
 */
bool dap_chain_node_check_addr(dap_chain_node_addr_t *addr, dap_chain_cell_id_t *shard_id)
{
    bool ret = false;
    if(!addr || !shard_id)
        ret= false;

    return ret;
}

/**
 * Register alias in base
 */
bool dap_chain_node_alias_register(const char *alias, dap_chain_node_addr_t *addr)
{
    const char *a_key = alias;
//    char a_value[2 * sizeof(dap_chain_node_addr_t) + 1];
//    if(bin2hex(a_value, (const unsigned char *) addr, sizeof(dap_chain_node_addr_t)) == -1)
//        return false;
//    a_value[2 * sizeof(dap_chain_node_addr_t)] = '\0';
    bool res = dap_chain_global_db_gr_set(a_key, (const uint8_t*) addr, sizeof(dap_chain_node_addr_t), GROUP_ALIAS);
    return res;
}

/**
 * @brief dap_chain_node_alias_find
 * @param alias
 * @return
 */
dap_chain_node_addr_t * dap_chain_node_alias_find(const char *a_alias)
{
    size_t l_addr_size =0;
    dap_chain_node_addr_t * l_addr = (dap_chain_node_addr_t *)
            dap_chain_global_db_gr_get(a_alias, &l_addr_size, GROUP_ALIAS);
    return  l_addr;
}

/**
 * Delete alias from base
 */
bool dap_chain_node_alias_delete(const char *alias)
{
    const char *a_key = alias;
    bool res = dap_chain_global_db_gr_del(a_key, GROUP_ALIAS);
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
int dap_chain_node_info_save(dap_chain_node_info_t *node_info)
{
    if(!node_info || !node_info->hdr.address.uint64)
        return  -1;

    char *l_key = dap_chain_node_addr_to_hash_str(&node_info->hdr.address);

    if(!l_key)
        return -2;

    //char *a_value = dap_chain_node_info_serialize(node_info, NULL);
    size_t node_info_size = dap_chain_node_info_get_size(node_info);
    bool res = dap_chain_global_db_gr_set(l_key, (const uint8_t *) node_info, node_info_size, GROUP_NODE);
    DAP_DELETE(l_key);
    //DAP_DELETE(a_value);
    return res;
}

/**
 * Read node from base
 */
dap_chain_node_info_t* dap_chain_node_info_read(dap_chain_node_addr_t *address)
{
    char *l_key = dap_chain_node_addr_to_hash_str(address);
    if(!l_key) {
        log_it(L_WARNING,"Can't calculate hash of addr");
        return NULL;
    }
    size_t node_info_size = 0;
    dap_chain_node_info_t *node_info;
    // read node
    node_info = (dap_chain_node_info_t *) dap_chain_global_db_gr_get(l_key, &node_info_size, GROUP_NODE);

    if(!node_info) {
        log_it(L_ERROR, "node not found in base");
        DAP_DELETE(l_key);
        return NULL;
    }

    size_t node_info_size_must_be = dap_chain_node_info_get_size(node_info);
    if(node_info_size_must_be != node_info_size) {
        log_it(L_ERROR, "Node has bad size in base=%u (must be %u)", node_info_size, node_info_size_must_be);
        DAP_DELETE(node_info);
        DAP_DELETE(l_key);
        return NULL;
    }

//    dap_chain_node_info_t *node_info = dap_chain_node_info_deserialize(str, (str) ? strlen(str) : 0);
//    if(!node_info) {
//        set_reply_text(str_reply, "node has invalid format in base");
//    }
//    DAP_DELETE(str);
    DAP_DELETE(l_key);
    return node_info;
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

