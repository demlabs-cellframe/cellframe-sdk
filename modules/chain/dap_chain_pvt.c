/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net    https:/gitlab.com/demlabs
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

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
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dap_chain_pvt.h"


#define LOG_TAG "dap_chain_pvt"


void dap_chain_add_mempool_notify_callback(dap_chain_t *a_chain, dap_store_obj_callback_notify_t a_callback, void *a_cb_arg)
{
    dap_chain_gdb_notifier_t *l_notifier = DAP_NEW(dap_chain_gdb_notifier_t);
    l_notifier->callback = a_callback;
    l_notifier->cb_arg = a_cb_arg;
    DAP_CHAIN_PVT(a_chain)->mempool_notifires = dap_list_append(DAP_CHAIN_PVT(a_chain)->mempool_notifires, l_notifier);
}

/**
 * @brief Sets the last hash of a remote node.
 *
 * @param a_node_addr a node adress
 * @param a_chain a pointer to the chain stucture
 * @param a_hash a
 * @return true
 * @return false
 */
bool dap_chain_db_set_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_hash)
{
    char l_key[DAP_GLOBAL_DB_KEY_MAX];

    snprintf(l_key, sizeof(l_key) - 1, "%"DAP_UINT64_FORMAT_U"%s%s", a_node_addr, a_chain->net_name, a_chain->name);
    return dap_global_db_set(GROUP_LOCAL_NODE_LAST_ID, l_key, a_hash, sizeof(dap_chain_hash_fast_t), false, NULL, NULL ) == 0;
}

/**
 * @brief Gets the last hash of a remote node.
 *
 * @param a_node_addr a node adress
 * @param a_chain a pointer to a chain structure
 * @return Returns a hash if successful.
 */
dap_chain_hash_fast_t *dap_chain_db_get_last_hash_remote(uint64_t a_node_addr, dap_chain_t *a_chain)
{
    char l_key[DAP_GLOBAL_DB_KEY_MAX];

    snprintf(l_key, sizeof(l_key) - 1, "%"DAP_UINT64_FORMAT_U"%s%s", a_node_addr, a_chain->net_name, a_chain->name);
    return (dap_chain_hash_fast_t *)dap_global_db_get_sync(GROUP_LOCAL_NODE_LAST_ID, l_key, NULL, NULL, NULL);
}
