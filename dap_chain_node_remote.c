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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "uthash.h"
#include "dap_chain_node_remote.h"

typedef struct list_linked_item {
    dap_chain_node_addr_t address;
    chain_node_client_t *client;
    UT_hash_handle hh;
} list_linked_item_t;

// List of connections
static list_linked_item_t *conn_list = NULL;

// for separate access to connect_list
static pthread_mutex_t connect_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Add new established connection to the list
 *
 * return 0 OK, -1 error, -2 already present
 */
int chain_node_client_list_add(dap_chain_node_addr_t *address, chain_node_client_t *client)
{
    int ret = 0;
    if(!address || !client)
        return -1;
    list_linked_item_t *item_tmp = NULL;
    pthread_mutex_lock(&connect_list_mutex);
    HASH_FIND(hh, conn_list, address, sizeof(dap_chain_node_addr_t), item_tmp); // address already in the hash?
    if(item_tmp == NULL) {
        item_tmp = DAP_NEW(list_linked_item_t);
        item_tmp->address.uint64 = address->uint64;
        item_tmp->client = client;
        HASH_ADD(hh, conn_list, address, sizeof(dap_chain_node_addr_t), item_tmp); // address: name of key field
        ret = 0;
    }
    // connection already present
    else
        ret = -2;
    //connect_list = g_list_append(connect_list, client);
    pthread_mutex_unlock(&connect_list_mutex);
    return ret;
}

/**
 * Delete established connection from the list
 *
 * return 0 OK, -1 error, -2 address not found
 */
int chain_node_client_list_del(dap_chain_node_addr_t *address)
{
    int ret = -1;
    if(!address)
        return -1;
    list_linked_item_t *item_tmp;
    pthread_mutex_lock(&connect_list_mutex);
    HASH_FIND(hh, conn_list, address, sizeof(dap_chain_node_addr_t), item_tmp);
    if(item_tmp != NULL) {
        HASH_DEL(conn_list, item_tmp);
        ret = 0;
    }
    else
        // address not found in the hash
        ret = -2;
    pthread_mutex_unlock(&connect_list_mutex);
    if(!ret) {
        // close connection
        chain_node_client_close(item_tmp->client);
        // del struct for hash
        DAP_DELETE(item_tmp);
    }
    return ret;
}

/**
 * Delete all established connection from the list
 */
void chain_node_client_list_del_all(void)
{
    int ret = -1;
    list_linked_item_t *iter_current, *item_tmp;
    pthread_mutex_lock(&connect_list_mutex);
    HASH_ITER(hh, conn_list , iter_current, item_tmp) {
        // close connection
        chain_node_client_close(iter_current->client);
        // del struct for hash
        HASH_DEL(conn_list, iter_current);
    }
    pthread_mutex_unlock(&connect_list_mutex);
}

/**
 * Get present established connection by address
 *
 * return client, or NULL if the position is off the end of the list
 */
const chain_node_client_t* chain_node_client_find(dap_chain_node_addr_t *address)
{
    int ret = 0;
    if(!address)
        return NULL;
    chain_node_client_t *client_ret = NULL;
    list_linked_item_t *item_tmp;
    pthread_mutex_lock(&connect_list_mutex);
    HASH_FIND(hh, conn_list, address, sizeof(dap_chain_node_addr_t), item_tmp); // address already in the hash?
    if(item_tmp != NULL) {
        client_ret = item_tmp->client;
    }
    pthread_mutex_unlock(&connect_list_mutex);
    return client_ret;
}

