/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

#include <string.h>
#include <pthread.h>
#include <malloc.h>

#include "uthash.h"
#include "dap_hash.h"
#include "dap_chain_datum_tx_cache.h"

typedef struct list_linked_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    UT_hash_handle hh;
} list_cached_item_t;

// List of UTXO - unspent transactions cache
static list_cached_item_t *datum_list = NULL;

// for separate access to connect_list
static pthread_mutex_t hash_list_mutex = PTHREAD_MUTEX_INITIALIZER;


dap_chain_hash_fast_t* chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *tx)
{
    dap_chain_hash_fast_t *tx_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
    dap_hash(tx, dap_chain_datum_tx_get_size(tx), tx_hash->raw, sizeof(tx_hash->raw), DAP_HASH_TYPE_KECCAK);

    return tx_hash;
}

/**
 * Add new transaction to the cache list
 *
 * return 0 OK, -1 error, -2 already present
 */
int chain_node_datum_tx_list_hash_add(dap_chain_hash_fast_t *tx_hash, dap_chain_datum_tx_t *tx)
{
    int ret = 0;
    if(!tx_hash || !tx)
        return -1;
    list_cached_item_t *item_tmp = NULL;
    pthread_mutex_lock(&hash_list_mutex);
    HASH_FIND(hh, datum_list, tx_hash, sizeof(dap_chain_hash_fast_t), item_tmp); // tx_hash already in the hash?
    if(item_tmp == NULL) {
        item_tmp = DAP_NEW(list_cached_item_t);
        memcpy(&item_tmp->tx_hash_fast, tx_hash, sizeof(dap_chain_hash_fast_t));
        item_tmp->tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, dap_chain_datum_tx_get_size(tx));
        memcpy(&item_tmp->tx, tx, dap_chain_datum_tx_get_size(tx));
        HASH_ADD(hh, datum_list, tx_hash_fast, sizeof(dap_chain_hash_fast_t), item_tmp); // tx_hash_fast: name of key field
        ret = 0;
    }
    // transaction already present
    else
        ret = -2;
    pthread_mutex_unlock(&hash_list_mutex);
    return ret;
}

/**
 * Delete transaction from the cache
 *
 * return 0 OK, -1 error, -2 tx_hash not found
 */
int chain_node_datum_tx_list_hash_del(dap_chain_hash_fast_t *tx_hash)
{
    int ret = -1;
    if(!tx_hash)
        return -1;
    list_cached_item_t *item_tmp;
    pthread_mutex_lock(&hash_list_mutex);
    HASH_FIND(hh, datum_list, tx_hash, sizeof(dap_chain_hash_fast_t), item_tmp);
    if(item_tmp != NULL) {
        HASH_DEL(datum_list, item_tmp);
        ret = 0;
    }
    else
        // hash not found in the cache
        ret = -2;
    pthread_mutex_unlock(&hash_list_mutex);
    if(!ret) {
        // delete transaction
        DAP_DELETE(item_tmp->tx);
        // del struct for hash
        DAP_DELETE(item_tmp);
    }
    return ret;
}

/**
 * Delete all transactions from the cache
 */
void chain_node_datum_tx_list_hash_del_all(void)
{
    int ret = -1;
    list_cached_item_t *iter_current, *item_tmp;
    pthread_mutex_lock(&hash_list_mutex);
    HASH_ITER(hh, datum_list , iter_current, item_tmp)
    {
        // delete transaction
        DAP_DELETE(iter_current->tx);
        // del struct for hash
        HASH_DEL(datum_list, iter_current);
    }
    pthread_mutex_unlock(&hash_list_mutex);
}

/**
 * Get transaction by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
const dap_chain_datum_tx_t* chain_node_datum_tx_list_hash_find(dap_chain_hash_fast_t *tx_hash)
{
    int ret = 0;
    if(!tx_hash)
        return NULL;
    dap_chain_datum_tx_t *tx_ret = NULL;
    list_cached_item_t *item_tmp;
    pthread_mutex_lock(&hash_list_mutex);
    HASH_FIND(hh, datum_list, tx_hash, sizeof(dap_chain_hash_fast_t), item_tmp); // tx_hash already in the hash?
    if(item_tmp != NULL) {
        tx_ret = item_tmp->tx;
    }
    pthread_mutex_unlock(&hash_list_mutex);
    return tx_ret;
}

