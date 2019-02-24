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
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_cache.h"

typedef struct list_linked_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    UT_hash_handle hh;
} list_cached_item_t;

// List of UTXO - unspent transactions cache
static list_cached_item_t *s_datum_list = NULL;

// for separate access to connect_list
static pthread_mutex_t s_hash_list_mutex = PTHREAD_MUTEX_INITIALIZER;


int dap_chain_node_datum_tx_cache_init(dap_enc_key_t *a_key, const char *a_token_name, dap_chain_addr_t *a_addr, uint64_t a_value)
{
    // create first transaction
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    dap_chain_hash_fast_t l_tx_prev_hash = {0};

    // create items
    dap_chain_tx_token_t *l_token = dap_chain_datum_item_token_create(a_token_name);
    dap_chain_tx_out_t *l_in = dap_chain_datum_item_in_create(&l_tx_prev_hash, 0);
    dap_chain_tx_out_t *l_out = dap_chain_datum_item_out_create(a_addr, a_value);

    // pack items to transaction
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_token);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_out);
    dap_chain_datum_tx_add_sign(&l_tx, a_key);
    DAP_DELETE(l_token);
    DAP_DELETE(l_in);
    DAP_DELETE(l_out);

    // put transaction to cache
    dap_chain_hash_fast_t *l_tx_hash = dap_chain_node_datum_tx_calc_hash(l_tx);
    dap_chain_node_datum_tx_cache_add(l_tx_hash, l_tx);
    DAP_DELETE(l_tx_hash);
    DAP_DELETE(l_tx);

    return 0;
}

dap_chain_hash_fast_t* dap_chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *a_tx)
{
    dap_chain_hash_fast_t *tx_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
    dap_hash(a_tx, dap_chain_datum_tx_get_size(a_tx), tx_hash->raw, sizeof(tx_hash->raw), DAP_HASH_TYPE_KECCAK);

    return tx_hash;
}

/**
 * Add new transaction to the cache list
 *
 * return 0 OK, -1 error, -2 already present
 */
int dap_chain_node_datum_tx_cache_add(dap_chain_hash_fast_t *a_tx_hash, dap_chain_datum_tx_t *a_tx)
{
    int ret = 0;
    if(!a_tx_hash || !a_tx)
        return -1;
    list_cached_item_t *l_item_tmp = NULL;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_FIND(hh, s_datum_list, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash already in the hash?
    if(l_item_tmp == NULL) {
        l_item_tmp = DAP_NEW(list_cached_item_t);
        memcpy(&l_item_tmp->tx_hash_fast, a_tx_hash, sizeof(dap_chain_hash_fast_t));
        l_item_tmp->tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, dap_chain_datum_tx_get_size(a_tx));
        memcpy(l_item_tmp->tx, a_tx, dap_chain_datum_tx_get_size(a_tx));
        HASH_ADD(hh, s_datum_list, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash_fast: name of key field
        ret = 0;
    }
    // transaction already present
    else
        ret = -2;
    pthread_mutex_unlock(&s_hash_list_mutex);
    return ret;
}

/**
 * Delete transaction from the cache
 *
 * return 0 OK, -1 error, -2 tx_hash not found
 */
int dap_chain_node_datum_tx_cache_del(dap_chain_hash_fast_t *a_tx_hash)
{
    int l_ret = -1;
    if(!a_tx_hash)
        return -1;
    list_cached_item_t *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_FIND(hh, s_datum_list, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp);
    if(l_item_tmp != NULL) {
        HASH_DEL(s_datum_list, l_item_tmp);
        l_ret = 0;
    }
    else
        // hash not found in the cache
        l_ret = -2;
    pthread_mutex_unlock(&s_hash_list_mutex);
    if(!l_ret) {
        // delete transaction
        DAP_DELETE(l_item_tmp->tx);
        // del struct for hash
        DAP_DELETE(l_item_tmp);
    }
    return l_ret;
}

/**
 * Delete all transactions from the cache
 */
void dap_chain_node_datum_tx_cache_del_all(void)
{
    int l_ret = -1;
    list_cached_item_t *l_iter_current, *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_ITER(hh, s_datum_list , l_iter_current, l_item_tmp)
    {
        // delete transaction
        DAP_DELETE(l_iter_current->tx);
        // del struct for hash
        HASH_DEL(s_datum_list, l_iter_current);
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
}

/**
 * Get transaction by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find(dap_chain_hash_fast_t *a_tx_hash)
{
    int ret = 0;
    if(!a_tx_hash)
        return NULL;
    dap_chain_datum_tx_t *l_tx_ret = NULL;
    list_cached_item_t *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_FIND(hh, s_datum_list, a_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash already in the hash?
    if(l_item_tmp != NULL) {
        l_tx_ret = l_item_tmp->tx;
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    return l_tx_ret;
}

