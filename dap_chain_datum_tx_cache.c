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
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_cache.h"

#define LOG_TAG "dap_chain_datum_tx_cache"

#define MAX_OUT_ITEMS   10

// sample https://github.com/troydhanson/uthash/blob/master/tests/example.c
typedef struct list_linked_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    int n_outs;
    int n_outs_used;
    // TODO dynamically allocates the memory in order not to limit the number of outputs in transaction
    dap_chain_hash_fast_t tx_hash_spent_fast[MAX_OUT_ITEMS]; // spent outs list
    UT_hash_handle hh;
} list_cached_item_t;

// List of UTXO - unspent transactions cache
static list_cached_item_t *s_datum_list = NULL;

// for separate access to connect_list
static pthread_mutex_t s_hash_list_mutex = PTHREAD_MUTEX_INITIALIZER;

int dap_chain_node_datum_tx_cache_init(dap_enc_key_t *a_key, const char *a_token_name, dap_chain_addr_t *a_addr,
        uint64_t a_value)
{
    // create first transaction
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    dap_chain_hash_fast_t l_tx_prev_hash = { 0 };

    // create items
    dap_chain_tx_token_t *l_token = dap_chain_datum_tx_item_token_create(a_token_name);
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, 0);
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(a_addr, a_value);

    // pack items to transaction
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_token);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key);
    DAP_DELETE(l_token);
    DAP_DELETE(l_in);
    DAP_DELETE(l_out);

    // put transaction to cache
    dap_chain_node_datum_tx_cache_add(l_tx);
    DAP_DELETE(l_tx);

    return 1;
}

dap_chain_hash_fast_t* dap_chain_node_datum_tx_calc_hash(dap_chain_datum_tx_t *a_tx)
{
    dap_chain_hash_fast_t *tx_hash = DAP_NEW_Z(dap_chain_hash_fast_t);
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), tx_hash);
    return tx_hash;
}

/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
static const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find_inside(dap_chain_hash_fast_t *a_tx_hash,
        list_cached_item_t **a_item_out)
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
        if(a_item_out)
            *a_item_out = l_item_tmp;
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    return l_tx_ret;
}

const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find(dap_chain_hash_fast_t *a_tx_hash)
{
    return dap_chain_node_datum_tx_cache_find_inside(a_tx_hash, NULL);
}

/**
 * Checking a new transaction before adding to the cache
 *
 * return 1 OK, -1 error
 */
static int dap_chain_node_datum_tx_cache_check(dap_chain_datum_tx_t *a_tx)
{
    /*
     Steps of checking for current transaction tx2 and every previous transaction tx1:
     1. valid(tx2.dap_chain_datum_tx_sig.pkey )
     &&
     2. valid (tx1.dap_chain_datum_tx_sig.pkey)
     &&
     3. hash(tx1) == tx2.dap_chain_datump_tx_in.tx_prev_hash
     &&
     4. tx1.dap_chain_datum_tx_out.addr.data.key == tx2.dap_chain_datum_tx_sig.pkey
     &&
     5. sum(  find (tx2.input.tx_prev_hash).output[tx2.input_tx_prev_idx].value )  ==  sum (tx2.outputs.value)
     */

    if(!a_tx)
        return -1;

    typedef struct prev_item_t {
        dap_chain_hash_fast_t tx_prev_hash_fast;
        dap_chain_datum_tx_t *tx_prev;
        dap_chain_tx_in_t *tx_cur_in;
        dap_chain_tx_out_t *tx_prev_out;
        list_cached_item_t *item_out;
    } bound_items_t;
    dap_list_t *l_list_bound_items = NULL;

    bool is_first_transaction = false;
    // sum of values in 'out' items from the previous transactions
    uint64_t l_values_from_prev_tx = 0;
    // 1. Verify signature in current transaction
    if(dap_chain_datum_tx_verify_sign(a_tx) != 1)
        return -1;

    // calculate hash for current transactions
    dap_chain_hash_fast_t l_tx_hash;
    dap_hash_fast(a_tx, dap_chain_datum_tx_get_size(a_tx), &l_tx_hash);

    // check all previous transactions
    {
        bool l_is_err = false;
        int l_prev_tx_count = 0;
        // find all 'in' items in current transaction
        dap_list_t *l_list_in = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_IN,
                &l_prev_tx_count);
        // find all previous transactions
        dap_list_t *l_list_tmp = l_list_in;
        int l_list_tmp_num = 0;
        while(l_list_tmp) {
            bound_items_t *bound_item = DAP_NEW_Z(bound_items_t);
            l_list_tmp_num++;
            dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t*) l_list_tmp->data;
            // one of the previous transaction
            dap_chain_hash_fast_t tx_prev_hash = l_tx_in->header.tx_prev_hash;
            bound_item->tx_cur_in = l_tx_in;
            memcpy(&bound_item->tx_prev_hash_fast, &tx_prev_hash, sizeof(dap_chain_hash_fast_t));

            bool l_is_blank = dap_hash_fast_is_blank(&tx_prev_hash);
            if(l_is_blank || is_first_transaction) {
                // if at least one blank hash is present, then all the hashes should be blank
                if((!is_first_transaction && l_list_tmp_num > 1) || !l_is_blank) {
                    l_is_err = true;
                    DAP_DELETE(bound_item);
                    break;
                }
                is_first_transaction = true;
            }
            // Get previous transaction in the cache by hash
            list_cached_item_t *l_item_out;
            dap_chain_datum_tx_t *l_tx_prev =
                    (dap_chain_datum_tx_t*) dap_chain_node_datum_tx_cache_find_inside(&tx_prev_hash, &l_item_out); // dap_chain_datum_tx_t *l_tx_prev = (dap_chain_datum_tx_t*) dap_chain_node_datum_tx_cache_find(&tx_prev_hash);
            bound_item->item_out = l_item_out;
            if(!l_tx_prev) {
                DAP_DELETE(bound_item);
                // go to next previous transaction
                l_list_tmp = dap_list_next(l_list_tmp);
                continue;
            }
            bound_item->tx_prev = l_tx_prev;

            // 2. Verify signature in previous transaction
            int l_res_sign = dap_chain_datum_tx_verify_sign(l_tx_prev);

            // calculate hash of previous transaction anew
            dap_chain_hash_fast_t *l_hash_prev = dap_chain_node_datum_tx_calc_hash(l_tx_prev);
            // 3. Compare hash in previous transaction with hash inside 'in' item
            int l_res_hash = dap_hash_fast_compare(l_hash_prev, &tx_prev_hash);

            if(l_res_sign != 1 || l_res_hash != 1) {
                l_is_err = true;
                DAP_DELETE(bound_item);
                break;
            }
            DAP_DELETE(l_hash_prev);

            // Get list of all 'out' items from previous transaction
            dap_list_t *l_list_prev_out = dap_chain_datum_tx_items_get(l_tx_prev, TX_ITEM_TYPE_OUT, NULL);
            // Get one 'out' item in previous transaction bound with current 'in' item
            dap_chain_tx_out_t *l_tx_prev_out = dap_list_nth_data(l_list_prev_out, l_tx_in->header.tx_out_prev_idx);
            if(!l_tx_prev_out) {
                l_is_err = true;
                DAP_DELETE(bound_item);
                break;
            }
            dap_list_free(l_list_prev_out);
            bound_item->tx_prev_out = l_tx_prev_out;

            // calculate hash of public key in current transaction
            dap_chain_hash_fast_t l_hash_pkey;
            {
                // Get sign item
                const dap_chain_tx_sig_t *l_tx_sig = (const dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(a_tx, NULL,
                        TX_ITEM_TYPE_SIG, NULL);
                // Get sign from sign item
                dap_chain_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*) l_tx_sig);
                // Get public key from sign
                size_t l_pkey_ser_size = 0;
                uint8_t *l_pkey_ser = dap_chain_sign_get_pkey(l_sign, &l_pkey_ser_size);
                // calculate hash from public key
                dap_hash_fast(l_pkey_ser, l_pkey_ser_size, &l_hash_pkey);
            }
            // hash of public key in 'out' item of previous transaction
            uint8_t *l_prev_out_addr_key = l_tx_prev_out->addr.data.key;

            // 4. compare public key hashes in the signature of the current transaction and in the 'out' item of the previous transaction
            if(memcmp(&l_hash_pkey, l_prev_out_addr_key, sizeof(dap_chain_hash_fast_t))) {
                l_is_err = true;
                DAP_DELETE(bound_item);
                break;
            }

            // calculate sum of values from previous transactions
            l_values_from_prev_tx += l_tx_prev_out->header.value;

            l_list_bound_items = dap_list_append(l_list_bound_items, bound_item);

            // go to next previous transaction
            l_list_tmp = dap_list_next(l_list_tmp);
        }
        dap_list_free(l_list_in);

        if(l_is_err) {
            dap_list_free_full(l_list_bound_items, free);
            return -1;
        }
    }

    // Additional check whether the transaction is first
    if(is_first_transaction)
    {
        // Get sign item
        if(!dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_TOKEN, NULL)) {
            dap_list_free_full(l_list_bound_items, free);
            return -1;
        }
    }

    // Calculate the sum of values in 'out' items from the current transaction
    uint64_t l_values_from_cur_tx = 0;
    if(!is_first_transaction)
    {
        // find 'out' items
        dap_list_t *l_list_out = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_OUT, NULL);
        dap_list_t *l_list_out2 = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) a_tx, TX_ITEM_TYPE_OUT_COND,
        NULL);
        l_list_out = dap_list_concat(l_list_out, l_list_out2); // add l_list_out2 onto the end of l_list_out
        bool l_is_err = false;
        // find all previous transactions
        dap_list_t *l_list_tmp = l_list_out;
        while(l_list_tmp) {
            dap_chain_tx_out_t *l_tx_out = (dap_chain_tx_out_t*) l_list_tmp->data;
            l_values_from_cur_tx += l_tx_out->header.value;
            l_list_tmp = dap_list_next(l_list_tmp);
        }
        dap_list_free(l_list_out);
    }

    // 5. Compare sum of values in 'out' items in the current transaction and in the previous transactions
    if(l_values_from_cur_tx != l_values_from_prev_tx) {
        dap_list_free_full(l_list_bound_items, free);
        return -1;
    }

    // Mark 'out' items in cache if they were used & delete previous transactions from cache if it need
    {
        // find all bound pairs 'in' and 'out'
        dap_list_t *l_list_tmp = l_list_bound_items;
        int l_list_tmp_num = 0;
        while(l_list_tmp) {
            bound_items_t *bound_item = l_list_tmp->data;
            dap_chain_tx_in_t *l_tx_in = bound_item->tx_cur_in;
            list_cached_item_t *l_prev_item_out = bound_item->item_out;

            /// Mark 'out' item in cache because it used
            dap_chain_hash_fast_t *l_tx_prev_hash =
                    &(l_prev_item_out->tx_hash_spent_fast[l_tx_in->header.tx_out_prev_idx]);
            memcpy(l_tx_prev_hash, &l_tx_hash, sizeof(dap_chain_hash_fast_t));
            // add a used output
            l_prev_item_out->n_outs_used++;

            // delete previous transactions from cache because all out is used
            if(l_prev_item_out->n_outs_used == l_prev_item_out->n_outs) {
                dap_chain_hash_fast_t tx_prev_hash = bound_item->tx_prev_hash_fast;
                int res = dap_chain_node_datum_tx_cache_del(&tx_prev_hash);
                if(res == -2) {
                    log_it(L_ERROR, "Can't delete previous transactions because hash=0x%x not found", tx_prev_hash);
                    assert(0);
                }
                else if(res != 1) {
                    log_it(L_ERROR, "Can't delete previous transactions with hash=0x%x", tx_prev_hash);
                    assert(0);
                }
            }
            // go to next previous transaction
            l_list_tmp = dap_list_next(l_list_tmp);
        }
    }

    dap_list_free_full(l_list_bound_items, free);
    return 1;
}

/**
 * Add new transaction to the cache list
 *
 * return 1 OK, -1 error
 */
int dap_chain_node_datum_tx_cache_add(dap_chain_datum_tx_t *a_tx)
{
    int ret = 1;
    if(dap_chain_node_datum_tx_cache_check(a_tx) != 1)
        return -1;
    dap_chain_hash_fast_t *l_tx_hash = dap_chain_node_datum_tx_calc_hash(a_tx);
    list_cached_item_t *l_item_tmp = NULL;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_FIND(hh, s_datum_list, l_tx_hash, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash already in the hash?
    // transaction already present in the cache list
    if(l_item_tmp) {
        // delete transaction from the cache list
        ret = dap_chain_node_datum_tx_cache_del(l_tx_hash);
        // there should be no duplication
        log_it(L_WARNING, "Transaction (hash=0x%x) deleted from cache because there is an attempt to add it to cache",
                l_tx_hash);
        assert(0);
    }
    // add transaction to the cache list
    if(ret == 1)
            {
        l_item_tmp = DAP_NEW_Z(list_cached_item_t);
        memcpy(&l_item_tmp->tx_hash_fast, l_tx_hash, sizeof(dap_chain_hash_fast_t));
        l_item_tmp->tx = DAP_NEW_SIZE(dap_chain_datum_tx_t, dap_chain_datum_tx_get_size(a_tx));
        //calculate l_item_tmp->n_outs;
        {
            l_item_tmp->n_outs = 0;
            dap_list_t *l_tist_tmp = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT, &l_item_tmp->n_outs);
            dap_list_free(l_tist_tmp);
        }
        memcpy(l_item_tmp->tx, a_tx, dap_chain_datum_tx_get_size(a_tx));
        HASH_ADD(hh, s_datum_list, tx_hash_fast, sizeof(dap_chain_hash_fast_t), l_item_tmp); // tx_hash_fast: name of key field
        ret = 1;
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    DAP_DELETE(l_tx_hash);
    return ret;
}

/**
 * Delete transaction from the cache
 *
 * return 1 OK, -1 error, -2 tx_hash not found
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
        l_ret = 1;
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
 * Return number transactions from the cache
 */
int dap_chain_node_datum_tx_cache_count(void)
{
    int l_ret = 0;
    list_cached_item_t *l_iter_current, *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_ITER(hh, s_datum_list , l_iter_current, l_item_tmp)
    {
        l_ret++;
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    return l_ret;
}

/**
 * Check whether used 'out' items (local function)
 */
static bool dap_chain_node_datum_tx_cache_is_used_out_item_inside(list_cached_item_t *a_item, int a_idx_out)
{
    bool l_used_out = false;
    if(!a_item) {
        log_it(L_WARNING, "list_cached_item is NULL");
        return false;
    }
    if(a_idx_out >= MAX_OUT_ITEMS) {
        log_it(L_ERROR, "Too big index(%d) of 'out'items (max=%d)", a_idx_out, MAX_OUT_ITEMS);
    }
    assert(a_idx_out < MAX_OUT_ITEMS);
    // if there are used 'out' items
    if(a_item->n_outs_used > 0) {
        if(!dap_hash_fast_is_blank(&(a_item->tx_hash_spent_fast[a_idx_out])))
            l_used_out = true;
    }
    return l_used_out;
}

/**
 * Check whether used 'out' items
 */
bool dap_chain_node_datum_tx_cache_is_used_out_item(dap_chain_hash_fast_t *a_tx_hash, int a_idx_out)
{
    list_cached_item_t *l_item_out = NULL;
    dap_chain_datum_tx_t *l_tx =
            (dap_chain_datum_tx_t*) dap_chain_node_datum_tx_cache_find_inside(a_tx_hash, &l_item_out);
    return dap_chain_node_datum_tx_cache_is_used_out_item_inside(l_item_out, a_idx_out);
}

/**
 * Calculate balance of addr
 *
 */
uint64_t dap_chain_datum_tx_cache_calc_balance(dap_chain_addr_t *a_addr)
{
    uint64_t balance = 0;
    if(!a_addr || !dap_chain_addr_check_sum(a_addr))
        return 0;
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    list_cached_item_t *l_iter_current, *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_ITER(hh, s_datum_list , l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        int l_n_outs_used = l_iter_current->n_outs_used; // number of used 'out' items

        // Get 'out' items from transaction
        int l_out_item_count = 0;
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx_tmp, TX_ITEM_TYPE_OUT, &l_out_item_count);
        if(l_out_item_count >= MAX_OUT_ITEMS) {
            log_it(L_ERROR, "Too many 'out' items=%d in transaction (max=%d)", l_out_item_count, MAX_OUT_ITEMS);
            assert(l_out_item_count < MAX_OUT_ITEMS);
        }
        dap_list_t *l_list_tmp = l_list_out_items;
        int l_out_idx_tmp = 0;
        while(l_list_tmp) {
            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;

            // if transaction has the out item with requested addr
            if(l_tx_out && &l_tx_out->addr && !memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                // if 'out' item not used & transaction is valid
                if(!dap_chain_node_datum_tx_cache_is_used_out_item_inside(l_iter_current, l_out_idx_tmp) &&
                        dap_chain_datum_tx_verify_sign(l_tx_tmp))
                    balance += l_tx_out->header.value;
            }
            // go to the next 'out' item in l_tx_tmp transaction
            l_out_idx_tmp++;

            l_list_tmp = dap_list_next(l_list_tmp);
        }
        dap_list_free(l_list_tmp);
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    return balance;
}

/**
 * Get the transaction in the cache by the addr in 'out' item
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 * a_tx_first_hash [in/out] hash of the initial transaction/ found transaction, if 0 start from the beginning
 */
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find_by_addr(dap_chain_addr_t *a_addr,
        dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_addr || !a_tx_first_hash)
        return NULL;
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    int l_ret = -1;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    list_cached_item_t *l_iter_current, *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_ITER(hh, s_datum_list , l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash_tmp, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get 'out' items from transaction
        dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(l_tx_tmp, TX_ITEM_TYPE_OUT, NULL);
        dap_list_t *l_list_tmp = l_list_out_items;
        while(l_list_tmp) {
            const dap_chain_tx_out_t *l_tx_out = (const dap_chain_tx_out_t*) l_list_tmp->data;
            // if transaction has the out item with requested addr
            if(l_tx_out && &l_tx_out->addr && !memcmp(a_addr, &l_tx_out->addr, sizeof(dap_chain_addr_t))) {
                l_cur_tx = l_tx_tmp;
                memcpy(a_tx_first_hash, l_tx_hash_tmp, sizeof(dap_chain_hash_fast_t));
                break;
            }
            l_list_tmp = dap_list_next(l_list_tmp);
        }
        dap_list_free(l_list_tmp);
        // already found transaction
        if(l_cur_tx)
            break;
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    return l_cur_tx;
}

/**
 * Get the transaction in the cache by the public key that signed the transaction,
 * starting from the next hash after a_tx_first_hash
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 * a_tx_first_hash [in/out] hash of the initial transaction/ found transaction, if 0 start from the beginning
 */
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find_by_pkey(char *a_public_key, size_t a_public_key_size,
        dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_public_key || !a_tx_first_hash)
        return NULL;
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    int l_ret = -1;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    list_cached_item_t *l_iter_current, *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_ITER(hh, s_datum_list , l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash_tmp, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get sign item from transaction
        const dap_chain_tx_sig_t *l_tx_sig = (const dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get(l_tx_tmp, NULL,
                TX_ITEM_TYPE_SIG, NULL);
        // Get dap_chain_sign_t from item
        dap_chain_sign_t *l_sig = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*) l_tx_sig);
        if(l_sig) {
            // compare public key in transaction with a_public_key
            if(a_public_key_size == l_sig->header.sign_pkey_size &&
                    !memcmp(a_public_key, l_sig->pkey_n_sign, a_public_key_size)) {
                l_cur_tx = l_tx_tmp;
                memcpy(a_tx_first_hash, l_tx_hash_tmp, sizeof(dap_chain_hash_fast_t));
                break;
            }
        }
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    return l_cur_tx;
}

/**
 * Get the transaction in the cache with the out_cond item
 *
 * a_addr[in] wallet address, whose owner can use the service
 */
const dap_chain_datum_tx_t* dap_chain_node_datum_tx_cache_find_out_cond(dap_chain_addr_t *a_addr,
        dap_chain_hash_fast_t *a_tx_first_hash)
{
    if(!a_addr || !a_tx_first_hash)
        return NULL;
    dap_chain_datum_tx_t *l_cur_tx = NULL;
    int l_ret = -1;
    bool is_null_hash = dap_hash_fast_is_blank(a_tx_first_hash);
    bool is_search_enable = is_null_hash;
    list_cached_item_t *l_iter_current, *l_item_tmp;
    pthread_mutex_lock(&s_hash_list_mutex);
    HASH_ITER(hh, s_datum_list , l_iter_current, l_item_tmp)
    {
        dap_chain_datum_tx_t *l_tx_tmp = l_iter_current->tx;
        dap_chain_hash_fast_t *l_tx_hash_tmp = &l_iter_current->tx_hash_fast;
        // start searching from the next hash after a_tx_first_hash
        if(!is_search_enable) {
            if(dap_hash_fast_compare(l_tx_hash_tmp, a_tx_first_hash))
                is_search_enable = true;
            continue;
        }
        // Get sign item from transaction
        int l_tx_out_cond_size = 0;
        const dap_chain_tx_out_cond_t *l_tx_out_cond = (const dap_chain_tx_out_cond_t*) dap_chain_datum_tx_item_get(
                l_tx_tmp, NULL, TX_ITEM_TYPE_OUT_COND, &l_tx_out_cond_size);

        if(l_tx_out_cond && !memcmp(&l_tx_out_cond->addr, a_addr, sizeof(dap_chain_addr_t))) {
            l_cur_tx = l_tx_tmp;
            memcpy(a_tx_first_hash, l_tx_hash_tmp, sizeof(dap_chain_hash_fast_t));
            break;
        }
    }
    pthread_mutex_unlock(&s_hash_list_mutex);
    return l_cur_tx;
}

/**
 * Get the value from all transactions in the cache with out_cond item
 *
 * a_addr[in] wallet address, whose owner can use the service
 * a_sign [in] signature of a_addr hash for check valid key
 * a_sign_size [in] signature size
 *
 * a_public_key[in] public key that signed the transaction
 * a_public_key_size[in] public key size
 */
uint64_t dap_chain_node_datum_tx_cache_get_out_cond_value(dap_chain_addr_t *a_addr, dap_chain_tx_out_cond_t **tx_out_cond)
{
    uint64_t l_ret_value = 0;

    const dap_chain_datum_tx_t *l_tx_tmp;
    dap_chain_hash_fast_t l_tx_first_hash = { 0 }; // start hash
    //memcpy(&l_tx_first_hash, 0, sizeof(dap_chain_hash_fast_t));
    /* size_t l_pub_key_size = a_key_from->pub_key_data_size;
     uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_key_from, &l_pub_key_size);*/

    // Find all transactions
    do {
        l_tx_tmp = dap_chain_node_datum_tx_cache_find_out_cond(a_addr, &l_tx_first_hash);

        // Get out_cond item from transaction
        if(l_tx_tmp) {
            const dap_chain_tx_out_cond_t *l_tx_out_cond = (const dap_chain_tx_out_cond_t*) dap_chain_datum_tx_item_get(
                    (dap_chain_datum_tx_t*) l_tx_tmp, NULL, TX_ITEM_TYPE_OUT_COND, NULL);

            // TODO check relations a_addr with cond_data and public key

            if(l_tx_out_cond){
                l_ret_value += l_tx_out_cond->header.value;
                if(tx_out_cond)
                    *tx_out_cond = (dap_chain_tx_out_cond_t*)l_tx_out_cond;
            }
        }
    }
    while(l_tx_tmp);
    return l_ret_value;
}
