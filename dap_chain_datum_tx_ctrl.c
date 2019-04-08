/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
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

#include <memory.h>
#include <assert.h>

#include "dap_common.h"
#include "dap_list.h"
#include "dap_chain_sign.h"
#include "dap_chain_datum_tx.h"
//#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_cache.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_ctrl.h"

#define LOG_TAG "dap_chain_datum_tx_ctrl"

typedef struct list_used_item {
    dap_chain_hash_fast_t tx_hash_fast;
    int num_idx_out;
    uint64_t value;
//dap_chain_tx_out_t *tx_out;
} list_used_item_t;

/**
 * Make transfer transaction & insert to cache
 *
 * return 1 Ok, 0 not enough funds to transfer, -1 other Error
 */
int dap_chain_datum_tx_ctrl_create_transfer(dap_enc_key_t *a_key_from,
        dap_chain_addr_t* a_addr_from, dap_chain_addr_t* a_addr_to, dap_chain_addr_t* a_addr_fee,
        uint64_t a_value, uint64_t a_value_fee)
{
    // check valid param
    if(!a_key_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            !dap_chain_addr_check_sum(a_addr_from) || !dap_chain_addr_check_sum(a_addr_to) ||
            (a_addr_fee && !dap_chain_addr_check_sum(a_addr_fee)) || !a_value)
        return -1;

    // find the transactions from which to take away coins
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    uint64_t l_value_transfer = 0; // how many coins to transfer
    {
        dap_chain_hash_fast_t l_tx_cur_hash = { 0 };
        uint64_t l_value_need = a_value + a_value_fee;
        while(l_value_transfer < l_value_need)
        {
            // Get the transaction in the cache by the addr in out item
            const dap_chain_datum_tx_t *l_tx = dap_chain_node_datum_tx_cache_find_by_addr(a_addr_from,
                    &l_tx_cur_hash);
            if(!l_tx)
                break;
            // Get all item from transaction by type
            int l_item_count = 0;
            dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get((dap_chain_datum_tx_t*) l_tx, TX_ITEM_TYPE_OUT,
                    &l_item_count);
            dap_list_t *l_list_tmp = l_list_out_items;
            int l_out_idx_tmp = 0; // current index of 'out' item
            while(l_list_tmp) {
                dap_chain_tx_out_t *out_item = l_list_tmp->data;
                // if 'out' item has addr = a_addr_from
                if(out_item && &out_item->addr && !memcmp(a_addr_from, &out_item->addr, sizeof(dap_chain_addr_t))) {

                    // Check whether used 'out' items
                    if(!dap_chain_node_datum_tx_cache_is_used_out_item(&l_tx_cur_hash, l_out_idx_tmp)) {

                        list_used_item_t *item = DAP_NEW(list_used_item_t);
                        memcpy(&item->tx_hash_fast, &l_tx_cur_hash, sizeof(dap_chain_hash_fast_t));
                        item->num_idx_out = l_out_idx_tmp;
                        item->value = out_item->header.value;
                        l_list_used_out = dap_list_append(l_list_used_out, item);
                        l_value_transfer += item->value;
                        // already accumulated the required value, finish the search for 'out' items
                        if(l_value_transfer >= l_value_need){
                            break;
                        }
                    }
                }
                // go to the next 'out' item in l_tx transaction
                l_out_idx_tmp++;
                l_list_tmp = dap_list_next(l_list_tmp);
            }
            dap_list_free(l_list_out_items);
        }

        // nothing to tranfer (not enough funds)
        if(!l_list_used_out || l_value_transfer < l_value_need) {
            dap_list_free_full(l_list_used_out, free);
            return 0;
        }
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        dap_list_t *l_list_tmp = l_list_used_out;
        uint64_t l_value_to_items = 0; // how many coins to transfer
        while(l_list_tmp) {
            list_used_item_t *item = l_list_tmp->data;
            if(dap_chain_datum_tx_add_in_item(&l_tx, &item->tx_hash_fast, item->num_idx_out) == 1) {
                l_value_to_items += item->value;
            }
            l_list_tmp = dap_list_next(l_list_tmp);
        }
        assert(l_value_to_items == l_value_transfer);
        dap_list_free_full(l_list_used_out, free);
    }
    // add 'out' items
    {
        uint64_t l_value_pack = 0; // how much coin add to 'out' items
        if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) == 1) {
            l_value_pack += a_value;
            // transaction fee
            if(a_addr_fee) {
                if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_fee, a_value_fee) == 1)
                    l_value_pack += a_value_fee;
            }
        }
        // coin back
        uint64_t l_value_back = l_value_transfer - l_value_pack;
        if(l_value_back) {
            if(dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_value_back) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return -1;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return -1;
    }

    // Add a new transaction to the cache (with checks)
    if(dap_chain_node_datum_tx_cache_add(l_tx) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return -1;
    }
    return 1;

    /*const dap_chain_datum_tx_t *l_tx_tmp;
     dap_chain_hash_fast_t l_tx_hash_tmp = { 0 }; // start hash
     size_t l_pub_key_size = a_key_from->pub_key_data_size;
     uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_key_from, &l_pub_key_size);

     do {
     l_tx_tmp = dap_chain_node_datum_tx_cache_find_by_pkey(l_pub_key, l_pub_key_size, &l_tx_hash_tmp);
     }
     while(l_tx_tmp);
     DAP_DELETE(l_pub_key);
     int a = dap_chain_addr_check_sum(a_addr_to);

     dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
     dap_chain_hash_fast_t l_tx_prev_hash = { 0 };
     uint32_t l_tx_out_prev_idx = 0;
     dap_chain_tx_in_t *l_tx_item_in = dap_chain_datum_tx_item_in_create(&l_tx_prev_hash, l_tx_out_prev_idx);
     res = dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *) l_tx_item_in);
     res = dap_chain_datum_tx_add_sign(&l_tx, l_key);
     res = dap_chain_node_datum_tx_cache_add(l_tx);
     DAP_DELETE(l_tx);*/
}
