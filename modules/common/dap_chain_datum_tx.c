/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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
#include "dap_sign.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_voting.h"

#define LOG_TAG "dap_chain_datum_tx"

/**
 * Create empty transaction
 *
 * return transaction, 0 Error
 */
dap_chain_datum_tx_t* dap_chain_datum_tx_create(void)
{
    dap_chain_datum_tx_t *tx = DAP_NEW_Z(dap_chain_datum_tx_t);
    if (!tx) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return 0;
    }
    tx->header.ts_created = time(NULL);
    return tx;
}

/**
 * Delete transaction
 */
void dap_chain_datum_tx_delete(dap_chain_datum_tx_t *a_tx)
{
    if(a_tx)
        DAP_DELETE(a_tx);
}

/**
 * Get size of transaction
 *
 * return size, 0 Error
 */
size_t dap_chain_datum_tx_get_size(dap_chain_datum_tx_t *a_tx)
{
    if(!a_tx)
        return 0;
    return (sizeof(dap_chain_datum_tx_t) + a_tx->header.tx_items_size);
}

/**
 * Insert item to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_item(dap_chain_datum_tx_t **a_tx, const void *a_item)
{
    size_t size = dap_chain_datum_item_tx_get_size(a_item);
    if(!size || !a_tx || !*a_tx)
        return -1;
    dap_chain_datum_tx_t *tx_cur = *a_tx;
    size_t l_new_size = dap_chain_datum_tx_get_size(tx_cur) + size;
    tx_cur = (dap_chain_datum_tx_t*)DAP_REALLOC(tx_cur, l_new_size);
    if (!tx_cur)
        return -1;
    memcpy((uint8_t*) tx_cur->tx_items + tx_cur->header.tx_items_size, a_item, size);
    tx_cur->header.tx_items_size += size;
    *a_tx = tx_cur;
    return 1;
}

/**
 * Create 'in' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_in_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_tx_prev_hash,
        uint32_t a_tx_out_prev_idx)
{
    dap_chain_tx_in_t *l_tx_in = dap_chain_datum_tx_item_in_create(a_tx_prev_hash, a_tx_out_prev_idx);
    if(l_tx_in) {
        dap_chain_datum_tx_add_item(a_tx, (const uint8_t *)l_tx_in);
        DAP_DELETE(l_tx_in);
        return 1;
    }
    return -1;
}

/**
 * Create 'in' items from list and insert to transaction
 *
 * return summary value from inserted items
 */
uint256_t dap_chain_datum_tx_add_in_item_list(dap_chain_datum_tx_t **a_tx, dap_list_t *a_list_used_out)
{
    dap_list_t *l_item_out;
    uint256_t l_value_to_items = { }; // how many datoshi to transfer
    DL_FOREACH(a_list_used_out, l_item_out) {
        dap_chain_tx_used_out_item_t *l_item = l_item_out->data;
        if (dap_chain_datum_tx_add_in_item(a_tx, &l_item->tx_hash_fast, l_item->num_idx_out) == 1) {
            SUM_256_256(l_value_to_items, l_item->value, &l_value_to_items);
        }
    }
    return l_value_to_items;
}


/**
 * @brief dap_chain_datum_tx_add_in_cond_item
 * @param a_tx
 * @param a_pkey_serialized
 * @param a_pkey_serialized_size
 * @param a_receipt_idx
 * @return
 */
int dap_chain_datum_tx_add_in_cond_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_tx_prev_hash,
                                        uint32_t a_tx_out_prev_idx,
                                        uint32_t a_receipt_idx)
{
    dap_chain_tx_in_cond_t *l_tx_in_cond
            = dap_chain_datum_tx_item_in_cond_create(a_tx_prev_hash, a_tx_out_prev_idx, a_receipt_idx);
    if (!l_tx_in_cond)
        return -1;
    dap_chain_datum_tx_add_item(a_tx, (uint8_t*)l_tx_in_cond);
    DAP_DELETE(l_tx_in_cond);
    return 0;
}

uint256_t dap_chain_datum_tx_add_in_cond_item_list(dap_chain_datum_tx_t **a_tx, dap_list_t *a_list_used_out_cound)
{
   dap_list_t *l_item_out;
   uint256_t l_value_to_items = { };
   DL_FOREACH(a_list_used_out_cound, l_item_out) {
       dap_chain_tx_used_out_item_t *l_item = l_item_out->data;
       if (!dap_chain_datum_tx_add_in_cond_item(a_tx, &l_item->tx_hash_fast, l_item->num_idx_out,0)) {
           SUM_256_256(l_value_to_items, l_item->value, &l_value_to_items);
       }
   }
   return l_value_to_items;
}

int dap_chain_datum_tx_add_in_reward_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_block_hash)
{
    dap_chain_tx_in_reward_t *l_tx_in_reward = dap_chain_datum_tx_item_in_reward_create(a_block_hash);
    if (!l_tx_in_reward)
        return -1;
    dap_chain_datum_tx_add_item(a_tx, (uint8_t*)l_tx_in_reward);
    DAP_DELETE(l_tx_in_reward);
    return 1;
}

/**
 * Create 'out_cond' item with fee value and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_fee_item(dap_chain_datum_tx_t **a_tx, uint256_t a_value)
{
    dap_chain_tx_out_cond_t *l_tx_out_fee = dap_chain_datum_tx_item_out_cond_create_fee(a_value);
    if (l_tx_out_fee) {
        dap_chain_datum_tx_add_item(a_tx, (const uint8_t *)l_tx_out_fee);
        DAP_DELETE(l_tx_out_fee);
        return 1;
    }
    return -1;
}

int dap_chain_datum_tx_get_fee_value(dap_chain_datum_tx_t *a_tx, uint256_t *a_value)
{
    if (!a_value)
        return -2;
    int l_ret = -1;
    dap_list_t *l_items_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_COND, NULL), *l_item;
    DL_FOREACH(l_items_list, l_item) {
        dap_chain_tx_out_cond_t *l_out_item = (dap_chain_tx_out_cond_t*)l_item->data;
        if (l_out_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE){
            *a_value = l_out_item->header.value;
            l_ret = 0;
            break;
        }
    }
    dap_list_free(l_items_list);
    return l_ret;
}

dap_sign_t *dap_chain_datum_tx_get_sign(dap_chain_datum_tx_t *a_tx, int a_sign_num)
{
    dap_return_val_if_fail(a_tx, NULL);
    if (!a_sign_num) {
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx, NULL, TX_ITEM_TYPE_SIG, NULL);
        return dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
    }
    dap_list_t *l_items_list = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_SIG, NULL);
    if (dap_list_length(l_items_list) <= (uint64_t)a_sign_num)
        return NULL;
    dap_sign_t *l_ret = dap_list_nth_data(l_items_list, a_sign_num);
    dap_list_free(l_items_list);
    return l_ret;
}

/**
 * Create 'out' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value)
{
    dap_chain_tx_out_t *l_tx_out = dap_chain_datum_tx_item_out_create(a_addr, a_value);
    if(l_tx_out) {
        dap_chain_datum_tx_add_item(a_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        return 1;
    }
    return -1;
}

/**
 * Create 'out_ext' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_ext_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token)
{
    dap_chain_tx_out_ext_t *l_tx_out = dap_chain_datum_tx_item_out_ext_create(a_addr, a_value, a_token);
    if(l_tx_out) {
        dap_chain_datum_tx_add_item(a_tx, (const uint8_t *)l_tx_out);
        DAP_DELETE(l_tx_out);
        return 1;
    }
    return -1;
}

/**
 * Create 'out_cond' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_cond_item(dap_chain_datum_tx_t **a_tx, dap_pkey_t *a_key, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value, uint256_t a_value_max_per_unit, dap_chain_net_srv_price_unit_uid_t a_unit, const void *a_cond, size_t a_cond_size)
{
    dap_chain_tx_out_cond_t *l_tx_out = dap_chain_datum_tx_item_out_cond_create_srv_pay(
                a_key, a_srv_uid,a_value, a_value_max_per_unit, a_unit, a_cond, a_cond_size );
    if(l_tx_out) {
        dap_chain_datum_tx_add_item(a_tx, (const uint8_t *) l_tx_out);
        DAP_DELETE(l_tx_out);
        return 1;
    }
    return -1;
}


/**
 * Sign a transaction (Add sign item to transaction)
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_sign_item(dap_chain_datum_tx_t **a_tx, dap_enc_key_t *a_key)
{
    if(!a_tx || !a_key)
        return -1;
    // sign all previous items in transaction
    const void *l_data = (*a_tx)->tx_items;
    const size_t l_data_size = (*a_tx)->header.tx_items_size;
    dap_chain_tx_sig_t *l_tx_sig = dap_chain_datum_tx_item_sign_create(a_key, l_data, l_data_size);
    if(l_tx_sig) {
        int l_ret = dap_chain_datum_tx_add_item(a_tx, (const uint8_t*) l_tx_sig);
        DAP_DELETE(l_tx_sig);
        return l_ret;
    }
    return -1;
}

/**
 * Verify all sign item in transaction
 *
 * return 1 Ok, 0 Invalid signature, -1 Not found signature or other Error
 */
int dap_chain_datum_tx_verify_sign(dap_chain_datum_tx_t *a_tx)
{
    dap_return_val_if_pass(!a_tx, -1);
    int l_ret = 0;
    uint32_t tx_items_pos = 0, tx_items_size = a_tx->header.tx_items_size;
    while(tx_items_pos < tx_items_size) {
        uint8_t *item = a_tx->tx_items + tx_items_pos;
        size_t l_item_tx_size = dap_chain_datum_item_tx_get_size(item);
        if(!l_item_tx_size || l_item_tx_size > tx_items_size)
            return -2;
        if(dap_chain_datum_tx_item_get_type(item) == TX_ITEM_TYPE_SIG) {
            dap_chain_tx_sig_t *l_item_tx_sig = (dap_chain_tx_sig_t*) item;
            dap_sign_t *l_sign = (dap_sign_t*) l_item_tx_sig->sig;
            if ( ( l_sign->header.sign_size + l_sign->header.sign_pkey_size +sizeof (l_sign->header) )
                  > l_item_tx_size ){
                log_it(L_WARNING,"Incorrect signature's header, possible corrupted data");
                return -3;
            }
            if ((l_ret = dap_sign_verify_all(l_sign, tx_items_size, a_tx->tx_items, tx_items_pos))) {
                // invalid signature
                tx_items_pos += l_item_tx_size;
                break;
            }
        }
        // sign item or items must be at the end, therefore ret will be changed later anyway
        else
            l_ret = -4;
        // go to text item
        tx_items_pos += l_item_tx_size;
    }
    assert(tx_items_pos == tx_items_size);
    return l_ret;
}
