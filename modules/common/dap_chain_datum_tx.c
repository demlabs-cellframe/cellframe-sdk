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
    return tx 
        ? tx->header.ts_created = time(NULL), tx
        : ( log_it(L_CRITICAL, "%s", c_error_memory_alloc), NULL );
}

/**
 * Delete transaction
 */
void dap_chain_datum_tx_delete(dap_chain_datum_tx_t *a_tx)
{
    DAP_DELETE(a_tx);
}

/**
 * Get size of transaction
 *
 * return size, 0 Error
 */
size_t dap_chain_datum_tx_get_size(dap_chain_datum_tx_t *a_tx)
{
    return a_tx ? sizeof(dap_chain_datum_tx_t) + a_tx->header.tx_items_size : 0;
}

/**
 * Insert item to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_item(dap_chain_datum_tx_t **a_tx, const void *a_item)
{
    size_t size = 0;
    if ( !a_tx || !*a_tx || !(size = dap_chain_datum_item_tx_get_size(a_item, 0)) )
        return -1;
    dap_chain_datum_tx_t *tx_new = DAP_REALLOC( *a_tx, dap_chain_datum_tx_get_size(*a_tx) + size );
    if (!tx_new)
        return -2;
    memcpy((uint8_t*) tx_new->tx_items + tx_new->header.tx_items_size, a_item, size);
    tx_new->header.tx_items_size += size;
    *a_tx = tx_new;
    return 1;
}

#define dap_chain_datum_tx_add_new_generic(a_tx, type, a_item) \
    ({ type* item = a_item; item ? ( dap_chain_datum_tx_add_item(a_tx, item), DAP_DELETE(item), 1 ) : -1; })

/**
 * Create 'in' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_in_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx)
{
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_in_t,
        dap_chain_datum_tx_item_in_create(a_tx_prev_hash, a_tx_out_prev_idx) );
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
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_in_cond_t,
        dap_chain_datum_tx_item_in_cond_create(a_tx_prev_hash, a_tx_out_prev_idx, a_receipt_idx) );
}

uint256_t dap_chain_datum_tx_add_in_cond_item_list(dap_chain_datum_tx_t **a_tx, dap_list_t *a_list_used_out_cound)
{
   dap_list_t *l_item_out;
   uint256_t l_value_to_items = { };
   DL_FOREACH(a_list_used_out_cound, l_item_out) {
       dap_chain_tx_used_out_item_t *l_item = l_item_out->data;
       if (1 == dap_chain_datum_tx_add_in_cond_item(a_tx, &l_item->tx_hash_fast, l_item->num_idx_out,0)) {
           SUM_256_256(l_value_to_items, l_item->value, &l_value_to_items);
       }
   }
   return l_value_to_items;
}

int dap_chain_datum_tx_add_in_reward_item(dap_chain_datum_tx_t **a_tx, dap_chain_hash_fast_t *a_block_hash)
{
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_in_reward_t,
        dap_chain_datum_tx_item_in_reward_create(a_block_hash) );
}

/**
 * Create 'out_cond' item with fee value and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_fee_item(dap_chain_datum_tx_t **a_tx, uint256_t a_value)
{
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_cond_t,
        dap_chain_datum_tx_item_out_cond_create_fee(a_value) );
}

int dap_chain_datum_tx_get_fee_value(dap_chain_datum_tx_t *a_tx, uint256_t *a_value)
{
    if (!a_value)
        return -2;
    byte_t *l_item; size_t l_tx_item_size;
    dap_chain_tx_out_cond_t *l_out_item;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_OUT_COND:
            l_out_item = (dap_chain_tx_out_cond_t*)l_item;
            if (l_out_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE)
                return (*a_value = l_out_item->header.value), 0;
        default:
            break;
        }
    }
    return -1;
}

dap_sign_t *dap_chain_datum_tx_get_sign(dap_chain_datum_tx_t *a_tx, int a_sign_num)
{
    dap_return_val_if_fail(a_tx, NULL);
    return dap_chain_datum_tx_item_sign_get_sig( (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get_nth(a_tx, TX_ITEM_TYPE_SIG, a_sign_num) );
}

/**
 * Create 'out' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value)
{
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_t,
        dap_chain_datum_tx_item_out_create(a_addr, a_value) );
}

/**
 * Create 'out_ext' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_ext_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token)
{
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_ext_t,
        dap_chain_datum_tx_item_out_ext_create(a_addr, a_value, a_token) );
}

/**
 * Create 'out_cond' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_cond_item(dap_chain_datum_tx_t **a_tx, dap_pkey_t *a_key, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value, uint256_t a_value_max_per_unit, dap_chain_net_srv_price_unit_uid_t a_unit, const void *a_cond, size_t a_cond_size)
{
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_cond_t,
        dap_chain_datum_tx_item_out_cond_create_srv_pay( a_key, a_srv_uid,a_value, a_value_max_per_unit, a_unit, a_cond, a_cond_size ));
}


/**
 * Sign a transaction (Add sign item to transaction)
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_sign_item(dap_chain_datum_tx_t **a_tx, dap_enc_key_t *a_key)
{
    return a_tx && a_key ? dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_sig_t,
        dap_chain_datum_tx_item_sign_create( a_key, (*a_tx)->tx_items, (*a_tx)->header.tx_items_size )) : -1;
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
    byte_t *l_item; size_t l_size;
    dap_sign_t *l_sign;
    TX_ITEM_ITER_TX(l_item, l_size, a_tx) {
        if (*l_item == TX_ITEM_TYPE_SIG) {
            l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t*)l_item);
            const size_t l_offset = (size_t)(l_item - a_tx->tx_items);
            if ( 0 != ( l_ret = dap_sign_get_size(l_sign) > l_size
                    ? log_it(L_WARNING, "Incorrect signature header, possible corrupted data"), -3
                    : dap_sign_verify_all(l_sign, a_tx->header.tx_items_size - l_offset, a_tx->tx_items, l_offset) ))
                break;
        }
    }
    return l_ret;
}
