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
    dap_chain_datum_tx_t *tx = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_datum_tx_t, NULL);
    tx->header.ts_created = time(NULL);
    return tx;
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
    dap_return_val_if_fail(a_tx, 0);
    return (sizeof(dap_chain_datum_tx_t) + a_tx->header.tx_items_size) > a_tx->header.tx_items_size
            ? sizeof(dap_chain_datum_tx_t) + a_tx->header.tx_items_size : 0;
}

/**
 * Insert item to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_item(dap_chain_datum_tx_t **a_tx, const void *a_item)
{
    size_t size = 0;
    dap_return_val_if_pass(!a_tx || !*a_tx || !(size = dap_chain_datum_item_tx_get_size(a_item, 0)), -1 );
    if (*(byte_t *)(a_item) != TX_ITEM_TYPE_SIG && dap_chain_datum_tx_item_get(*a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL)) {
        log_it(L_ERROR, "Can't add item, datum already signed");
        return -1;
    }
    size_t new_size = dap_chain_datum_tx_get_size(*a_tx) + size;
    dap_chain_datum_tx_t *tx_new = DAP_REALLOC_RET_VAL_IF_FAIL( *a_tx, new_size, -2 );
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
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_ext_t,  dap_chain_datum_tx_item_out_ext_create(a_addr, a_value, a_token) );
    // return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_std_t,  dap_chain_datum_tx_item_out_std_create(a_addr, a_value, a_token, 0) );
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
    return a_tx && a_key ? dap_chain_datum_tx_add_new_generic(a_tx, dap_chain_tx_sig_t,
                                                              dap_chain_datum_tx_item_sign_create(a_key, *a_tx)) : -1;
}

/**
 * Verify specified sign item in transaction
 *
 * return 0: OK, -1: Sign verify error, -2, -3: Size check error, -4: Not found signature
 */
int dap_chain_datum_tx_verify_sign(dap_chain_datum_tx_t *a_tx, int a_sign_num)
{
    dap_return_val_if_pass(!a_tx, -1);
    int l_ret = -4, l_sign_num = 0;
    byte_t *l_item = NULL, *l_first_item = NULL;
    size_t
        l_item_size = 0,
        l_sign_item_size = 0;
    dap_chain_tx_sig_t *l_sign_item = NULL;
    TX_ITEM_ITER_TX(l_item, l_item_size, a_tx) {
        if (*l_item != TX_ITEM_TYPE_SIG) {
            if (l_sign_item) {
                log_it(L_ERROR, "Items found after sign");
                return l_ret;
            }
            continue;
        }
        if (!l_first_item)
            l_first_item = l_item;
        if (l_sign_num++ == a_sign_num) {
            l_sign_item = (dap_chain_tx_sig_t*)l_item;
            l_sign_item_size = l_item_size;
        }
    }
    if (!l_sign_item || !l_sign_item_size)
        return log_it(L_ERROR, "Sign not found in TX"), l_ret;
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_sign_item);
    size_t
        l_tx_items_size = a_tx->header.tx_items_size,
        l_data_size = 0;
    dap_chain_datum_tx_t *l_tx = NULL;
    byte_t *l_tx_data = NULL;
    if ( l_sign_item->header.version ) {
        l_data_size = (size_t)( l_first_item - (byte_t *)a_tx );
        l_tx = dap_config_get_item_bool_default(g_config, "ledger", "mapped", true)
            ? DAP_DUP_SIZE(a_tx, l_data_size) : a_tx;
        l_tx_data = (byte_t*)l_tx;
        l_tx->header.tx_items_size = 0;
    } else {
        l_tx = a_tx;
        l_tx_data = a_tx->tx_items;
        l_data_size = (size_t)( (byte_t *)l_sign_item - l_tx_data );
    }
    l_ret = dap_sign_verify_all(l_sign, l_sign_item_size, l_tx_data, l_data_size);
    if (l_sign_item->header.version) {
        if ( dap_config_get_item_bool_default(g_config, "ledger", "mapped", true) )
            DAP_DELETE(l_tx);
        else
            a_tx->header.tx_items_size = l_tx_items_size;
    }
    return debug_if(l_ret, L_ERROR, "Sign verification error %d", l_ret), l_ret;
}

int dap_chain_datum_tx_verify_sign_all(dap_chain_datum_tx_t *a_tx)
{
    int l_sign_num = 0;
    int l_ret = 0;
    byte_t *l_item = NULL;
    size_t l_item_size = 0;
    TX_ITEM_ITER_TX(l_item, l_item_size, a_tx) {
        if (*l_item != TX_ITEM_TYPE_SIG)
            continue;
        if ((l_ret = dap_chain_datum_tx_verify_sign(a_tx, l_sign_num++)))
            return l_ret;
    }
    return l_ret;
}