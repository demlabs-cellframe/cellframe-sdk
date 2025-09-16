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
    if ( *(byte_t*)a_item != TX_ITEM_TYPE_SIG && dap_chain_datum_tx_item_get(*a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL) )
        return log_it(L_ERROR, "Can't add item, datum already signed"), -1;
    dap_chain_datum_tx_t *tx_new = DAP_REALLOC_RET_VAL_IF_FAIL( *a_tx, dap_chain_datum_tx_get_size(*a_tx) + size, -2 );
    memcpy((uint8_t*)tx_new->tx_items + tx_new->header.tx_items_size, a_item, size);
    tx_new->header.tx_items_size += size;
    *a_tx = tx_new;
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    char *l_hash = dap_hash_fast_str_new(a_item, size);
    log_it(L_INFO, "Add \"%s\" item %s\n",  dap_chain_datum_tx_item_type_to_str_short(*(byte_t *)(a_item)), l_hash);
    DAP_DELETE(l_hash);
#endif
    return 1;
}

#define dap_chain_datum_tx_add_new_generic(a_tx, type, a_item) \
    ({ type* item = a_item; int ret = dap_chain_datum_tx_add_item(a_tx, item); DAP_DELETE(item); ret; })

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
       if (1 == dap_chain_datum_tx_add_in_cond_item(a_tx, &l_item->tx_hash_fast, l_item->num_idx_out, -1)) {
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
    return dap_chain_datum_tx_item_sig_get_sign( (dap_chain_tx_sig_t*) dap_chain_datum_tx_item_get_nth(a_tx, TX_ITEM_TYPE_SIG, a_sign_num) );
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
#ifdef DAP_CHAIN_TX_COMPOSE_TEST
    if (rand() % 2)
        return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_std_t,  dap_chain_datum_tx_item_out_std_create(a_addr, a_value, a_token, rand() % UINT64_MAX ) );
    else
        return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_ext_t,  dap_chain_datum_tx_item_out_ext_create(a_addr, a_value, a_token) );
#else
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_std_t,  dap_chain_datum_tx_item_out_std_create(a_addr, a_value, a_token, 0) );
#endif
}

/**
 * Create 'out_ext' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_std_item(dap_chain_datum_tx_t **a_tx, const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token, dap_time_t a_ts_unlock)
{
    return dap_chain_datum_tx_add_new_generic( a_tx, dap_chain_tx_out_std_t,  dap_chain_datum_tx_item_out_std_create(a_addr, a_value, a_token, a_ts_unlock) );
}

/**
 * Create 'out_cond' item and insert to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_out_cond_item(dap_chain_datum_tx_t **a_tx, dap_pkey_t *a_key, dap_chain_srv_uid_t a_srv_uid,
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
 * Verify all sign item in transaction
 *
 * return 0: OK, -1: Sign verify error, -2, -3: Size check error, -4: Not found signature
 */
int dap_chain_datum_tx_verify_sign(dap_chain_datum_tx_t *a_tx, int a_sign_num)
{
    dap_return_val_if_pass(!a_tx, -1);
    int l_ret = -4;
    size_t l_item_size = 0, l_data_size = 0;
    byte_t *l_item = dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, &l_item_size), *l_data_end = l_item;
    if ( !l_item )
        return log_it(L_ERROR, "No signs in TX"), l_ret;
    dap_chain_tx_sig_t *l_sign_item = NULL;
    l_data_size = (size_t)(l_item - a_tx->tx_items);
    if ( a_sign_num ) {
        TX_ITEM_ITER( l_item, l_item_size, l_data_end, a_tx->header.tx_items_size - l_data_size ) {
            if ( *l_item != TX_ITEM_TYPE_SIG )
                return log_it(L_ERROR, "Item 0x%x found beyond data end", *l_item), -1;
            if ( !--a_sign_num ) {
                l_sign_item = (dap_chain_tx_sig_t*)l_item;
                break;
            }
        }
        if ( !l_sign_item )
            return log_it(L_ERROR, "Sign not found in TX"), l_ret;
    } else
        l_sign_item = (dap_chain_tx_sig_t*)l_item;
    
    dap_sign_t *l_sign = dap_chain_datum_tx_item_sig_get_sign(l_sign_item);
    if ( !l_sign )
        return log_it(L_ERROR, "Can't extract sign from item"), -1;
    size_t l_tx_items_size = a_tx->header.tx_items_size;
    dap_chain_datum_tx_t *l_tx;
    byte_t *l_data;
    if ( l_sign_item->header.version ) {
        l_data_size = l_data_end - (byte_t*)a_tx;
        l_tx = dap_config_get_item_bool_default(g_config, "ledger", "mapped", true) ? DAP_DUP_SIZE(a_tx, l_data_size) : a_tx;
        l_tx->header.tx_items_size = 0;
        l_data = (byte_t*)l_tx;
    } else {
        l_tx = a_tx;
        l_data = a_tx->tx_items;
        l_data_size = (byte_t*)l_sign_item - l_data;
    }
    l_ret = dap_sign_verify_all(l_sign, l_item_size, l_data, l_data_size);
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


/**
 * Get item from transaction
 *
 * a_tx [in] transaction
 * a_item_idx[in/out] start index / found index of item in transaction, if 0 then from beginning
 * a_type[in] type of item being find, if TX_ITEM_TYPE_ANY - any item
 * a_item_out_size size[out] size of returned item
 * return item data, NULL Error index or bad format transaction
 */
uint8_t* dap_chain_datum_tx_item_get(const dap_chain_datum_tx_t *a_tx, int *a_item_idx,
                                     byte_t *a_iter, dap_chain_tx_item_type_t a_type, size_t *a_item_out_size)
{
    if (!a_tx)
        return NULL;
    int i = a_item_idx ? *a_item_idx : 0, j = -1;
    const byte_t  *l_end = a_tx->tx_items + a_tx->header.tx_items_size,
                  *l_begin = i || !a_iter || a_iter < a_tx->tx_items || a_iter > l_end ? a_tx->tx_items : a_iter;
    size_t l_left_size = (size_t)(l_end - l_begin), l_tx_item_size;
    byte_t *l_item;
#define m_item_idx_n_size(item, idx, size) ({       \
    if (a_item_idx) *a_item_idx = idx;              \
    if (a_item_out_size) *a_item_out_size = size;   \
    item;                                           \
})
    TX_ITEM_ITER(l_item, l_tx_item_size, l_begin, l_left_size) {
        if (++j < i)
            continue;
        switch (a_type) {
        case TX_ITEM_TYPE_ANY:
            break;
        case TX_ITEM_TYPE_OUT_ALL:
            switch (*l_item) {
            case TX_ITEM_TYPE_OUT: case TX_ITEM_TYPE_OUT_OLD: case TX_ITEM_TYPE_OUT_COND: case TX_ITEM_TYPE_OUT_EXT: case TX_ITEM_TYPE_OUT_STD:
                break;
            default:
                continue;
            } break;
        case TX_ITEM_TYPE_IN_ALL:
            switch (*l_item) {
            case TX_ITEM_TYPE_IN: case TX_ITEM_TYPE_IN_COND: case TX_ITEM_TYPE_IN_EMS: case TX_ITEM_TYPE_IN_REWARD:
                break;
            default:
                continue;
            } break;
        default:
            if (*l_item == a_type)
                break;
            else continue;
        }
        return m_item_idx_n_size(l_item, j, l_tx_item_size);
    }
    return m_item_idx_n_size(NULL, -1, 0);
#undef m_item_idx_n_size
}

/**
 * Get all item from transaction by type
 *
 * a_tx [in] transaction
 * a_type[in] type of item being find, if TX_ITEM_TYPE_ANY - any item
 * a_item_count[out] count of returned item
 * return item data, NULL Error index or bad format transaction
 */
dap_list_t* dap_chain_datum_tx_items_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int *a_item_count)
{
    dap_list_t *items_list = NULL;
    uint8_t *l_tx_item = NULL;
    size_t l_size; int i, q = 0;
    TX_ITEM_ITER_TX_TYPE(l_tx_item, a_type, l_size, i, a_tx) {
        items_list = dap_list_append(items_list, l_tx_item);
        ++q;
    }
    return (a_item_count ? (*a_item_count = q) : 0), items_list;
}

uint8_t *dap_chain_datum_tx_item_get_nth(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int a_item_idx)
{
    uint8_t *l_tx_item = NULL; size_t l_size; int i;
    TX_ITEM_ITER_TX_TYPE(l_tx_item, a_type, l_size, i, a_tx) {
        if (!a_item_idx--)
            return l_tx_item;
    }
    return NULL;
}

/**
 * Get tx_out_cond item from transaction
 *
 * a_tx [in] transaction
 * a_cond_type [in] type of condition to find
 * a_out_num[out] found index of item in transaction, -1 if not found
 * return tx_out_cond, or NULL
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_out_cond_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_out_cond_subtype_t a_cond_subtype, int *a_out_num)
{
    if (!a_tx)
        return NULL;
    int l_idx = a_out_num && *a_out_num > 0 ? -*a_out_num : 0;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_OUT_COND:
            if ( l_idx >= 0 && ((dap_chain_tx_out_cond_t*)l_item)->header.subtype == a_cond_subtype ) {
                if (a_out_num) *a_out_num += l_idx;
                return (dap_chain_tx_out_cond_t*)l_item;
            }
        case TX_ITEM_TYPE_OUT: case TX_ITEM_TYPE_OUT_OLD: case TX_ITEM_TYPE_OUT_EXT: case TX_ITEM_TYPE_OUT_STD:
            ++l_idx;
        default:
            break;
        }
    }
    return (a_out_num ? (*a_out_num = -1) : 0), NULL;
}

void dap_chain_datum_tx_group_items_free( dap_chain_datum_tx_item_groups_t *a_items_groups)
{   
    dap_list_free(a_items_groups->items_in);
    dap_list_free(a_items_groups->items_in_cond);
    dap_list_free(a_items_groups->items_in_reward);
    dap_list_free(a_items_groups->items_sig);
    dap_list_free(a_items_groups->items_out);
    dap_list_free(a_items_groups->items_out_ext);
    dap_list_free(a_items_groups->items_out_std);
    dap_list_free(a_items_groups->items_out_cond);
    dap_list_free(a_items_groups->items_out_cond_srv_fee);
    dap_list_free(a_items_groups->items_out_cond_srv_pay);
    dap_list_free(a_items_groups->items_out_cond_srv_xchange);
    dap_list_free(a_items_groups->items_out_cond_srv_stake_pos_delegate);
    dap_list_free(a_items_groups->items_out_cond_srv_stake_lock);
    dap_list_free(a_items_groups->items_out_cond_wallet_shared);
    dap_list_free(a_items_groups->items_in_ems);
    dap_list_free(a_items_groups->items_vote);
    dap_list_free(a_items_groups->items_voting);
    dap_list_free(a_items_groups->items_tsd);
    dap_list_free(a_items_groups->items_pkey);
    dap_list_free(a_items_groups->items_receipt);
    dap_list_free(a_items_groups->items_unknown);
    dap_list_free(a_items_groups->items_out_old);
    dap_list_free(a_items_groups->items_out_cond_unknonwn);
    dap_list_free(a_items_groups->items_out_cond_undefined);
    dap_list_free(a_items_groups->items_out_all);
    dap_list_free(a_items_groups->items_in_all);
    dap_list_free(a_items_groups->items_event);
}

#define DAP_LIST_SAPPEND(X, Y) X = dap_list_append(X,Y)
bool dap_chain_datum_tx_group_items(dap_chain_datum_tx_t *a_tx, dap_chain_datum_tx_item_groups_t *a_res_group)
{   
    if(!a_tx || !a_res_group)
        return NULL;
    
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_IN:
            DAP_LIST_SAPPEND(a_res_group->items_in, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_in_all, l_item);
            break;

        case TX_ITEM_TYPE_IN_COND:
            DAP_LIST_SAPPEND(a_res_group->items_in_cond, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_in_all, l_item);
            break;

        case TX_ITEM_TYPE_IN_REWARD:
            DAP_LIST_SAPPEND(a_res_group->items_in_reward, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_in_all, l_item);
            break;

        case TX_ITEM_TYPE_IN_EMS:
            DAP_LIST_SAPPEND(a_res_group->items_in_ems, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_in_all, l_item);
            break;

        case TX_ITEM_TYPE_OUT_OLD:
            DAP_LIST_SAPPEND(a_res_group->items_out_old, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_out_all, l_item);
            break;

        case TX_ITEM_TYPE_OUT_EXT:
            DAP_LIST_SAPPEND(a_res_group->items_out_ext, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_out_all, l_item);
            break;

        case TX_ITEM_TYPE_OUT_STD:
            DAP_LIST_SAPPEND(a_res_group->items_out_std, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_out_all, l_item);
            break;

        case TX_ITEM_TYPE_OUT:
            DAP_LIST_SAPPEND(a_res_group->items_out, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_out_all, l_item);
            break;

        case TX_ITEM_TYPE_OUT_COND: {
            switch ( ((dap_chain_tx_out_cond_t *)l_item)->header.subtype ) {
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_undefined, l_item);
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_srv_pay, l_item);
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_srv_xchange, l_item);
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_srv_stake_pos_delegate, l_item);
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_srv_fee, l_item);
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_srv_stake_lock, l_item);
                break;
            case DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_wallet_shared, l_item);
                break;
            default:
                DAP_LIST_SAPPEND(a_res_group->items_out_cond_unknonwn, l_item);
                break;
            }
            DAP_LIST_SAPPEND(a_res_group->items_out_cond, l_item);
            DAP_LIST_SAPPEND(a_res_group->items_out_all, l_item);
            }
            break;

        case TX_ITEM_TYPE_PKEY:
            DAP_LIST_SAPPEND(a_res_group->items_pkey, l_item);
            break;
        case TX_ITEM_TYPE_SIG:
            DAP_LIST_SAPPEND(a_res_group->items_sig, l_item);
            break;
        case TX_ITEM_TYPE_RECEIPT_OLD:
        case TX_ITEM_TYPE_RECEIPT:
            DAP_LIST_SAPPEND(a_res_group->items_receipt, l_item);
            break;
        case TX_ITEM_TYPE_TSD:
            DAP_LIST_SAPPEND(a_res_group->items_tsd, l_item);
            break;

        case TX_ITEM_TYPE_VOTING:
            DAP_LIST_SAPPEND(a_res_group->items_voting, l_item);
            break;

        case TX_ITEM_TYPE_VOTE:
            DAP_LIST_SAPPEND(a_res_group->items_vote, l_item);
            break;
        case TX_ITEM_TYPE_EVENT:
            DAP_LIST_SAPPEND(a_res_group->items_event, l_item);
            break;
        default:
            DAP_LIST_SAPPEND(a_res_group->items_unknown, l_item);
        }
    }
    return true;
}

dap_chain_tx_tsd_t *dap_chain_datum_tx_item_get_tsd_by_type(dap_chain_datum_tx_t *a_tx, int a_type)
{   
    dap_return_val_if_pass(!a_tx, NULL);
    
    byte_t *l_item = NULL;
    size_t l_tx_item_size = 0;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        if (*l_item == TX_ITEM_TYPE_TSD && ((dap_tsd_t *)(((dap_chain_tx_tsd_t *)l_item)->tsd))->type ==  a_type)
        return (dap_chain_tx_tsd_t *)l_item;
    }
    return NULL;
}
