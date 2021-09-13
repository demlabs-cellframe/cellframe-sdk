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

#include <stdint.h>
#include <string.h>

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_items.h"

static size_t dap_chain_tx_in_get_size(const dap_chain_tx_in_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_in_t); // + item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_in_cond_get_size(const dap_chain_tx_in_cond_t *a_item)
{
    UNUSED(a_item);
    size_t size = sizeof(dap_chain_tx_in_cond_t);
    return size;
}

static size_t dap_chain_tx_out_get_size(const dap_chain_tx_out_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_out_t);
    return size;
}

static size_t dap_chain_tx_out_ext_get_size(const dap_chain_tx_out_ext_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_out_ext_t);
    return size;
}

static size_t dap_chain_tx_out_cond_get_size(const dap_chain_tx_out_cond_t *a_item)
{
    return sizeof(dap_chain_tx_out_cond_t) + a_item->params_size;
}

static size_t dap_chain_tx_pkey_get_size(const dap_chain_tx_pkey_t *a_item)
{
    size_t size = sizeof(dap_chain_tx_pkey_t) + a_item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_sig_get_size(const dap_chain_tx_sig_t *item)
{
    size_t size = sizeof(dap_chain_tx_sig_t) + item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_token_get_size(const dap_chain_tx_token_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_token_t);
    return size;
}

/**
 * Get item type
 *
 * return type, or TX_ITEM_TYPE_ANY if error
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_get_type(const uint8_t *a_item)
{
    const dap_chain_tx_in_t *l_item_tx_in = (const dap_chain_tx_in_t*) a_item;
    dap_chain_tx_item_type_t type = (l_item_tx_in) ? l_item_tx_in->header.type : TX_ITEM_TYPE_ANY;
    return type;
}

/**
 * Get item size
 *
 * return size, 0 Error
 */
size_t dap_chain_datum_item_tx_get_size(const uint8_t *a_item)
{
    dap_chain_tx_item_type_t type = dap_chain_datum_tx_item_get_type(a_item);
    size_t size = 0;
    switch (type) {
    case TX_ITEM_TYPE_IN: // Transaction inputs
        size = dap_chain_tx_in_get_size((const dap_chain_tx_in_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT: // Transaction outputs
        size = dap_chain_tx_out_get_size((const dap_chain_tx_out_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT_EXT:
        size = dap_chain_tx_out_ext_get_size((const dap_chain_tx_out_ext_t*) a_item);
        break;
    case TX_ITEM_TYPE_RECEIPT: // Receipt
        size = dap_chain_datum_tx_receipt_get_size((const dap_chain_datum_tx_receipt_t*) a_item);
    case TX_ITEM_TYPE_IN_COND: // Transaction inputs with condition
        size = dap_chain_tx_in_cond_get_size((const dap_chain_tx_in_cond_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT_COND: // Transaction output with condition
        size = dap_chain_tx_out_cond_get_size((const dap_chain_tx_out_cond_t*) a_item);
        break;
    case TX_ITEM_TYPE_PKEY: // Transaction public keys
        size = dap_chain_tx_pkey_get_size((const dap_chain_tx_pkey_t*) a_item);
        break;
    case TX_ITEM_TYPE_SIG: // Transaction signatures
        size = dap_chain_tx_sig_get_size((const dap_chain_tx_sig_t*) a_item);
        break;
    case TX_ITEM_TYPE_TOKEN: // token item
        size = dap_chain_tx_token_get_size((const dap_chain_tx_token_t*) a_item);
        break;
    default:
        return 0;
    }
    return size;
}

/**
 * Create item dap_chain_tx_token_t
 *
 * return item, NULL Error
 */
dap_chain_tx_token_t* dap_chain_datum_tx_item_token_create(dap_chain_hash_fast_t * a_datum_token_hash,const char * a_ticker)
{
    if(!a_ticker)
        return NULL;
    dap_chain_tx_token_t *l_item = DAP_NEW_Z(dap_chain_tx_token_t);
    l_item->header.type = TX_ITEM_TYPE_TOKEN;
    memcpy (& l_item->header.token_emission_hash, a_datum_token_hash, sizeof ( *a_datum_token_hash ) );
    strncpy(l_item->header.ticker, a_ticker, sizeof(l_item->header.ticker) - 1);
    return l_item;
}

/**
 * Create item dap_chain_tx_out_t
 *
 * return item, NULL Error
 */
dap_chain_tx_in_t* dap_chain_datum_tx_item_in_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx)
{
    if(!a_tx_prev_hash)
        return NULL;
    dap_chain_tx_in_t *l_item = DAP_NEW_Z(dap_chain_tx_in_t);
    l_item->header.type = TX_ITEM_TYPE_IN;
    l_item->header.tx_out_prev_idx = a_tx_out_prev_idx;
    memcpy(&l_item->header.tx_prev_hash, a_tx_prev_hash, sizeof(dap_chain_hash_fast_t));
    return l_item;
}

/**
 * @brief dap_chain_datum_tx_item_in_cond_create
 * @param a_pkey_serialized
 * @param a_pkey_serialized_size
 * @param a_receipt_idx
 * @return
 */
dap_chain_tx_in_cond_t* dap_chain_datum_tx_item_in_cond_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx,
                                                               uint32_t a_receipt_idx)
{
    if(!a_tx_prev_hash )
        return NULL;
    dap_chain_tx_in_cond_t *l_item = DAP_NEW_Z(dap_chain_tx_in_cond_t);
    l_item->header.type = TX_ITEM_TYPE_IN_COND;
    l_item->header.receipt_idx = a_receipt_idx;
    l_item->header.tx_out_prev_idx = a_tx_out_prev_idx;
    memcpy(&l_item->header.tx_prev_hash, a_tx_prev_hash,sizeof(l_item->header.tx_prev_hash) );
    return l_item;
}

/**
 * Create item dap_chain_tx_out_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_t* dap_chain_datum_tx_item_out_create(const dap_chain_addr_t *a_addr, uint64_t a_value)
{
    if(!a_addr)
        return NULL;
    dap_chain_tx_out_t *l_item = DAP_NEW_Z(dap_chain_tx_out_t);
    l_item->header.type = TX_ITEM_TYPE_OUT;
    l_item->header.value = a_value;
    memcpy(&l_item->addr, a_addr, sizeof(dap_chain_addr_t));
    return l_item;
}

dap_chain_tx_out_ext_t* dap_chain_datum_tx_item_out_ext_create(const dap_chain_addr_t *a_addr, uint64_t a_value, const char *a_token)
{
    if (!a_addr || !a_token)
        return NULL;
    dap_chain_tx_out_ext_t *l_item = DAP_NEW_Z(dap_chain_tx_out_ext_t);
    l_item->header.type = TX_ITEM_TYPE_OUT_EXT;
    l_item->header.value = a_value;
    memcpy(&l_item->addr, a_addr, sizeof(dap_chain_addr_t));
    strcpy(l_item->token, a_token);
    return l_item;
}

/**
 * Create item dap_chain_tx_out_cond_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t* dap_chain_datum_tx_item_out_cond_create_srv_pay(dap_enc_key_t *a_key, dap_chain_net_srv_uid_t a_srv_uid,
        uint64_t a_value,uint64_t a_value_max_per_unit, dap_chain_net_srv_price_unit_uid_t a_unit,
                                                                 const void *a_params, size_t a_params_size)
{
    if(!a_key || !a_params)
        return NULL;
    size_t l_pub_key_size = 0;
    uint8_t *l_pub_key = dap_enc_key_serealize_pub_key(a_key, &l_pub_key_size);


    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size);
    if(l_item == NULL)
        return NULL;

    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY; // By default creatre cond for service pay. Rework with smth more flexible
    l_item->subtype.srv_pay.srv_uid = a_srv_uid;
    l_item->subtype.srv_pay.unit = a_unit;
    l_item->subtype.srv_pay.unit_price_max_datoshi = a_value_max_per_unit;
    dap_hash_fast( l_pub_key, l_pub_key_size, & l_item->subtype.srv_pay.pkey_hash);
    l_item->params_size = (uint32_t)a_params_size;
    memcpy(l_item->params, a_params, a_params_size);
    return l_item;
}


dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_xchange(dap_chain_net_srv_uid_t a_srv_uid, dap_chain_net_id_t a_net_id,
                                                                             const char *a_token, uint64_t a_value,
                                                                             const void *a_params, uint32_t a_params_size)
{
    if (!a_token) {
        return NULL;
    }
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;
    l_item->subtype.srv_xchange.srv_uid = a_srv_uid;
    l_item->subtype.srv_xchange.net_id = a_net_id;
    strcpy(l_item->subtype.srv_xchange.token, a_token);
    l_item->params_size = a_params_size;
    if (a_params_size) {
        memcpy(l_item->params, a_params, a_params_size);
    }
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake(dap_chain_net_srv_uid_t a_srv_uid, uint64_t a_value, long double a_fee_value,
                                                                           dap_chain_addr_t *a_fee_addr, const void *a_params, uint32_t a_params_size)
{
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE;
    l_item->subtype.srv_stake.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake.fee_value = a_fee_value;
    memcpy(&l_item->subtype.srv_stake.fee_addr, a_fee_addr, sizeof(dap_chain_addr_t));
    l_item->params_size = a_params_size;
    if (a_params_size) {
        memcpy(l_item->params, a_params, a_params_size);
    }
    return l_item;
}

/**
 * Create item dap_chain_tx_sig_t
 *
 * return item, NULL Error
 */
dap_chain_tx_sig_t* dap_chain_datum_tx_item_sign_create(dap_enc_key_t *a_key, const void *a_data, size_t a_data_size)
{
    if(!a_key || !a_data || !a_data_size)
        return NULL;
    dap_sign_t *l_chain_sign = dap_sign_create(a_key, a_data, a_data_size, 0);
    size_t l_chain_sign_size = dap_sign_get_size(l_chain_sign); // sign data
    if(!l_chain_sign) {
        return NULL;
    }
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t,
            sizeof(dap_chain_tx_sig_t) + l_chain_sign_size);
    l_tx_sig->header.type = TX_ITEM_TYPE_SIG;
    l_tx_sig->header.sig_size =(uint32_t) l_chain_sign_size;
    memcpy(l_tx_sig->sig, l_chain_sign, l_chain_sign_size);
    DAP_DELETE(l_chain_sign);
    return l_tx_sig;
}

/**
 * Get sign from sign item
 *
 * return sign, NULL Error
 */
dap_sign_t* dap_chain_datum_tx_item_sign_get_sig(dap_chain_tx_sig_t *a_tx_sig)
{
    if(!a_tx_sig || !a_tx_sig->header.sig_size)
        return NULL;
    return (dap_sign_t*) a_tx_sig->sig;
}

/**
 * Get item from transaction
 *
 * a_tx [in] transaction
 * a_item_idx_start[in/out] start index / found index of item in transaction, if 0 then from beginning
 * a_type[in] type of item being find, if TX_ITEM_TYPE_ANY - any item
 * a_item_out_size size[out] size of returned item
 * return item data, NULL Error index or bad format transaction
 */
uint8_t* dap_chain_datum_tx_item_get( dap_chain_datum_tx_t *a_tx, int *a_item_idx_start,
        dap_chain_tx_item_type_t a_type, int *a_item_out_size)
{
    if(!a_tx)
        return NULL;
    uint32_t l_tx_items_pos = 0, l_tx_items_size = a_tx->header.tx_items_size;
    int l_item_idx = 0;
    while(l_tx_items_pos < l_tx_items_size) {
         uint8_t *l_item = a_tx->tx_items + l_tx_items_pos;
        int l_item_size = dap_chain_datum_item_tx_get_size(l_item);
        if(!l_item_size)
            return NULL;
        // check index
        if(!a_item_idx_start || l_item_idx >= *a_item_idx_start) {
            // check type
            dap_chain_tx_item_type_t l_type = dap_chain_datum_tx_item_get_type(l_item);
            if (a_type == TX_ITEM_TYPE_ANY || a_type == l_type ||
                    (a_type == TX_ITEM_TYPE_OUT_ALL && l_type == TX_ITEM_TYPE_OUT) ||
                    (a_type == TX_ITEM_TYPE_OUT_ALL && l_type == TX_ITEM_TYPE_OUT_COND) ||
                    (a_type == TX_ITEM_TYPE_OUT_ALL && l_type == TX_ITEM_TYPE_OUT_EXT)) {
                if(a_item_idx_start)
                    *a_item_idx_start = l_item_idx;
                if(a_item_out_size)
                    *a_item_out_size = l_item_size;
                return l_item;
            }
        }
        l_tx_items_pos += l_item_size;
        l_item_idx++;
    }
    return NULL;
}

/**
 * Get all item from transaction by type
 *
 * a_tx [in] transaction
 * a_item_idx_start[in/out] start index / found index of item in transaction, if 0 then from beginning
 * a_type[in] type of item being find, if TX_ITEM_TYPE_ANY - any item
 * a_item_count[out] count of returned item
 * return item data, NULL Error index or bad format transaction
 */
dap_list_t* dap_chain_datum_tx_items_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int *a_item_count)
{
    dap_list_t *items_list = NULL;
    int l_items_count = 0, l_item_idx_start = 0;
    // Get sign item from transaction
    while(1) {
        uint8_t *l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx_start, a_type, NULL);
        if(!l_tx_item)
            break;
        items_list = dap_list_append(items_list, l_tx_item);
        l_items_count++;
        l_item_idx_start++;
    }
    if(a_item_count)
        *a_item_count = l_items_count;
    return items_list;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_out_cond_get(dap_chain_datum_tx_t *a_tx, int *a_out_num)
{
    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
    int l_prev_cond_idx = l_list_out_items ? 0 : -1;
    dap_chain_tx_out_cond_t *l_res = NULL;
    for (dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = dap_list_next(l_list_tmp), l_prev_cond_idx++) {
        if (*(uint8_t *)l_list_tmp->data == TX_ITEM_TYPE_OUT_COND) {
            l_res = l_list_tmp->data;
            break;
        }
    }
    dap_list_free(l_list_out_items);
    if (a_out_num) {
        *a_out_num = l_prev_cond_idx;
    }
    return l_res;
}
