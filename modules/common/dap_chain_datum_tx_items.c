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

#include <stdint.h>
#include <string.h>

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"

#define LOG_TAG "dap_chain_datum_tx_items"

/**
 * Get item type by item name
 *
 * return type, or TX_ITEM_TYPE_UNKNOWN
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_str_to_type(const char *a_datum_name) {
    if(!a_datum_name)
        return TX_ITEM_TYPE_UNKNOWN;
    if(!dap_strcmp(a_datum_name, "in"))
        return TX_ITEM_TYPE_IN;
    else if(!dap_strcmp(a_datum_name, "in_ems"))
        return TX_ITEM_TYPE_IN_EMS;
    else if(!dap_strcmp(a_datum_name, "in_reward"))
        return TX_ITEM_TYPE_IN_REWARD;
    else if(!dap_strcmp(a_datum_name, "out"))
        return TX_ITEM_TYPE_OUT;
    else if(!dap_strcmp(a_datum_name, "out_ext"))
        return TX_ITEM_TYPE_OUT_EXT;
    else if(!dap_strcmp(a_datum_name, "pkey"))
        return TX_ITEM_TYPE_PKEY;
    else if(!dap_strcmp(a_datum_name, "sign"))
        return TX_ITEM_TYPE_SIG;
    else if(!dap_strcmp(a_datum_name, "token"))
        return TX_ITEM_TYPE_IN_EMS;
    else if(!dap_strcmp(a_datum_name, "in_cond"))
        return TX_ITEM_TYPE_IN_COND;
    else if(!dap_strcmp(a_datum_name, "out_cond"))
        return TX_ITEM_TYPE_OUT_COND;
    else if(!dap_strcmp(a_datum_name, "receipt"))
        return TX_ITEM_TYPE_RECEIPT;
    else if(!dap_strcmp(a_datum_name, "data"))
        return TX_ITEM_TYPE_TSD;
    else if(!dap_strcmp(a_datum_name, "voting"))
        return TX_ITEM_TYPE_VOTING;
    else if(!dap_strcmp(a_datum_name, "vote"))
        return TX_ITEM_TYPE_VOTE;
    return TX_ITEM_TYPE_UNKNOWN;
}

/**
 * Get dap_chain_tx_out_cond_subtype_t by name
 *
 * return subtype, or DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED
 */
dap_chain_tx_out_cond_subtype_t dap_chain_tx_out_cond_subtype_from_str(const char *a_subtype_str) {
    if(!a_subtype_str)
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
    if(!dap_strcmp(a_subtype_str, "srv_pay"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY;
    else if(!dap_strcmp(a_subtype_str, "srv_xchange"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;
    else if(!dap_strcmp(a_subtype_str, "srv_stake_pos_delegate"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    else if (!dap_strcmp(a_subtype_str, "srv_stake_lock"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK;
    else if(!dap_strcmp(a_subtype_str, "fee"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE;
    return DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
}

/**
 * Get item size
 *
 * return size, 0 Error
 */

size_t dap_chain_datum_item_tx_get_size(const byte_t *a_item, size_t a_max_size) {
    dap_return_val_if_fail(a_item, TX_ITEM_TYPE_UNKNOWN);
    size_t l_ret = 0;
#define m_tx_item_size(t) ( !a_max_size || sizeof(t) <= a_max_size ? sizeof(t) : 0 )
#define m_tx_item_size_ext(t, size_field)                                                                                       \
    ( !a_max_size ||                                                                                                            \
    ( sizeof(t) < a_max_size && a_max_size > ((t*)a_item)->size_field && sizeof(t) <= a_max_size - ((t*)a_item)->size_field )   \
        ? sizeof(t) + ((t*)a_item)->size_field : 0 );

    switch (*a_item) {
    case TX_ITEM_TYPE_IN:       return m_tx_item_size(dap_chain_tx_in_t);
    case TX_ITEM_TYPE_OUT_OLD:  return m_tx_item_size(dap_chain_tx_out_old_t);
    case TX_ITEM_TYPE_OUT:      return m_tx_item_size(dap_chain_tx_out_t);
    case TX_ITEM_TYPE_OUT_EXT:  return m_tx_item_size(dap_chain_tx_out_ext_t);
    case TX_ITEM_TYPE_IN_COND:  return m_tx_item_size(dap_chain_tx_in_cond_t);
    case TX_ITEM_TYPE_IN_EMS:   return m_tx_item_size(dap_chain_tx_in_ems_t);
    case TX_ITEM_TYPE_IN_REWARD:return m_tx_item_size(dap_chain_tx_in_reward_t);
    case TX_ITEM_TYPE_VOTING:   return m_tx_item_size(dap_chain_tx_voting_t);
    case TX_ITEM_TYPE_VOTE:     return m_tx_item_size(dap_chain_tx_vote_t);
    // Access data size by struct field
    case TX_ITEM_TYPE_TSD:           return m_tx_item_size_ext(dap_chain_tx_tsd_t, header.size);
    case TX_ITEM_TYPE_OUT_COND: return m_tx_item_size_ext(dap_chain_tx_out_cond_t, tsd_size);
    case TX_ITEM_TYPE_PKEY:         return m_tx_item_size_ext(dap_chain_tx_pkey_t, header.sig_size);
    case TX_ITEM_TYPE_SIG:           return m_tx_item_size_ext(dap_chain_tx_sig_t, header.sig_size);
    // Receipt size calculation is non-trivial...
    case TX_ITEM_TYPE_RECEIPT: {
        typedef dap_chain_datum_tx_receipt_t t;
        return !a_max_size || ( sizeof(t) < a_max_size && ((t*)a_item)->size < a_max_size ) ? ((t*)a_item)->size : 0;
    }
    default: return 0;
    }
#undef m_tx_item_size
#undef m_tx_item_size_ext
}

/**
 * Create item dap_chain_tx_in_ems_t
 *
 * return item, NULL Error
 */
dap_chain_tx_in_ems_t *dap_chain_datum_tx_item_in_ems_create(dap_chain_id_t a_id, dap_chain_hash_fast_t *a_datum_token_hash, const char *a_ticker)
{
    if(!a_ticker)
        return NULL;
    dap_chain_tx_in_ems_t *l_item = DAP_NEW_Z(dap_chain_tx_in_ems_t);
    if (!l_item) {
        return NULL;
    }
    l_item->header.type = TX_ITEM_TYPE_IN_EMS;
    l_item->header.token_emission_chain_id.uint64 = a_id.uint64;
    l_item->header.token_emission_hash = *a_datum_token_hash;
    strncpy(l_item->header.ticker, a_ticker, sizeof(l_item->header.ticker) - 1);
    return l_item;
}

/**
 * Create item dap_chain_tx_out_old_t
 *
 * return item, NULL Error
 */
dap_chain_tx_in_t* dap_chain_datum_tx_item_in_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx)
{
    if(!a_tx_prev_hash)
        return NULL;
    dap_chain_tx_in_t *l_item = DAP_NEW_Z(dap_chain_tx_in_t);
    if (!l_item)
        return NULL;
    l_item->header.type = TX_ITEM_TYPE_IN;
    l_item->header.tx_out_prev_idx = a_tx_out_prev_idx;
    l_item->header.tx_prev_hash = *a_tx_prev_hash;
    return l_item;
}

dap_chain_tx_in_reward_t *dap_chain_datum_tx_item_in_reward_create(dap_chain_hash_fast_t *a_block_hash)
{
    if (!a_block_hash)
        return NULL;
    dap_chain_tx_in_reward_t *l_item = DAP_NEW_Z(dap_chain_tx_in_reward_t);
    if (!l_item)
        return NULL;
    l_item->type = TX_ITEM_TYPE_IN_REWARD;
    l_item->block_hash = *a_block_hash;
    return l_item;
}

/**
 * Create tsd section
 */
dap_chain_tx_tsd_t *dap_chain_datum_tx_item_tsd_create(void *a_data, int a_type, size_t a_size) {
    if (!a_data || !a_size) {
        return NULL;
    }
    dap_tsd_t *l_tsd = dap_tsd_create(a_type, a_data, a_size);
    size_t l_tsd_sz = dap_tsd_size(l_tsd);
    dap_chain_tx_tsd_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_tsd_t,
                                                sizeof(dap_chain_tx_tsd_t) + l_tsd_sz);
    memcpy(l_item->tsd, l_tsd, l_tsd_sz);
    DAP_DELETE(l_tsd);
    l_item->header.type = TX_ITEM_TYPE_TSD;
    l_item->header.size = l_tsd_sz;
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
    if (!l_item) {
        return NULL;
    }
    l_item->header.type = TX_ITEM_TYPE_IN_COND;
    l_item->header.receipt_idx = a_receipt_idx;
    l_item->header.tx_out_prev_idx = a_tx_out_prev_idx;
    l_item->header.tx_prev_hash = *a_tx_prev_hash;
    return l_item;
}

/**
 * Create item dap_chain_tx_out_old_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_t* dap_chain_datum_tx_item_out_create(const dap_chain_addr_t *a_addr, uint256_t a_value)
{
    if (!a_addr || IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_t *l_item = DAP_NEW_Z(dap_chain_tx_out_t);
    if (!l_item) {
        return NULL;
    }
    l_item->addr = *a_addr;
    l_item->header.type = TX_ITEM_TYPE_OUT;
    l_item->header.value = a_value;
    return l_item;
}

dap_chain_tx_out_ext_t* dap_chain_datum_tx_item_out_ext_create(const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token)
{
    if (!a_addr || !a_token)
        return NULL;
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_ext_t *l_item = DAP_NEW_Z(dap_chain_tx_out_ext_t);
    if (!l_item) {
        return NULL;
    }
    l_item->header.type = TX_ITEM_TYPE_OUT_EXT;
    l_item->header.value = a_value;
    l_item->addr = *a_addr;
    strcpy((char *)l_item->token, a_token);
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_fee(uint256_t a_value)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    if (!l_item) {
        return NULL;
    }
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE;
    return l_item;
}

/**
 * Create item dap_chain_tx_out_cond_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t* dap_chain_datum_tx_item_out_cond_create_srv_pay(dap_pkey_t *a_key, dap_chain_net_srv_uid_t a_srv_uid,
                                                                             uint256_t a_value, uint256_t a_value_max_per_unit,
                                                                             dap_chain_net_srv_price_unit_uid_t a_unit,
                                                                             const void *a_params, size_t a_params_size)
{
    if (!a_key || !a_key->header.size )
        return NULL;
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size);
    if (l_item == NULL)
        return NULL;

    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_pay.unit = a_unit;
    l_item->subtype.srv_pay.unit_price_max_datoshi = a_value_max_per_unit;
    dap_hash_fast(a_key->pkey, a_key->header.size, &l_item->subtype.srv_pay.pkey_hash);
    if (a_params && a_params_size) {
        l_item->tsd_size = (uint32_t)a_params_size;
        memcpy(l_item->tsd, a_params, a_params_size);
    }
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_xchange(dap_chain_net_srv_uid_t a_srv_uid, dap_chain_net_id_t a_sell_net_id,
                                                                             uint256_t a_value_sell, dap_chain_net_id_t a_buy_net_id,
                                                                             const char *a_token, uint256_t a_value_rate,
                                                                             const dap_chain_addr_t *a_seller_addr,
                                                                             const void *a_params, uint32_t a_params_size)
{
    if (!a_token)
        return NULL;
    if (IS_ZERO_256(a_value_sell) || IS_ZERO_256(a_value_rate))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value_sell;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_xchange.buy_net_id = a_buy_net_id;
    l_item->subtype.srv_xchange.sell_net_id = a_sell_net_id;
    strncpy(l_item->subtype.srv_xchange.buy_token, a_token, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_item->subtype.srv_xchange.rate = a_value_rate;
    l_item->subtype.srv_xchange.seller_addr = *a_seller_addr;
    l_item->tsd_size = a_params_size;
    if (a_params_size) {
        memcpy(l_item->tsd, a_params, a_params_size);
    }
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake(dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value,
                                                                           dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_signer_node_addr,
                                                                           dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    size_t l_tsd_total_size = a_sovereign_addr && !dap_chain_addr_is_blank(a_sovereign_addr) ?
                                dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size() : 0;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + l_tsd_total_size);
    if (!l_item) {
        return NULL;
    }
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake_pos_delegate.signing_addr = *a_signing_addr;
    l_item->subtype.srv_stake_pos_delegate.signer_node_addr = *a_signer_node_addr;
    if (l_tsd_total_size) {
        l_item->tsd_size = l_tsd_total_size;
        byte_t *l_next_tsd_ptr = dap_tsd_write(l_item->tsd, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, a_sovereign_addr, sizeof(*a_sovereign_addr));
        dap_tsd_write(l_next_tsd_ptr, DAP_CHAIN_TX_OUT_COND_TSD_VALUE, &a_sovereign_tax, sizeof(a_sovereign_tax));
    }
    return l_item;
}

/**
 * @brief dap_chain_net_srv_stake_lock_create_cond_out
 * @param a_key
 * @param a_srv_uid
 * @param a_value
 * @param a_time_staking
 * @param token
 * @return
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(dap_chain_net_srv_uid_t a_srv_uid,
                                                                                uint256_t a_value, uint64_t a_time_staking,
                                                                                uint256_t a_reinvest_percent)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    if (!l_item) {
        return NULL;
    }
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake_lock.flags = DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME | DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_EMIT;
    l_item->subtype.srv_stake_lock.reinvest_percent = a_reinvest_percent;
    l_item->subtype.srv_stake_lock.time_unlock = dap_time_now() + a_time_staking;
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
    return a_tx_sig && a_tx_sig->header.sig_size > sizeof(dap_sign_t) ? (dap_sign_t*)a_tx_sig->sig : NULL;
}

/**
 * Get data from tsd section
 * @param a_tx_tsd
 * @param a_type
 * @param a_size
 * @return
 */
byte_t *dap_chain_datum_tx_item_get_data(dap_chain_tx_tsd_t *a_tx_tsd, int *a_type, size_t *a_size) {
    if (!a_tx_tsd || !a_type || !a_size)
        return NULL;

    *a_size = ((dap_tsd_t*)(a_tx_tsd->tsd))->size;
    *a_type = ((dap_tsd_t*)(a_tx_tsd->tsd))->type;
    return ((dap_tsd_t*)(a_tx_tsd->tsd))->data;
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
uint8_t* dap_chain_datum_tx_item_get( dap_chain_datum_tx_t *a_tx, int *a_item_idx,
        byte_t *a_iter, dap_chain_tx_item_type_t a_type, size_t *a_item_out_size)
{
    if (!a_tx)
        return NULL;
    int i = a_item_idx && *a_item_idx > 0 ? -*a_item_idx - 1 : 0;
    byte_t  *l_end = a_tx->tx_items + a_tx->header.tx_items_size,
            *l_begin = i || !a_iter || a_iter < a_tx->tx_items || a_iter >= l_end ? a_tx->tx_items : a_iter;
    size_t l_left_size = (size_t)(l_end - l_begin), l_tx_item_size;
    byte_t *l_item;
    TX_ITEM_ITER(l_item, l_tx_item_size, l_begin, l_left_size) {
        if (++i < 0)
            continue;
        switch (a_type) {
        case TX_ITEM_TYPE_ANY:
            break;
        case TX_ITEM_TYPE_OUT_ALL:
            switch (*l_item) {
            case TX_ITEM_TYPE_OUT: case TX_ITEM_TYPE_OUT_OLD: case TX_ITEM_TYPE_OUT_COND: case TX_ITEM_TYPE_OUT_EXT:
                break;
            default:
                continue;
            }
        case TX_ITEM_TYPE_IN_ALL:
            switch (*l_item) {
            case TX_ITEM_TYPE_IN: case TX_ITEM_TYPE_IN_COND: case TX_ITEM_TYPE_IN_EMS: case TX_ITEM_TYPE_IN_REWARD:
                break;
            default:
                continue; 
            }
        default:
            if (*l_item == a_type)
                break;
            else continue;
        }
        return (a_item_idx ? (*a_item_idx = i) : 0), (a_item_out_size ? (*a_item_out_size = l_tx_item_size) : 0), l_item;
    }
    return (a_item_idx ? (*a_item_idx = 0) : 0), (a_item_out_size ? (*a_item_out_size = 0) : 0), NULL;
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
    int l_idx = a_out_num && *a_out_num > 0 ? -*a_out_num : 0;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx) {
        switch (*l_item) {
        case TX_ITEM_TYPE_OUT_COND:
            if ( l_idx >= 0 && ((dap_chain_tx_out_cond_t*)l_item)->header.subtype == a_cond_subtype )
                return (a_out_num ? (*a_out_num = l_idx) : 0), (dap_chain_tx_out_cond_t*)l_item;
        case TX_ITEM_TYPE_OUT: case TX_ITEM_TYPE_OUT_OLD: case TX_ITEM_TYPE_OUT_EXT:
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
    dap_list_free(a_items_groups->items_out_cond);
    dap_list_free(a_items_groups->items_out_cond_srv_fee);
    dap_list_free(a_items_groups->items_out_cond_srv_pay);
    dap_list_free(a_items_groups->items_out_cond_srv_xchange);
    dap_list_free(a_items_groups->items_out_cond_srv_stake_pos_delegate);
    dap_list_free(a_items_groups->items_out_cond_srv_stake_lock);
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
        default:
            DAP_LIST_SAPPEND(a_res_group->items_unknown, l_item);
        }
    }
    return true;

}
