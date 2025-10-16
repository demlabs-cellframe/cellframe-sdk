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
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_voting.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_time.h"

#define LOG_TAG "dap_chain_datum_tx_items"

/**
 * Get item type by item name
 *
 * return type, or TX_ITEM_TYPE_UNKNOWN
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_type_from_str_short(const char *a_datum_name) {
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
    else if(!dap_strcmp(a_datum_name, "out_std"))
        return TX_ITEM_TYPE_OUT_STD;
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
    else if(!dap_strcmp(a_datum_name, "event"))
        return TX_ITEM_TYPE_EVENT;
    return TX_ITEM_TYPE_UNKNOWN;
}

/**
 * Get dap_chain_tx_out_cond_subtype_t by name
 *
 * return subtype, or DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED
 */
dap_chain_tx_out_cond_subtype_t dap_chain_tx_out_cond_subtype_from_str_short(const char *a_subtype_str) {
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
    else if(!dap_strcmp(a_subtype_str, "wallet_shared"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED;
    return DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
}

/**
 * Get item size
 *
 * return size, 0 Error
 */

size_t dap_chain_datum_item_tx_get_size(const byte_t *a_item, size_t a_max_size) {
    dap_return_val_if_fail(a_item, 0);
#define m_tx_item_size(t) ( !a_max_size || sizeof(t) <= a_max_size ? sizeof(t) : 0 )
#define m_tx_item_size_ext(t, size_field)                                                                                       \
    ( !a_max_size ||                                                                                                            \
    ( sizeof(t) <= a_max_size && a_max_size > ((t*)a_item)->size_field && sizeof(t) <= a_max_size - ((t*)a_item)->size_field )  \
        ? sizeof(t) + ((t*)a_item)->size_field : 0 );

    switch (*a_item) {
    case TX_ITEM_TYPE_IN:       return m_tx_item_size(dap_chain_tx_in_t);
    case TX_ITEM_TYPE_OUT_OLD:  return m_tx_item_size(dap_chain_tx_out_old_t);
    case TX_ITEM_TYPE_OUT:      return m_tx_item_size(dap_chain_tx_out_t);
    case TX_ITEM_TYPE_OUT_EXT:  return m_tx_item_size(dap_chain_tx_out_ext_t);
    case TX_ITEM_TYPE_OUT_STD:  return m_tx_item_size(dap_chain_tx_out_std_t);
    case TX_ITEM_TYPE_IN_COND:  return m_tx_item_size(dap_chain_tx_in_cond_t);
    case TX_ITEM_TYPE_IN_EMS:   return m_tx_item_size(dap_chain_tx_in_ems_t);
    case TX_ITEM_TYPE_IN_REWARD:return m_tx_item_size(dap_chain_tx_in_reward_t);
    case TX_ITEM_TYPE_VOTING:   return m_tx_item_size(dap_chain_tx_voting_t);
    case TX_ITEM_TYPE_VOTE:     return m_tx_item_size(dap_chain_tx_vote_t);
    // Access data size by struct field
    case TX_ITEM_TYPE_TSD:           return m_tx_item_size_ext(dap_chain_tx_tsd_t, header.size);
    case TX_ITEM_TYPE_OUT_COND: return m_tx_item_size_ext(dap_chain_tx_out_cond_t, tsd_size);
    case TX_ITEM_TYPE_PKEY:         return m_tx_item_size_ext(dap_chain_tx_pkey_t, header.size);
    case TX_ITEM_TYPE_SIG:           return m_tx_item_size_ext(dap_chain_tx_sig_t, header.sig_size);
    case TX_ITEM_TYPE_EVENT:  return m_tx_item_size_ext(dap_chain_tx_item_event_t, group_name_size);
    // Receipt size calculation is non-trivial...
    case TX_ITEM_TYPE_RECEIPT_OLD:{
        if(((dap_chain_datum_tx_receipt_t*)a_item)->receipt_info.version < 2)
            return !a_max_size || ( sizeof(dap_chain_datum_tx_receipt_old_t) < a_max_size && 
                                    ((dap_chain_datum_tx_receipt_old_t*)a_item)->size < a_max_size ) ? 
                                    ((dap_chain_datum_tx_receipt_old_t*)a_item)->size : 0;
    }
    case TX_ITEM_TYPE_RECEIPT:{
        if(((dap_chain_datum_tx_receipt_t*)a_item)->receipt_info.version == 2) 
            return !a_max_size || ( sizeof(dap_chain_datum_tx_receipt_t) < a_max_size && 
                                        ((dap_chain_datum_tx_receipt_t*)a_item)->size < a_max_size ) ? 
                                        ((dap_chain_datum_tx_receipt_t*)a_item)->size : 0;
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
    dap_chain_tx_in_ems_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_in_ems_t, NULL);
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
    dap_chain_tx_in_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_in_t, NULL);
    l_item->header.type = TX_ITEM_TYPE_IN;
    l_item->header.tx_out_prev_idx = a_tx_out_prev_idx;
    l_item->header.tx_prev_hash = *a_tx_prev_hash;
    return l_item;
}

dap_chain_tx_in_reward_t *dap_chain_datum_tx_item_in_reward_create(dap_chain_hash_fast_t *a_block_hash)
{
    if (!a_block_hash)
        return NULL;
    dap_chain_tx_in_reward_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_in_reward_t, NULL);
    l_item->type = TX_ITEM_TYPE_IN_REWARD;
    l_item->block_hash = *a_block_hash;
    return l_item;
}

/**
 * Create tsd section
 */
dap_chain_tx_tsd_t *dap_chain_datum_tx_item_tsd_create(const void *a_data, int a_type, size_t a_size)
{
    dap_return_val_if_fail(a_data && a_size, NULL);
    dap_chain_tx_tsd_t *l_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_tsd_t, sizeof(dap_chain_tx_tsd_t) + sizeof(dap_tsd_t) + a_size, NULL);
    l_item->header.type = TX_ITEM_TYPE_TSD;
    l_item->header.size = sizeof(dap_tsd_t) + a_size;
    dap_tsd_write(l_item->tsd, (uint16_t)a_type, a_data, a_size);
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
    dap_chain_tx_in_cond_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_in_cond_t, NULL);
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
    dap_chain_tx_out_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_out_t, NULL);
    l_item->addr = *a_addr;
    l_item->header.type = TX_ITEM_TYPE_OUT;
    l_item->header.value = a_value;
    return l_item;
}

dap_chain_tx_out_ext_t *dap_chain_datum_tx_item_out_ext_create(const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token)
{
    if (!a_addr || !a_token || IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_ext_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_out_ext_t, NULL);
    l_item->header.type = TX_ITEM_TYPE_OUT_EXT;
    l_item->header.value = a_value;
    l_item->addr = *a_addr;
    dap_strncpy((char*)l_item->token, a_token, sizeof(l_item->token));
    return l_item;
}

dap_chain_tx_out_std_t *dap_chain_datum_tx_item_out_std_create(const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token, dap_time_t a_ts_unlock)
{
    if (!a_addr || !a_token || IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_std_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_out_std_t, NULL);
    l_item->type = TX_ITEM_TYPE_OUT_STD;
    l_item->value = a_value;
    l_item->addr = *a_addr;
    dap_strncpy((char*)l_item->token, a_token, sizeof(l_item->token));
    l_item->ts_unlock = a_ts_unlock;
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_fee(uint256_t a_value)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, NULL);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE;
    return l_item;
}

/**
 * @brief Create item dap_chain_tx_out_cond_t
 * @param a_key public key
 * @param a_srv_uid service uid
 * @param a_value value
 * @param a_value_max_per_unit max value per unit
 * @param a_unit unit
 * @param a_params additinonal TSD data
 * @param a_params_size size of additional TSD data
 * @return item, NULL Error
 */
DAP_INLINE dap_chain_tx_out_cond_t* dap_chain_datum_tx_item_out_cond_create_srv_pay(dap_pkey_t *a_key, dap_chain_srv_uid_t a_srv_uid,
                                                                             uint256_t a_value, uint256_t a_value_max_per_unit,
                                                                             dap_chain_net_srv_price_unit_uid_t a_unit,
                                                                             const void *a_params, size_t a_params_size)
{
    dap_return_val_if_pass(!a_key ||!a_key->header.size, NULL);
    dap_hash_fast_t l_key_hash = { };
    
    return dap_hash_fast(a_key->pkey, a_key->header.size, &l_key_hash) ?
        dap_chain_datum_tx_item_out_cond_create_srv_pay_with_hash(&l_key_hash, a_srv_uid, a_value, a_value_max_per_unit, a_unit, a_params, a_params_size) :
        NULL;
}

/**
 * @brief Create item dap_chain_tx_out_cond_t
 * @param a_key_hash pkey hash
 * @param a_srv_uid service uid
 * @param a_value value
 * @param a_value_max_per_unit max value per unit
 * @param a_unit unit
 * @param a_params additinonal TSD data
 * @param a_params_size size of additional TSD data
 * @return item, NULL Error
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_pay_with_hash(dap_hash_fast_t *a_key_hash, dap_chain_srv_uid_t a_srv_uid,
                                                                                    uint256_t a_value, uint256_t a_value_max_per_unit,
                                                                                    dap_chain_net_srv_price_unit_uid_t a_unit,
                                                                                    const void *a_params, size_t a_params_size)
{
    dap_return_val_if_pass(!a_key_hash || IS_ZERO_256(a_value), NULL);
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size, NULL);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_pay.unit = a_unit;
    l_item->subtype.srv_pay.unit_price_max_datoshi = a_value_max_per_unit;
    memcpy( &l_item->subtype.srv_pay.pkey_hash, a_key_hash, sizeof(l_item->subtype.srv_pay.pkey_hash));
    if (a_params && a_params_size) {
        l_item->tsd_size = (uint32_t)a_params_size;
        memcpy(l_item->tsd, a_params, a_params_size);
    }
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_xchange(dap_chain_srv_uid_t a_srv_uid, dap_chain_net_id_t a_sell_net_id,
                                                                             uint256_t a_value_sell, dap_chain_net_id_t a_buy_net_id,
                                                                             const char *a_token, uint256_t a_value_rate,
                                                                             const dap_chain_addr_t *a_seller_addr,
                                                                             const void *a_params, uint32_t a_params_size)
{
    if (!a_token)
        return NULL;
    if (IS_ZERO_256(a_value_sell) || IS_ZERO_256(a_value_rate))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size, NULL);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value_sell;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_xchange.buy_net_id = a_buy_net_id;
    l_item->subtype.srv_xchange.sell_net_id = a_sell_net_id;
    strncpy(l_item->subtype.srv_xchange.buy_token, a_token, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_item->subtype.srv_xchange.rate = a_value_rate;
    l_item->subtype.srv_xchange.seller_addr = *a_seller_addr;
    if (a_params && a_params_size) {
        l_item->tsd_size = (uint32_t)a_params_size;
        memcpy(l_item->tsd, a_params, a_params_size);
    }
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake(dap_chain_srv_uid_t a_srv_uid, uint256_t a_value,
                                                                           dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_signer_node_addr,
                                                                           dap_chain_addr_t *a_sovereign_addr, uint256_t a_sovereign_tax, dap_pkey_t *a_pkey)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    bool l_tsd_sovereign_addr = a_sovereign_addr && !dap_chain_addr_is_blank(a_sovereign_addr);
    size_t l_pkey_size = a_pkey ? dap_pkey_get_size(a_pkey) : 0;
    size_t l_tsd_total_size = dap_chain_datum_tx_item_out_cond_create_srv_stake_get_tsd_size(l_tsd_sovereign_addr, l_pkey_size);
    
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + l_tsd_total_size, NULL);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake_pos_delegate.signing_addr = *a_signing_addr;
    l_item->subtype.srv_stake_pos_delegate.signer_node_addr = *a_signer_node_addr;
    if (l_tsd_total_size) {
        l_item->tsd_size = l_tsd_total_size;
        byte_t *l_next_tsd_ptr = l_item->tsd;
        if (l_tsd_sovereign_addr) {
            l_next_tsd_ptr = dap_tsd_write(l_next_tsd_ptr, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, a_sovereign_addr, sizeof(*a_sovereign_addr));
            l_next_tsd_ptr = dap_tsd_write(l_next_tsd_ptr, DAP_CHAIN_TX_OUT_COND_TSD_VALUE, &a_sovereign_tax, sizeof(a_sovereign_tax));
        }
        if (l_pkey_size) {
            dap_tsd_write(l_next_tsd_ptr, DAP_CHAIN_TX_OUT_COND_TSD_PKEY, a_pkey, l_pkey_size);
            l_item->subtype.srv_stake_pos_delegate.flags = DAP_SIGN_ADD_PKEY_HASHING_FLAG(l_item->subtype.srv_stake_pos_delegate.flags);
        }
    }
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake_delegate(dap_chain_srv_uid_t a_srv_uid, uint256_t a_value,
                                                                           dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_signer_node_addr,
                                                                           uint256_t a_sovereign_tax, const void *a_params, size_t a_params_size)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size, NULL);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake_pos_delegate.signing_addr = *a_signing_addr;
    l_item->subtype.srv_stake_pos_delegate.signer_node_addr = *a_signer_node_addr;
    l_item->tsd_size = a_params_size;
    if (l_item->tsd_size) {
        memcpy(l_item->tsd, a_params, l_item->tsd_size);
        if (dap_tsd_find((byte_t *)a_params, a_params_size, DAP_CHAIN_TX_OUT_COND_TSD_PKEY)) {
            l_item->subtype.srv_stake_pos_delegate.flags = DAP_SIGN_ADD_PKEY_HASHING_FLAG(l_item->subtype.srv_stake_pos_delegate.flags);
        }
    }
    return l_item;
}

/**
 * @brief dap_chain_net_srv_stake_lock_create_cond_out
 * @param a_key
 * @param a_srv_uid
 * @param a_value
 * @param a_time_unlock
 * @param token
 * @return
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(dap_chain_srv_uid_t a_srv_uid,
                                                                                uint256_t a_value, uint64_t a_time_unlock,
                                                                                uint256_t a_reinvest_percent)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, NULL);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake_lock.flags = DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_BY_TIME | DAP_CHAIN_NET_SRV_STAKE_LOCK_FLAG_EMIT;
    l_item->subtype.srv_stake_lock.reinvest_percent = a_reinvest_percent;
    l_item->subtype.srv_stake_lock.time_unlock = a_time_unlock;
    return l_item;
}

/**
 * @brief dap_chain_datum_tx_item_out_cond_create_srv_auction_bid
 * Create conditional output transaction item for auction bid
 * 
 * @param a_srv_uid Service UID for auction service
 * @param a_value Bid amount in datoshi
 * @param a_auction_hash Hash of the auction being bid on
 * @param a_lock_time Lock time for the bid tokens
 * @param a_project_id Project ID for the bid
 * @param a_params Additional TSD parameters
 * @param a_params_size Size of additional parameters
 * @return dap_chain_tx_out_cond_t* Conditional output item or NULL on error
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(dap_chain_srv_uid_t a_srv_uid,
                                                                                  uint256_t a_value,
                                                                                  const dap_hash_fast_t *a_auction_hash,
                                                                                  dap_time_t a_lock_time,
                                                                                  uint32_t a_project_id,
                                                                                  const void *a_params, size_t a_params_size)
{
    if (IS_ZERO_256(a_value) || !a_auction_hash)
        return NULL;
    
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, 
                                                                      sizeof(dap_chain_tx_out_cond_t) + a_params_size, NULL);
    
    // Set header fields
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID;
    l_item->header.srv_uid = a_srv_uid;
    
    // Set auction bid specific fields
    l_item->subtype.srv_auction_bid.auction_hash = *a_auction_hash;
    l_item->subtype.srv_auction_bid.range_end = 1; // Default to 1
    l_item->subtype.srv_auction_bid.lock_time = a_lock_time;
    l_item->subtype.srv_auction_bid.project_id = a_project_id;
    
    // Copy additional parameters if provided
    if (a_params && a_params_size) {
        l_item->tsd_size = (uint32_t)a_params_size;
        memcpy(l_item->tsd, a_params, a_params_size);
    }
    
    return l_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_wallet_shared(dap_chain_srv_uid_t a_srv_uid, uint256_t a_value,
                                                                                   uint32_t a_signs_min, dap_hash_fast_t *a_pkey_hashes,
                                                                                   size_t a_pkey_hashes_count, const char *a_tag_str)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    size_t l_tsd_total_size = a_pkey_hashes_count * (sizeof(dap_hash_fast_t) + sizeof(dap_tsd_t)) + (a_tag_str ? sizeof(dap_tsd_t) + strlen(a_tag_str) + 1 : 0);
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + l_tsd_total_size, NULL);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.wallet_shared.signers_minimum = a_signs_min;
    l_item->tsd_size = l_tsd_total_size;
    byte_t *l_next_tsd_ptr = l_item->tsd;
    for (size_t i = 0; i < a_pkey_hashes_count; i++)
        l_next_tsd_ptr = dap_tsd_write(l_next_tsd_ptr, DAP_CHAIN_TX_OUT_COND_TSD_HASH, a_pkey_hashes + i, sizeof(dap_hash_fast_t));
    if (a_tag_str)
        l_next_tsd_ptr = dap_tsd_write(l_next_tsd_ptr, DAP_CHAIN_TX_OUT_COND_TSD_STR, (const void*)a_tag_str, strlen(a_tag_str) + 1);
    return l_item;
}

dap_chain_tx_sig_t *dap_chain_tx_sig_create(const dap_sign_t *a_sign)
{
    dap_return_val_if_fail(a_sign, NULL);
    size_t l_chain_sign_size = dap_sign_get_size((dap_sign_t *)a_sign); // sign data
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_sig_t,
                                                                  sizeof(dap_chain_tx_sig_t) + l_chain_sign_size, NULL);
    l_tx_sig->header.type = TX_ITEM_TYPE_SIG;
    l_tx_sig->header.version = 1;
    l_tx_sig->header.sig_size = (uint32_t)l_chain_sign_size;
    memcpy(l_tx_sig->sig, a_sign, l_chain_sign_size);
    return l_tx_sig;
}

dap_chain_tx_sig_t *dap_chain_datum_tx_item_sign_create_from_sign(const dap_sign_t *a_sign)
{
    dap_return_val_if_fail(a_sign, NULL);
    size_t l_chain_sign_size = dap_sign_get_size((dap_sign_t *)a_sign); // sign data
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_sig_t,
                                                                  sizeof(dap_chain_tx_sig_t) + l_chain_sign_size, NULL);
    l_tx_sig->header.type = TX_ITEM_TYPE_SIG;
    l_tx_sig->header.version = 1;
    l_tx_sig->header.sig_size = (uint32_t)l_chain_sign_size;
    memcpy(l_tx_sig->sig, a_sign, l_chain_sign_size);
    return l_tx_sig;
}

dap_sign_t *dap_chain_datum_tx_sign_create(dap_enc_key_t *a_key, const dap_chain_datum_tx_t *a_tx)
{
    dap_return_val_if_fail(a_key && a_tx, NULL);
    uint8_t *l_tx_sig_present = dap_chain_datum_tx_item_get(a_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    size_t l_tx_size = sizeof(dap_chain_datum_tx_t) +
                                  (l_tx_sig_present ? (size_t)(l_tx_sig_present - a_tx->tx_items)
                                                    : a_tx->header.tx_items_size);
    dap_chain_datum_tx_t *l_tx = DAP_DUP_SIZE_RET_VAL_IF_FAIL((dap_chain_datum_tx_t *)a_tx, l_tx_size, NULL);
    l_tx->header.tx_items_size = 0;
    dap_sign_t *ret = dap_sign_create(a_key, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    return ret;
}

/**
 * Create item dap_chain_tx_sig_t
 *
 * return item, NULL Error
 */
dap_chain_tx_sig_t *dap_chain_datum_tx_item_sign_create(dap_enc_key_t *a_key, const dap_chain_datum_tx_t *a_tx)
{
    dap_return_val_if_fail(a_key && a_tx, NULL);
    dap_sign_t *l_chain_sign = dap_chain_datum_tx_sign_create(a_key, a_tx);
    if (!l_chain_sign)
        return NULL;
    dap_chain_tx_sig_t *ret = dap_chain_datum_tx_item_sign_create_from_sign(l_chain_sign);
    DAP_DELETE(l_chain_sign);
    return ret;
}

/**
 * Get sign from sign item
 *
 * return sign, NULL Error
 */
dap_sign_t *dap_chain_datum_tx_item_sig_get_sign(dap_chain_tx_sig_t *a_tx_sig)
{
    return a_tx_sig && a_tx_sig->header.sig_size > sizeof(dap_sign_t) &&
            a_tx_sig->header.sig_size == dap_sign_get_size((dap_sign_t*)a_tx_sig->sig)
            ? (dap_sign_t*)a_tx_sig->sig
            : NULL;
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

dap_chain_tx_item_event_t *dap_chain_datum_tx_event_create(dap_chain_srv_uid_t a_srv_uid, const char *a_group_name, uint16_t a_type, dap_time_t a_timestamp)
{
    dap_return_val_if_fail(a_group_name, NULL);
    size_t l_group_name_size = strlen(a_group_name);
    if (l_group_name_size > UINT16_MAX)
        return NULL;
    dap_chain_tx_item_event_t *l_event = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_tx_item_event_t, sizeof(dap_chain_tx_item_event_t) + l_group_name_size, NULL);
    memcpy(l_event->group_name, a_group_name, l_group_name_size);
    l_event->type = TX_ITEM_TYPE_EVENT;
    l_event->version = DAP_CHAIN_TX_EVENT_VERSION;
    l_event->group_name_size = (uint16_t)l_group_name_size;
    l_event->event_type = a_type;
    l_event->timestamp = a_timestamp;
    l_event->srv_uid = a_srv_uid;
    return l_event;
}
void dap_chain_tx_event_delete(void *a_event)
{
    dap_chain_tx_event_t *l_event = a_event;
    DAP_DEL_MULTY(l_event->group_name, l_event->event_data, l_event);
}

dap_chain_tx_event_t *dap_chain_tx_event_copy(dap_chain_tx_event_t *a_event)
{
    dap_return_val_if_fail(a_event, NULL);
    dap_chain_tx_event_t *l_event = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_tx_event_t, NULL);
    *l_event = *a_event;
    l_event->group_name = dap_strdup(a_event->group_name);
    if (!l_event->group_name) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_event);
        return NULL;
    }
    l_event->event_data = DAP_DUP_SIZE(a_event->event_data, a_event->event_data_size);
    if (!l_event->event_data) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DEL_MULTY(l_event->group_name, l_event);
        return NULL;
    }
    return l_event;
}

int dap_chain_datum_tx_item_event_to_json(dap_json_t *a_json_obj, dap_chain_tx_item_event_t *a_event)
{
    dap_return_val_if_fail(a_json_obj && a_event, -1);
    dap_json_t *l_object = a_json_obj;
    char l_timestamp_str[DAP_TIME_STR_SIZE] = {0};
    dap_time_to_str_rfc822(l_timestamp_str, DAP_TIME_STR_SIZE, a_event->timestamp);
    dap_json_object_add_object(l_object, "timestamp", dap_json_object_new_string(l_timestamp_str));
    dap_json_object_add_object(l_object, "srv_uid", dap_json_object_new_uint64(a_event->srv_uid.uint64));
    dap_json_object_add_object(l_object, "event_type", dap_json_object_new_string(dap_chain_tx_item_event_type_to_str(a_event->event_type)));
    dap_json_object_add_object(l_object, "event_version", dap_json_object_new_int(a_event->version));
    dap_json_object_add_object(l_object, "event_group", dap_json_object_new_string((char *)a_event->group_name));
    return 0;
}

int dap_chain_datum_tx_event_to_json(dap_json_t *a_json_obj, dap_chain_tx_event_t *a_event, const char *a_hash_out_type)
{
    dap_return_val_if_fail(a_json_obj && a_event, -1);
    dap_json_t *l_object = a_json_obj;
    char l_timestamp_str[DAP_TIME_STR_SIZE] = {0};
    dap_time_to_str_rfc822(l_timestamp_str, DAP_TIME_STR_SIZE, a_event->timestamp);
    dap_json_object_add_object(l_object, "timestamp", dap_json_object_new_string(l_timestamp_str));
    dap_json_object_add_object(l_object, "srv_uid", dap_json_object_new_uint64(a_event->srv_uid.uint64));
    dap_json_object_add_object(l_object, "event_type", dap_json_object_new_string(dap_chain_tx_item_event_type_to_str(a_event->event_type)));
    dap_json_object_add_object(l_object, "event_group", dap_json_object_new_string(a_event->group_name));
    const char *l_tx_hash_str = dap_strcmp(a_hash_out_type, "hex") ? dap_enc_base58_encode_hash_to_str_static(&a_event->tx_hash)
                                                                   : dap_chain_hash_fast_to_str_static(&a_event->tx_hash);
    dap_json_object_add_object(l_object, "tx_hash", dap_json_object_new_string(l_tx_hash_str));
    const char *l_pkey_hash_str = dap_strcmp(a_hash_out_type, "hex") ? dap_enc_base58_encode_hash_to_str_static(&a_event->pkey_hash)
                                                                     : dap_hash_fast_to_str_static(&a_event->pkey_hash);
    dap_json_object_add_object(l_object, "pkey_hash", dap_json_object_new_string(l_pkey_hash_str));
    dap_json_object_add_object(l_object, "data_size", dap_json_object_new_int64(a_event->event_data_size));
    if (a_event->event_data && a_event->event_data_size > 0) {
        const size_t l_print_size_max = 32;
        size_t l_print_size = a_event->event_data_size > l_print_size_max ? l_print_size_max : a_event->event_data_size;
        char *l_data_hex = DAP_NEW_Z_SIZE(char, l_print_size * 2 + 1);
        if (l_data_hex) {
            dap_bin2hex(l_data_hex, a_event->event_data, l_print_size);
            dap_json_object_add_object(l_object, "data_hex", dap_json_object_new_string(l_data_hex));
            DAP_DELETE(l_data_hex);
        }
        if (a_event->event_data_size > l_print_size_max)
            for (size_t i = l_print_size; i > l_print_size - 3; i--)
                l_data_hex[i] = '.';
    }
    return 0;
}
