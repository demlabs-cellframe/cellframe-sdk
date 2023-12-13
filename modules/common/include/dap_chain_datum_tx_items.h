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
#pragma once

#include <stdint.h>
#include <string.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_list.h"
#include "dap_chain_common.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_out_ext.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_in_ems.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_datum_tx_in_reward.h"

/**
 * Get item type
 *
 * return type, or TX_ITEM_TYPE_ANY if error
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_get_type(const void *a_item);

typedef struct dap_chain_datum_tx_item
{
    dap_chain_tx_item_type_t type;
    byte_t data[];
} DAP_ALIGN_PACKED dap_chain_datum_tx_item_t;

/**
 * Get item name by item type
 *
 * return name, or UNDEFINED
 */
DAP_STATIC_INLINE const char * dap_chain_datum_tx_item_type_to_str(dap_chain_tx_item_type_t a_item_type)
{
    switch(a_item_type){
        case TX_ITEM_TYPE_IN: return "TX_ITEM_TYPE_IN";
        case TX_ITEM_TYPE_OUT_OLD: return "TX_ITEM_TYPE_OUT_OLD";
        case TX_ITEM_TYPE_OUT: return "TX_ITEM_TYPE_OUT"; // 256
        case TX_ITEM_TYPE_OUT_EXT: return "TX_ITEM_TYPE_OUT_EXT"; // 256
        case TX_ITEM_TYPE_PKEY: return "TX_ITEM_TYPE_PKEY";
        case TX_ITEM_TYPE_SIG: return "TX_ITEM_TYPE_SIG";
        case TX_ITEM_TYPE_IN_EMS: return "TX_ITEM_TYPE_IN_EMS";
        case TX_ITEM_TYPE_IN_REWARD: return "TX_ITEM_TYPE_IN_REWARD";
        case TX_ITEM_TYPE_IN_COND: return "TX_ITEM_TYPE_IN_COND";
        case TX_ITEM_TYPE_OUT_COND: return "TX_ITEM_TYPE_OUT_COND"; // 256
        case TX_ITEM_TYPE_RECEIPT: return "TX_ITEM_TYPE_RECEIPT";
        case TX_ITEM_TYPE_TSD: return "TX_ITEM_TYPE_TSD";
        default: return "UNDEFINED";
    }
}

/**
 * Get item type by item name
 *
 * return type, or TX_ITEM_TYPE_UNKNOWN
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_str_to_type(const char *a_datum_name);

/**
 * Get dap_chain_tx_out_cond_subtype_t by name
 *
 * return subtype, or DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED
 */
dap_chain_tx_out_cond_subtype_t dap_chain_tx_out_cond_subtype_from_str(const char *a_subtype_str);

/**
 * Get item size
 *
 * return size, 0 Error
 */
size_t dap_chain_datum_item_tx_get_size(const void *a_item);

/**
 * Create item dap_chain_tx_in_ems_t
 *
 * return item, NULL Error
 */
dap_chain_tx_in_ems_t *dap_chain_datum_tx_item_in_ems_create(dap_chain_id_t a_id, dap_chain_hash_fast_t *a_datum_token_hash, const char *a_ticker);

json_object *dap_chain_datum_tx_item_in_ems_to_json(const dap_chain_tx_in_ems_t *a_in_ems);

/**
 * Create item dap_chain_tx_out_old_t
 *
 * return item, NULL Error
 */
dap_chain_tx_in_t* dap_chain_datum_tx_item_in_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx);

dap_chain_tx_in_reward_t *dap_chain_datum_tx_item_in_reward_create(dap_chain_hash_fast_t *a_block_hash);

json_object* dap_chain_datum_tx_item_in_to_json(dap_chain_tx_in_t *a_in);

dap_chain_tx_tsd_t *dap_chain_datum_tx_item_tsd_create(void *a_data, int a_type, size_t a_size);

json_object* dap_chain_datum_tx_item_tsd_to_json(dap_chain_tx_tsd_t *a_tsd);


dap_chain_tx_in_cond_t* dap_chain_datum_tx_item_in_cond_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx,
                                                               uint32_t a_receipt_idx);

json_object* dap_chain_datum_tx_item_in_cond_to_json(dap_chain_tx_in_cond_t *a_in_cond);

/**
 * Create item dap_chain_tx_out_old_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_t* dap_chain_datum_tx_item_out_create(const dap_chain_addr_t *a_addr, uint256_t a_value);

json_object* dap_chain_datum_tx_item_out_to_json(const dap_chain_tx_out_t *a_out);

/**
 * Create item dap_chain_tx_out_ext_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_ext_t* dap_chain_datum_tx_item_out_ext_create(const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token);

json_object* dap_chain_datum_tx_item_out_ext_to_json(const dap_chain_tx_out_ext_t *a_out_ext);

/**
 * Create item dap_chain_tx_out_cond_t with fee subtype
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_fee(uint256_t a_value);

json_object *dap_chain_datum_tx_item_out_cond_fee_to_json(dap_chain_tx_out_cond_t *a_fee);

/**
 * Create item dap_chain_tx_out_cond_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t* dap_chain_datum_tx_item_out_cond_create_srv_pay(dap_pkey_t *a_key, dap_chain_net_srv_uid_t a_srv_uid,
                                                                             uint256_t a_value, uint256_t a_value_max_per_unit,
                                                                             dap_chain_net_srv_price_unit_uid_t a_unit,
                                                                             const void *a_params, size_t a_params_size);

json_object *dap_chain_datum_tx_item_out_cond_srv_pay_to_json(dap_chain_tx_out_cond_t *a_srv_pay);

/**
 * Create item dap_chain_tx_out_cond_t for eXchange service
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_xchange(dap_chain_net_srv_uid_t a_srv_uid, dap_chain_net_id_t a_sell_net_id,
                                                                             uint256_t a_value_sell, dap_chain_net_id_t a_buy_net_id,
                                                                             const char *a_token, uint256_t a_value_buy, const dap_chain_addr_t *a_seller_addr,
                                                                             const void *a_params, uint32_t a_params_size);

json_object* dap_chain_datum_tx_item_out_cond_srv_xchange_to_json(dap_chain_tx_out_cond_t* a_srv_xchange);

/**
 * Create item dap_chain_tx_out_cond_t for stake service
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake(dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value,
                                                                               dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_signer_node_addr);

json_object *dap_chain_datum_tx_item_out_cond_srv_stake_to_json(dap_chain_tx_out_cond_t* a_srv_stake);

// Create cond out
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(dap_chain_net_srv_uid_t a_srv_uid,
                                                                                  uint256_t a_value, uint64_t a_time_staking,
                                                                                  uint256_t a_reinvest_percent);

json_object *dap_chain_net_srv_stake_lock_cond_out_to_json(dap_chain_tx_out_cond_t *a_stake_lock);


/**
 * Create item dap_chain_tx_sig_t
 *
 * return item, NULL Error
 */
dap_chain_tx_sig_t *dap_chain_datum_tx_item_sign_create(dap_enc_key_t *a_key, const void *a_data, size_t a_data_size);

json_object* dap_chain_datum_tx_item_sig_to_json(const dap_chain_tx_sig_t *a_sig);

/**
 * Get sign from sign item
 *
 * return sign, NULL Error
 */
dap_sign_t *dap_chain_datum_tx_item_sign_get_sig(dap_chain_tx_sig_t *a_tx_sig);

byte_t *dap_chain_datum_tx_item_get_data(dap_chain_tx_tsd_t *a_tx_tsd, int *a_type, size_t *a_size);

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
        dap_chain_tx_item_type_t a_type, int *a_item_out_size);
// Get Nth item of pointed type
uint8_t *dap_chain_datum_tx_item_get_nth(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int a_item_idx);
// Get all item from transaction by type
dap_list_t* dap_chain_datum_tx_items_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int *a_item_count);
// Get conditional out item with it's idx
dap_chain_tx_out_cond_t *dap_chain_datum_tx_out_cond_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_cond_type, int *a_out_num);
