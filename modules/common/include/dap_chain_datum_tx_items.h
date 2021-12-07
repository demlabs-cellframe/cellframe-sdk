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
//#include <glib.h>

#include "dap_common.h"
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
#include "dap_chain_datum_tx_token.h"
#include "dap_chain_datum_tx_receipt.h"

/**
 * Get item type
 *
 * return type, or TX_ITEM_TYPE_ANY if error
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_get_type(const uint8_t *a_item);
DAP_STATIC_INLINE const char * dap_chain_datum_tx_item_type_to_str(dap_chain_tx_item_type_t a_item_type)
{
    switch(a_item_type){
        case TX_ITEM_TYPE_IN: return "TX_ITEM_TYPE_IN";
        case TX_ITEM_TYPE_OUT: return "TX_ITEM_TYPE_OUT";
        case TX_ITEM_TYPE_OUT_EXT: return "TX_ITEM_TYPE_OUT_EXT";
        case TX_ITEM_TYPE_PKEY: return "TX_ITEM_TYPE_PKEY";
        case TX_ITEM_TYPE_SIG: return "TX_ITEM_TYPE_SIG";
        case TX_ITEM_TYPE_TOKEN: return "TX_ITEM_TYPE_TOKEN";
        case TX_ITEM_TYPE_TOKEN_EXT: return "TX_ITEM_TYPE_TOKEN_EXT";
        case TX_ITEM_TYPE_IN_COND: return "TX_ITEM_TYPE_IN_COND";
        case TX_ITEM_TYPE_OUT_COND: return "TX_ITEM_TYPE_OUT_COND";
        case TX_ITEM_TYPE_RECEIPT: return "TX_ITEM_TYPE_RECEIPT";
        case TX_ITEM_TYPE_OUT_ALL: return "TX_ITEM_TYPE_OUT_ALL";
        case TX_ITEM_TYPE_ANY: return "TX_ITEM_TYPE_ANY";
        default: return "UNDEFINED";
    }

}

/**
 * Get item size
 *
 * return size, 0 Error
 */
size_t dap_chain_datum_item_tx_get_size(const uint8_t *a_item);

/**
 * Create item dap_chain_tx_token_t
 *
 * return item, NULL Error
 */
dap_chain_tx_token_t* dap_chain_datum_tx_item_token_create(dap_chain_hash_fast_t * a_datum_token_hash,const char * a_ticker);

/**
 * Create item dap_chain_tx_out_t
 *
 * return item, NULL Error
 */
dap_chain_tx_in_t* dap_chain_datum_tx_item_in_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx);


dap_chain_tx_in_cond_t* dap_chain_datum_tx_item_in_cond_create(dap_chain_hash_fast_t *a_tx_prev_hash, uint32_t a_tx_out_prev_idx,
                                                               uint32_t a_receipt_idx);
/**
 * Create item dap_chain_tx_out_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_t* dap_chain_datum_tx_item_out_create(const dap_chain_addr_t *a_addr, uint64_t a_value);

/**
 * Create item dap_chain_tx_out_ext_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_ext_t* dap_chain_datum_tx_item_out_ext_create(const dap_chain_addr_t *a_addr, uint64_t a_value, const char *a_token);

/**
 * Create item dap_chain_tx_out_cond_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t* dap_chain_datum_tx_item_out_cond_create_srv_pay(dap_enc_key_t *a_key, dap_chain_net_srv_uid_t a_srv_uid,
        uint64_t a_value, uint64_t a_value_max_per_unit, dap_chain_net_srv_price_unit_uid_t a_unit,
                                                                 const void *a_cond, size_t a_cond_size);
/**
 * Create item dap_chain_tx_out_cond_t for eXchange service
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t* dap_chain_datum_tx_item_out_cond_create_srv_xchange(dap_chain_net_srv_uid_t a_srv_uid,
                                                                             dap_chain_net_id_t a_net_id, const char *a_token, uint64_t a_value,
                                                                             const void *a_params, uint32_t a_params_size);

/**
 * Create item dap_chain_tx_out_cond_t for stake service
 *
 * return item, NULL Error
 */
dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake(dap_chain_net_srv_uid_t a_srv_uid, uint64_t a_value, long double a_fee_value,
                                                                           dap_chain_addr_t *a_fee_addr, dap_chain_addr_t *a_hldr_addr,
                                                                           const void *a_params, uint32_t a_params_size);
/**
 * Create item dap_chain_tx_sig_t
 *
 * return item, NULL Error
 */
dap_chain_tx_sig_t* dap_chain_datum_tx_item_sign_create(dap_enc_key_t *a_key, const void *a_data, size_t a_data_size);

/**
 * Get sign from sign item
 *
 * return sign, NULL Error
 */
dap_sign_t* dap_chain_datum_tx_item_sign_get_sig(dap_chain_tx_sig_t *a_tx_sig);

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

// Get all item from transaction by type
dap_list_t* dap_chain_datum_tx_items_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int *a_item_count);
// Get conditional out item with it's idx
dap_chain_tx_out_cond_t *dap_chain_datum_tx_out_cond_get(dap_chain_datum_tx_t *a_tx, int *a_out_num);
