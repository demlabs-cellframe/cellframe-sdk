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

static size_t dap_chain_tx_out_get_size(const dap_chain_tx_out_old_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_out_old_t);
    return size;
}

// 256
static size_t dap_chain_256_tx_out_get_size(const dap_chain_tx_out_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_out_t);
    return size;
}

// 256
static size_t dap_chain_tx_out_ext_get_size(const dap_chain_tx_out_ext_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_out_ext_t);
    return size;
}

static size_t dap_chain_tx_out_cond_get_size(const dap_chain_tx_out_cond_t *a_item)
{
    return sizeof(dap_chain_tx_out_cond_t) + a_item->tsd_size;
}

static size_t dap_chain_tx_pkey_get_size(const dap_chain_tx_pkey_t *a_item)
{
    size_t size = sizeof(dap_chain_tx_pkey_t) + a_item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_sig_get_size(const dap_chain_tx_sig_t *a_item)
{
    size_t size = sizeof(dap_chain_tx_sig_t) + a_item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_token_get_size(const dap_chain_tx_token_t *a_item)
{
    (void) a_item;
    size_t size = sizeof(dap_chain_tx_token_t);
    return size;
}

static size_t dap_chain_datum_tx_receipt_get_size(const dap_chain_datum_tx_receipt_t *a_item)
{
    size_t size = a_item->size;
    return size;
}

static size_t dap_chain_tx_tsd_get_size(const dap_chain_tx_tsd_t *a_item)
{
    return sizeof(dap_chain_tx_tsd_t) + a_item->header.size;
}

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
    else if(!dap_strcmp(a_datum_name, "out"))
        return TX_ITEM_TYPE_OUT;
    else if(!dap_strcmp(a_datum_name, "out_ext"))
        return TX_ITEM_TYPE_OUT_EXT;
    else if(!dap_strcmp(a_datum_name, "pkey"))
        return TX_ITEM_TYPE_PKEY;
    else if(!dap_strcmp(a_datum_name, "sign"))
        return TX_ITEM_TYPE_SIG;
    else if(!dap_strcmp(a_datum_name, "token"))
        return TX_ITEM_TYPE_TOKEN;
    else if(!dap_strcmp(a_datum_name, "in_cond"))
        return TX_ITEM_TYPE_IN_COND;
    else if(!dap_strcmp(a_datum_name, "out_cond"))
        return TX_ITEM_TYPE_OUT_COND;
    else if(!dap_strcmp(a_datum_name, "receipt"))
        return TX_ITEM_TYPE_RECEIPT;
    else if(!dap_strcmp(a_datum_name, "data"))
        return TX_ITEM_TYPE_TSD;
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
    else if(!dap_strcmp(a_subtype_str, "srv_stake_lock"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK;
    else if(!dap_strcmp(a_subtype_str, "fee"))
        return DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE;
    return DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED;
}

/**
 * Get item type
 *
 * return type, or TX_ITEM_TYPE_ANY if error
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_get_type(const void *a_item)
{
    dap_chain_tx_item_type_t type = a_item ? *(dap_chain_tx_item_type_t *)a_item : TX_ITEM_TYPE_ANY;
    return type;
}

/**
 * Get item size
 *
 * return size, 0 Error
 */
size_t dap_chain_datum_item_tx_get_size(const void *a_item)
{
    dap_chain_tx_item_type_t type = dap_chain_datum_tx_item_get_type(a_item);
    size_t size = 0;
    switch (type) {
    case TX_ITEM_TYPE_IN: // Transaction inputs
        size = dap_chain_tx_in_get_size((const dap_chain_tx_in_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT_OLD: // Transaction outputs
        size = dap_chain_tx_out_get_size((const dap_chain_tx_out_old_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT: // 256
        size = dap_chain_256_tx_out_get_size((const dap_chain_tx_out_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT_EXT: // Exchange transaction outputs
        size = dap_chain_tx_out_ext_get_size((const dap_chain_tx_out_ext_t*) a_item);
        break;
    case TX_ITEM_TYPE_RECEIPT: // Receipt
        size = dap_chain_datum_tx_receipt_get_size((const dap_chain_datum_tx_receipt_t *)a_item);
        break;
    case TX_ITEM_TYPE_IN_COND: // Transaction inputs with condition
        size = dap_chain_tx_in_cond_get_size((const dap_chain_tx_in_cond_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT_COND_OLD: // Transaction output with condition
        size = 0; // obsolete dap_chain_tx_out_cond_get_size((const dap_chain_tx_out_cond_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT_COND: // 256
        size = dap_chain_tx_out_cond_get_size((const dap_chain_tx_out_cond_t *)a_item);
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
    case TX_ITEM_TYPE_TSD:
        size = dap_chain_tx_tsd_get_size((const dap_chain_tx_tsd_t*)a_item);
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
dap_chain_tx_token_t *dap_chain_datum_tx_item_token_create(dap_chain_id_t a_id, dap_chain_hash_fast_t *a_datum_token_hash, const char *a_ticker)
{
    if(!a_ticker)
        return NULL;
    dap_chain_tx_token_t *l_item = DAP_NEW_Z(dap_chain_tx_token_t);
    l_item->header.type = TX_ITEM_TYPE_TOKEN;
    l_item->header.token_emission_chain_id.uint64 = a_id.uint64;
    l_item->header.token_emission_hash = *a_datum_token_hash;
    strncpy(l_item->header.ticker, a_ticker, sizeof(l_item->header.ticker) - 1);
    return l_item;
}

json_object *dap_chain_datum_tx_item_token_to_json(const dap_chain_tx_token_t *a_token){
    json_object *l_object = json_object_new_object();
    json_object *l_obj_ticker = json_object_new_string(a_token->header.ticker);
    json_object *l_obj_chain_id = json_object_new_uint64(a_token->header.token_emission_chain_id.uint64);
    char *l_ehf = dap_chain_hash_fast_to_str_new(&a_token->header.token_emission_hash);
    json_object *l_obj_ehf = json_object_new_string(l_ehf);
    DAP_DELETE(l_ehf);
    json_object_object_add(l_object, "ticker", l_obj_ticker);
    json_object_object_add(l_object, "chainId", l_obj_chain_id);
    json_object_object_add(l_object, "emissionHash", l_obj_ehf);
    return l_object;
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
    l_item->header.type = TX_ITEM_TYPE_IN;
    l_item->header.tx_out_prev_idx = a_tx_out_prev_idx;
    l_item->header.tx_prev_hash = *a_tx_prev_hash;
    return l_item;
}

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

json_object* dap_chain_datum_tx_item_in_to_json(dap_chain_tx_in_t *a_in){
    json_object *l_obj_in = json_object_new_object();
    json_object *l_obj_prev_idx = json_object_new_uint64(a_in->header.tx_out_prev_idx);
    char *l_hash = dap_chain_hash_fast_to_str_new(&a_in->header.tx_prev_hash);
    json_object *l_obj_hash = json_object_new_string(l_hash);
    DAP_DELETE(l_hash);
    json_object_object_add(l_obj_in, "prev_idx", l_obj_prev_idx);
    json_object_object_add(l_obj_in, "prev_hash", l_obj_hash);
    return l_obj_in;
}

json_object* dap_chain_datum_tx_item_tsd_to_json(dap_chain_tx_tsd_t *a_tsd){
    json_object *l_object = json_object_new_object();
    json_object *l_obj_tsd_type = json_object_new_int(a_tsd->header.type);
    json_object *l_obj_tsd_size = json_object_new_uint64(a_tsd->header.size);
    json_object *l_obj_data = json_object_new_string_len(a_tsd->tsd, a_tsd->header.size);
    json_object_object_add(l_object, "type", l_obj_tsd_type);
    json_object_object_add(l_object, "size", l_obj_tsd_size);
    json_object_object_add(l_object, "data", l_obj_data);
    return l_object;
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
    l_item->header.tx_prev_hash = *a_tx_prev_hash;
    return l_item;
}

json_object* dap_chain_datum_tx_item_in_cond_to_json(dap_chain_tx_in_cond_t *a_in_cond){
    json_object *l_obj = json_object_new_object();
    json_object *l_obj_receipt_idx = json_object_new_uint64(a_in_cond->header.receipt_idx);
    json_object *l_obj_out_prev_idx = json_object_new_uint64(a_in_cond->header.tx_out_prev_idx);
    json_object *l_obj_prev_hash = NULL;
    if (dap_hash_fast_is_blank(&a_in_cond->header.tx_prev_hash)){
        l_obj_prev_hash = json_object_new_null();
    } else {
        char *l_prev_hash = dap_hash_fast_to_str_new(&a_in_cond->header.tx_prev_hash);
        l_obj_prev_hash = json_object_new_string(dap_strdup(l_prev_hash));
        DAP_DELETE(l_prev_hash);
    }
    json_object_object_add(l_obj, "receiptIdx", l_obj_receipt_idx);
    json_object_object_add(l_obj, "outPrevIdx", l_obj_out_prev_idx);
    json_object_object_add(l_obj, "txPrevHash", l_obj_prev_hash);
    return l_obj;
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
    l_item->addr = *a_addr;
    l_item->header.type = TX_ITEM_TYPE_OUT;
    l_item->header.value = a_value;
    return l_item;
}

json_object* dap_chain_datum_tx_item_out_to_json(const dap_chain_tx_out_t *a_out) {
    json_object *l_object = json_object_new_object();
    json_object *l_value = json_object_new_string(dap_chain_balance_print(a_out->header.value));
    json_object *l_addr = dap_chain_addr_to_json(&a_out->addr);
    json_object_object_add(l_object, "value", l_value);
    json_object_object_add(l_object, "addr", l_addr);
    return l_object;
}

dap_chain_tx_out_ext_t* dap_chain_datum_tx_item_out_ext_create(const dap_chain_addr_t *a_addr, uint256_t a_value, const char *a_token)
{
    if (!a_addr || !a_token)
        return NULL;
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_ext_t *l_item = DAP_NEW_Z(dap_chain_tx_out_ext_t);
    l_item->header.type = TX_ITEM_TYPE_OUT_EXT;
    l_item->header.value = a_value;
    l_item->addr = *a_addr;
    strcpy(l_item->token, a_token);
    return l_item;
}

json_object* dap_chain_datum_tx_item_out_ext_to_json(const dap_chain_tx_out_ext_t *a_out_ext) {
    json_object *l_obj = json_object_new_object();
    char *l_value = dap_chain_balance_print(a_out_ext->header.value);
    json_object *l_obj_value = json_object_new_string(l_value);
    DAP_DELETE(l_value);
    json_object *l_obj_addr = dap_chain_addr_to_json(&a_out_ext->addr);
    json_object *l_obj_token = json_object_new_string(a_out_ext->token);
    json_object_object_add(l_obj, "value", l_obj_value);
    json_object_object_add(l_obj, "addr", l_obj_addr);
    json_object_object_add(l_obj, "token", l_obj_token);
    return l_obj;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_fee(uint256_t a_value)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE;
    return l_item;
}

json_object *dap_chain_datum_tx_item_out_cond_fee_to_json(dap_chain_tx_out_cond_t *a_fee){
    if (a_fee->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE) {
        json_object *l_obj = json_object_new_object();
        char *l_balance = dap_chain_balance_print(a_fee->header.value);
        json_object *l_obj_balance = json_object_new_string(l_balance);
        DAP_DELETE(l_balance);
        json_object_object_add(l_obj, "balance", l_obj_balance);
        return l_obj;
    }
    return NULL;
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
    if (!a_key || !a_key->pkey[0])
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

json_object *dap_chain_datum_tx_item_out_cond_srv_pay_to_json(dap_chain_tx_out_cond_t *a_srv_pay) {
    if (a_srv_pay->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY) {
        json_object *l_obj = json_object_new_object();
        char *l_balance = dap_chain_balance_print(a_srv_pay->header.value);
        json_object *l_obj_value = json_object_new_string(l_balance);
        DAP_DELETE(l_balance);
        json_object_object_add(l_obj, "value", l_obj_value);
        json_object *l_obj_srv_uid = json_object_new_uint64(a_srv_pay->header.srv_uid.uint64);
        json_object_object_add(l_obj, "srvUid", l_obj_srv_uid);
        serv_unit_enum_t l_service_unit = a_srv_pay->subtype.srv_pay.unit.enm;
        json_object *l_obj_units_type = json_object_new_string(serv_unit_enum_to_str(&l_service_unit));
        json_object_object_add(l_obj, "srvUnit", l_obj_units_type);
        char *l_price_max_datoshi = dap_chain_balance_print(a_srv_pay->subtype.srv_pay.unit_price_max_datoshi);
        json_object *l_obj_price_max_datoshi = json_object_new_string(l_price_max_datoshi);
        DAP_DELETE(l_price_max_datoshi);
        json_object_object_add(l_obj, "price", l_obj_price_max_datoshi);
        char *l_pkeyHash = dap_hash_fast_to_str_new(&a_srv_pay->subtype.srv_pay.pkey_hash);
        json_object *l_obj_pkey_hash = json_object_new_string(l_pkeyHash);
        DAP_DELETE(l_pkeyHash);
        json_object_object_add(l_obj, "pKeyHash", l_obj_pkey_hash);
        //TODO: Parsing a_srv_pay->tsd
//        json_object *l_obj_tsd = json_object_new_string_len(a_srv_pay->tsd, a_srv_pay->tsd_size);
//        json_object_object_add(l_obj, "TSD", l_obj_tsd);
        return l_obj;
    }
    return NULL;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_xchange(dap_chain_net_srv_uid_t a_srv_uid, dap_chain_net_id_t a_sell_net_id,
                                                                             uint256_t a_value_sell, dap_chain_net_id_t a_buy_net_id,
                                                                             const char *a_token, uint256_t a_value_buy,
                                                                             const dap_chain_addr_t *a_seller_addr,
                                                                             const void *a_params, uint32_t a_params_size)
{
    if (!a_token)
        return NULL;
    if (IS_ZERO_256(a_value_sell) || IS_ZERO_256(a_value_buy))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z_SIZE(dap_chain_tx_out_cond_t, sizeof(dap_chain_tx_out_cond_t) + a_params_size);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value_sell;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_xchange.buy_net_id = a_buy_net_id;
    l_item->subtype.srv_xchange.sell_net_id = a_sell_net_id;
    strncpy(l_item->subtype.srv_xchange.buy_token, a_token, DAP_CHAIN_TICKER_SIZE_MAX);
    l_item->subtype.srv_xchange.buy_value = a_value_buy;
    l_item->subtype.srv_xchange.seller_addr = *a_seller_addr;
    l_item->tsd_size = a_params_size;
    if (a_params_size) {
        memcpy(l_item->tsd, a_params, a_params_size);
    }
    return l_item;
}

json_object* dap_chain_datum_tx_item_out_cond_srv_xchange_to_json(dap_chain_tx_out_cond_t* a_srv_xchange){
    if (a_srv_xchange->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE){
        json_object *l_object = json_object_new_object();
        char *l_value = dap_chain_balance_print(a_srv_xchange->header.value);
        json_object *l_obj_value = json_object_new_string(l_value);
        DAP_DELETE(l_value);
        json_object *l_obj_srv_uid = json_object_new_uint64(a_srv_xchange->header.srv_uid.uint64);
        json_object *l_obj_buy_net_id = dap_chain_net_id_to_json(a_srv_xchange->subtype.srv_xchange.buy_net_id);
        json_object *l_obj_sell_net_id = dap_chain_net_id_to_json(a_srv_xchange->subtype.srv_xchange.sell_net_id);
        json_object *l_obj_buy_token = json_object_new_string(a_srv_xchange->subtype.srv_xchange.buy_token);
        char *l_value_buy = dap_chain_balance_print(a_srv_xchange->subtype.srv_xchange.buy_value);
        json_object *l_obj_value_buy = json_object_new_string(l_value_buy);
        DAP_DELETE(l_value_buy);
        json_object *l_obj_seller_addr = dap_chain_addr_to_json(&a_srv_xchange->subtype.srv_xchange.seller_addr);
        json_object_object_add(l_object, "value", l_obj_value);
        json_object_object_add(l_object, "valueBuy", l_obj_value_buy);
        json_object_object_add(l_object, "srvUID", l_obj_srv_uid);
        json_object_object_add(l_object, "buyNetId", l_obj_buy_net_id);
        json_object_object_add(l_object, "sellNetId", l_obj_sell_net_id);
        json_object_object_add(l_object, "buyToken", l_obj_buy_token);
        json_object_object_add(l_object, "sellerAddr", l_obj_seller_addr);
        //TODO: Parse TSD
        return l_object;
    }
    return NULL;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_item_out_cond_create_srv_stake(dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value, uint256_t a_fee_value,
                                                                           dap_chain_addr_t *a_fee_addr, dap_chain_addr_t *a_hldr_addr,
                                                                           dap_chain_addr_t *a_signing_addr, dap_chain_node_addr_t *a_signer_node_addr)
{
    if (IS_ZERO_256(a_value))
        return NULL;
    dap_chain_tx_out_cond_t *l_item = DAP_NEW_Z(dap_chain_tx_out_cond_t);
    l_item->header.item_type = TX_ITEM_TYPE_OUT_COND;
    l_item->header.value = a_value;
    l_item->header.subtype = DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE;
    l_item->header.srv_uid = a_srv_uid;
    l_item->subtype.srv_stake.fee_value = a_fee_value;
    l_item->subtype.srv_stake.fee_addr = *a_fee_addr;
    l_item->subtype.srv_stake.hldr_addr = *a_hldr_addr;
    l_item->subtype.srv_stake.signing_addr = *a_signing_addr;
    l_item->subtype.srv_stake.signer_node_addr = *a_signer_node_addr;
    return l_item;
}

json_object *dap_chain_datum_tx_item_out_cond_srv_stake_to_json(dap_chain_tx_out_cond_t* a_srv_stake) {
    if (a_srv_stake->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE) {
        json_object *l_object = json_object_new_object();
        char *l_value = dap_chain_balance_print(a_srv_stake->header.value);
        json_object *l_obj_value = json_object_new_string(l_value);
        DAP_DELETE(l_value);
        json_object *l_obj_srv_uid = json_object_new_uint64(a_srv_stake->header.srv_uid.uint64);
        char *l_value_fee = dap_chain_balance_print(a_srv_stake->subtype.srv_stake.fee_value);
        json_object *l_obj_value_fee = json_object_new_string(l_value_fee);
        DAP_DELETE(l_value_fee);
        json_object *l_obj_fee_addr = dap_chain_addr_to_json(&a_srv_stake->subtype.srv_stake.fee_addr);
        json_object *l_obj_hldr_addr = dap_chain_addr_to_json(&a_srv_stake->subtype.srv_stake.hldr_addr);
        json_object *l_obj_signing_addr = dap_chain_addr_to_json(&a_srv_stake->subtype.srv_stake.signing_addr);
        char *l_signer_node_addr = dap_strdup_printf(
                NODE_ADDR_FP_STR,
                NODE_ADDR_FP_ARGS_S(a_srv_stake->subtype.srv_stake.signer_node_addr));
        json_object *l_obj_signer_node_addr = json_object_new_string(l_signer_node_addr);
        DAP_DELETE(l_signer_node_addr);
        json_object_object_add(l_object, "value", l_obj_value);
        json_object_object_add(l_object, "srvUID", l_obj_srv_uid);
        json_object_object_add(l_object, "valueFee", l_obj_value_fee);
        json_object_object_add(l_object, "feeAddr", l_obj_fee_addr);
        json_object_object_add(l_object, "hldrAddr", l_obj_hldr_addr);
        json_object_object_add(l_object, "signindAddr", l_obj_signing_addr);
        json_object_object_add(l_object, "signerNodeAddr", l_obj_signer_node_addr);
        return l_object;
    }
    return NULL;
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

json_object* dap_chain_datum_tx_item_sig_to_json(const dap_chain_tx_sig_t *a_sig){
    json_object *l_object = json_object_new_object();
    json_object *l_sign_size = json_object_new_uint64(a_sig->header.sig_size);
    json_object *l_sign = dap_sign_to_json((dap_sign_t*)a_sig->sig);
    json_object_object_add(l_object, "signSize", l_sign_size);
    json_object_object_add(l_object, "sign", l_sign);
    return l_object;
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
        dap_chain_tx_item_type_t a_type, int *a_item_out_size)
{
    if(!a_tx)
        return NULL;
    uint32_t l_tx_items_pos = 0, l_tx_items_size = a_tx->header.tx_items_size;
    int l_item_idx = 0;
    while (l_tx_items_pos < l_tx_items_size) {
        uint8_t *l_item = a_tx->tx_items + l_tx_items_pos;
        int l_item_size = dap_chain_datum_item_tx_get_size(l_item);
        if(!l_item_size)
            return NULL;
        // check index
        if(!a_item_idx || l_item_idx >= *a_item_idx) {
            // check type
            dap_chain_tx_item_type_t l_type = dap_chain_datum_tx_item_get_type(l_item);
            if (a_type == TX_ITEM_TYPE_ANY || a_type == l_type ||
                    (a_type == TX_ITEM_TYPE_OUT_ALL && l_type == TX_ITEM_TYPE_OUT) ||
                    (a_type == TX_ITEM_TYPE_OUT_ALL && l_type == TX_ITEM_TYPE_OUT_OLD) ||
                    (a_type == TX_ITEM_TYPE_OUT_ALL && l_type == TX_ITEM_TYPE_OUT_COND) ||
                    (a_type == TX_ITEM_TYPE_OUT_ALL && l_type == TX_ITEM_TYPE_OUT_EXT) ||
                    (a_type == TX_ITEM_TYPE_IN_ALL && l_type == TX_ITEM_TYPE_IN) ||
                    (a_type == TX_ITEM_TYPE_IN_ALL && l_type == TX_ITEM_TYPE_IN_COND)) {
                if(a_item_idx)
                    *a_item_idx = l_item_idx;
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
	uint8_t *l_tx_item;

    // Get items from transaction
    while ((l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx_start, a_type, NULL)) != NULL)
    {
        items_list = dap_list_append(items_list, l_tx_item);
        l_items_count++;
        l_item_idx_start++;
    }

    if(a_item_count)
        *a_item_count = l_items_count;

    return items_list;
}

uint8_t *dap_chain_datum_tx_item_get_nth(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int a_item_idx)
{
    uint8_t *l_tx_item;
    int l_item_idx = 0;
    for (int l_type_idx = 0; l_type_idx <= a_item_idx; l_type_idx++) {
        l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx, a_type, NULL);
        if (!l_tx_item)
            break;
        l_item_idx++;
    }
    return l_tx_item;
}

dap_chain_tx_out_cond_t *dap_chain_datum_tx_out_cond_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_cond_type, int *a_out_num)
{
    dap_list_t *l_list_out_items = dap_chain_datum_tx_items_get(a_tx, TX_ITEM_TYPE_OUT_ALL, NULL);
    int l_prev_cond_idx = a_out_num ? *a_out_num : -1;
    dap_chain_tx_out_cond_t *l_res = NULL;
    int l_cur_cond_idx = -1;
    for (dap_list_t *l_list_tmp = l_list_out_items; l_list_tmp; l_list_tmp = l_list_tmp->next) {
        if (l_cur_cond_idx++ < l_prev_cond_idx)
            continue;
        l_prev_cond_idx++;
        if (*(uint8_t *)l_list_tmp->data == TX_ITEM_TYPE_OUT_COND &&
                ((dap_chain_tx_out_cond_t *)l_list_tmp->data)->header.subtype == a_cond_type) {
            l_res = l_list_tmp->data;
            break;
        }
    }
    dap_list_free(l_list_out_items);
    if (a_out_num && l_res) {
        *a_out_num = l_prev_cond_idx;
    }
    return l_res;
}
