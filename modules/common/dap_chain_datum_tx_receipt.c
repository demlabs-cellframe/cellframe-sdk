/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx_receipt.h"
#include "dap_json_rpc_errors.h"

#define LOG_TAG "dap_chain_datum_tx_receipt"

/**
 * @brief dap_chain_datum_tx_receipt_create
 * @param a_srv_uid
 * @param a_units_type
 * @param a_units
 * @param a_value_datoshi
 * @param a_ext
 * @param a_ext_size
 * @return
 */
dap_chain_datum_tx_receipt_t * dap_chain_datum_tx_receipt_create( dap_chain_net_srv_uid_t a_srv_uid,
                                                                  dap_chain_net_srv_price_unit_uid_t a_units_type,
                                                                    uint64_t a_units, uint256_t a_value_datoshi,
                                                                  const void * a_ext, size_t a_ext_size)
{

    dap_chain_datum_tx_receipt_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_datum_tx_receipt_t,
                                                         sizeof(dap_chain_datum_tx_receipt_t) + a_ext_size);
    l_ret->type = TX_ITEM_TYPE_RECEIPT;
    l_ret->receipt_info.units_type = a_units_type;
    l_ret->receipt_info.srv_uid = a_srv_uid;
    l_ret->receipt_info.units = a_units;
    l_ret->receipt_info.value_datoshi = a_value_datoshi;
    l_ret->size = sizeof(dap_chain_datum_tx_receipt_t) + a_ext_size;

    if (a_ext_size && a_ext) {
        l_ret->exts_size = a_ext_size;
        memcpy(l_ret->exts_n_signs, a_ext, a_ext_size);
    }
    return  l_ret;
}

dap_chain_datum_tx_receipt_t *dap_chain_datum_tx_receipt_sign_add(dap_chain_datum_tx_receipt_t *a_receipt, dap_enc_key_t *a_key)
{
    if (!a_receipt) {
        log_it(L_ERROR, "NULL receipt, can't add sign");
        return NULL;
    }
    dap_sign_t *l_sign = dap_sign_create(a_key, &a_receipt->receipt_info, sizeof(a_receipt->receipt_info), 0);
    size_t l_sign_size = l_sign ? dap_sign_get_size(l_sign) : 0;
    if (!l_sign || !l_sign_size) {
        log_it(L_ERROR, "Can't sign the receipt, may be smth with key?");
        return NULL;
    }
    dap_chain_datum_tx_receipt_t *l_receipt = (dap_chain_datum_tx_receipt_t *)
                                                DAP_REALLOC(a_receipt, a_receipt->size + l_sign_size);
    if (!l_receipt)
    {
        DAP_DELETE(l_sign);
        return NULL;
    }
    memcpy((byte_t *)l_receipt + l_receipt->size, l_sign, l_sign_size);
    l_receipt->size += l_sign_size;
    DAP_DELETE(l_sign);
    return l_receipt;
}

/**
 * @brief dap_chain_datum_tx_receipt_sign_get
 * @param l_receipt
 * @param a_sign_position
 * @return
 */
dap_sign_t* dap_chain_datum_tx_receipt_sign_get(dap_chain_datum_tx_receipt_t * l_receipt, size_t l_receipt_size, uint16_t a_sign_position)
{
    if (!l_receipt ||  l_receipt_size != l_receipt->size ||
            l_receipt->size == sizeof(dap_chain_datum_tx_receipt_t) + l_receipt->exts_size)
        return NULL;
    dap_sign_t *l_sign = (dap_sign_t *)l_receipt->exts_n_signs + l_receipt->exts_size;
    uint16_t l_sign_position;
    for (l_sign_position = a_sign_position;
             l_sign_position && l_receipt_size > (size_t)((byte_t *)l_sign - (byte_t *)l_receipt);
             l_sign_position--) {
        l_sign = (dap_sign_t *)((byte_t *)l_sign + dap_sign_get_size(l_sign));
    }
    // not enough signs in receipt
    if (l_sign_position > 0)
        return NULL;
    // too big sign size
    if ((size_t)(l_sign->header.sign_size + ((byte_t *)l_sign - l_receipt->exts_n_signs)) >= l_receipt->size)
        return NULL;
    return l_sign;
}

uint32_t dap_chain_datum_tx_receipt_type_get(dap_chain_datum_tx_receipt_t * l_receipt)
{
    if (!l_receipt)
        return -1;
    return l_receipt->receipt_info.units_type.enm;
}
uint64_t    dap_chain_datum_tx_receipt_srv_uid_get(dap_chain_datum_tx_receipt_t * l_receipt)
{
    if (!l_receipt)
        return -1;
    return l_receipt->receipt_info.srv_uid.uint64;
}
uint64_t    dap_chain_datum_tx_receipt_units_get(dap_chain_datum_tx_receipt_t * l_receipt)
{
    if (!l_receipt)
        return -1;
    return l_receipt->receipt_info.units;
}
uint256_t   dap_chain_datum_tx_receipt_value_get(dap_chain_datum_tx_receipt_t * l_receipt)
{
    uint256_t res = {};
    if (!l_receipt)
        return res;
    return l_receipt->receipt_info.value_datoshi;
}

/**
 * @brief dap_chain_datum_tx_receipt_signs_count
 * @param a_receipt
 * @param a_receipt_size
 * @return
 */
uint16_t dap_chain_datum_tx_receipt_signs_count(dap_chain_datum_tx_receipt_t * a_receipt, size_t a_receipt_size)
{
    uint16_t l_ret = 0;
    if(!a_receipt)
        return 0;
    dap_sign_t *l_sign;
    for (l_sign = (dap_sign_t *)a_receipt->exts_n_signs; a_receipt_size > (size_t) ( (byte_t *) l_sign - (byte_t *) a_receipt ) ;
        l_sign =(dap_sign_t *) (((byte_t*) l_sign)+  dap_sign_get_size( l_sign )) ){
        l_ret++;
    }
    if(a_receipt_size != (size_t) ((byte_t *) l_sign - (byte_t *) a_receipt) )
        log_it(L_ERROR, "Receipt 0x%zu (size=%zu) is corrupted", (size_t)a_receipt, a_receipt_size);
    return l_ret;
}


json_object* dap_chain_receipt_info_to_json(dap_chain_receipt_info_t *a_info){
    json_object *l_obj = json_object_new_object();
    if (!l_obj) {
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object *l_obj_srv_uid = json_object_new_uint64(a_info->srv_uid.uint64);
    if (!l_obj_srv_uid) {
        json_object_put(l_obj_srv_uid);
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object_object_add(l_obj, "srvUID", l_obj_srv_uid);
#if DAP_CHAIN_NET_SRV_UID_SIZE == 8
    json_object *l_obj_addition = json_object_new_uint64(a_info->addition);
    if (!l_obj_addition){
        json_object_put(l_obj);
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object_object_add(l_obj, "addition", l_obj_addition);
#endif
    json_object *l_obj_units_type = json_object_new_string(dap_chain_srv_unit_enum_to_str(a_info->units_type.enm));
    if (!l_obj_units_type) {
        json_object_put(l_obj);
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object_object_add(l_obj, "unitsType", l_obj_units_type);
    char *l_datoshi_value = dap_chain_balance_print(a_info->value_datoshi);
    if (!l_datoshi_value) {
        json_object_put(l_obj);
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object *l_obj_datoshi = json_object_new_string(l_datoshi_value);
    if (!l_obj_datoshi) {
        json_object_put(l_datoshi_value);
        DAP_DELETE(l_datoshi_value);
        dap_json_rpc_allocated_error
        return NULL;
    }
    DAP_DELETE(l_datoshi_value);
    json_object_object_add(l_obj, "value", l_obj_datoshi);
    return l_obj;
}

json_object *dap_chain_datum_tx_receipt_to_json(dap_chain_datum_tx_receipt_t *a_receipt) {
    json_object *l_obj = json_object_new_object();
    if (!l_obj) {
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object *l_obj_info = dap_chain_receipt_info_to_json(&a_receipt->receipt_info);
    if (!l_obj_info) {
        json_object_put(l_obj);
        return NULL;
    }
    json_object *l_obj_size = json_object_new_uint64(a_receipt->size);
    if (!l_obj_size) {
        json_object_put(l_obj);
        json_object_put(l_obj_info);
        dap_json_rpc_allocated_error
        return NULL;
    }
    //Provider
    dap_sign_t *l_first_sign  = dap_chain_datum_tx_receipt_sign_get(a_receipt, a_receipt->size, 1);
    //Client
    dap_sign_t *l_second_sign  = dap_chain_datum_tx_receipt_sign_get(a_receipt, a_receipt->size, 2);
    json_object *l_obj_signs = json_object_new_object();
    if (!l_obj_signs) {
        json_object_put(l_obj_size);
        json_object_put(l_obj_info);
        json_object_put(l_obj);
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object *l_obj_provider_sign = dap_sign_to_json(l_first_sign);
    if (!l_obj_provider_sign) {
        json_object_put(l_obj_size);
        json_object_put(l_obj_info);
        json_object_put(l_obj_signs);
        json_object_put(l_obj);
        dap_json_rpc_error_add(2, "Error serializing signature to JSON.");
        return NULL;
    }
    json_object *l_obj_client_sign = dap_sign_to_json(l_second_sign);
    if (!l_obj_client_sign) {
        json_object_put(l_obj_provider_sign);
        json_object_put(l_obj_size);
        json_object_put(l_obj_info);
        json_object_put(l_obj_signs);
        json_object_put(l_obj);
        dap_json_rpc_error_add(2, "Error serializing signature to JSON.");
        return NULL;
    }
    json_object_object_add(l_obj_signs, "provider", l_obj_provider_sign);
    json_object_object_add(l_obj_signs, "client", l_obj_client_sign);
    json_object *l_exts_data = json_object_new_string_len((char *)a_receipt->exts_n_signs, a_receipt->exts_size);
    if (!l_exts_data) {
        json_object_put(l_obj_size);
        json_object_put(l_obj_info);
        json_object_put(l_obj_signs);
        json_object_put(l_obj);
        dap_json_rpc_allocated_error
        return NULL;
    }
    json_object_object_add(l_obj, "info", l_obj_info);
    json_object_object_add(l_obj, "size", l_obj_size);
    json_object_object_add(l_obj, "sings", l_obj_signs);
    json_object_object_add(l_obj, "extsData", l_exts_data);
    return l_obj;
}
