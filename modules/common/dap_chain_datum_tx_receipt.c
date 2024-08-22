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
dap_sign_t *dap_chain_datum_tx_receipt_sign_get(dap_chain_datum_tx_receipt_t *a_receipt, size_t a_receipt_size, uint16_t a_sign_position)
{
    if (dap_chain_datum_tx_receipt_check_size(a_receipt, a_receipt_size)) {
        log_it(L_WARNING, "Receipt size check error");
        return NULL;
    }
    size_t l_offset = a_receipt->exts_size;
    size_t l_total_signs_size = a_receipt->size - sizeof(dap_chain_datum_tx_receipt_t) - a_receipt->exts_size;
    if (!l_total_signs_size)
        return NULL;
    dap_sign_t *l_sign = NULL;
    for (uint16_t l_sign_position = a_sign_position + 1; l_sign_position; l_sign_position--) {
        dap_sign_t *l_sign = (dap_sign_t *)(a_receipt->exts_n_signs + l_offset);
        uint64_t l_sign_size = dap_sign_get_size(l_sign);
        l_offset += l_sign_size;
        if (l_offset > l_total_signs_size)
            return NULL;
    }
    return l_sign;
}

uint32_t dap_chain_datum_tx_receipt_type_get(dap_chain_datum_tx_receipt_t *a_receipt)
{
    dap_return_val_if_fail(a_receipt, -1);
    return a_receipt->receipt_info.units_type.enm;
}

uint64_t dap_chain_datum_tx_receipt_srv_uid_get(dap_chain_datum_tx_receipt_t *a_receipt)
{
    dap_return_val_if_fail(a_receipt, -1)
    return a_receipt->receipt_info.srv_uid.uint64;
}
uint64_t dap_chain_datum_tx_receipt_units_get(dap_chain_datum_tx_receipt_t *a_receipt)
{
    dap_return_val_if_fail(a_receipt, -1);
    return a_receipt->receipt_info.units;
}
uint256_t   dap_chain_datum_tx_receipt_value_get(dap_chain_datum_tx_receipt_t *a_receipt)
{
    dap_return_val_if_fail(a_receipt, uint256_0);
    return a_receipt->receipt_info.value_datoshi;
}

/**
 * @brief dap_chain_datum_tx_receipt_signs_count
 * @param a_receipt
 * @param a_receipt_size
 * @return
 */
uint16_t dap_chain_datum_tx_receipt_signs_count(dap_chain_datum_tx_receipt_t *a_receipt)
{
    uint16_t l_ret = 0;
    dap_return_val_if_fail(a_receipt, 0);
    dap_sign_t *l_sign;
    for (l_sign = (dap_sign_t *)a_receipt->exts_n_signs; a_receipt->size > (size_t) ( (byte_t *) l_sign - (byte_t *) a_receipt ) ;
        l_sign =(dap_sign_t *) (((byte_t*) l_sign)+  dap_sign_get_size( l_sign )) ){
        l_ret++;
    }
    return l_ret;
}

int dap_chain_datum_tx_receipt_check_size(dap_chain_datum_tx_receipt_t *a_receipt, size_t a_control_size)
{
    dap_return_val_if_fail(a_receipt && a_control_size == a_receipt->size &&
                           a_control_size >= sizeof(dap_chain_datum_tx_receipt_t) + a_receipt->exts_size,
                           -1); // Main controls incosistentency
    if (a_control_size == sizeof(dap_chain_datum_tx_receipt_t) + a_receipt->exts_size)
        return 0;               // No signs at receipt, it's OK
    if (a_control_size < sizeof(dap_chain_datum_tx_receipt_t) + a_receipt->exts_size + sizeof(dap_sign_t))
        return -2;
    dap_sign_t *l_sign = (dap_sign_t *)(a_receipt->exts_n_signs + a_receipt->exts_size);
    for (uint16_t l_sign_position = 2; l_sign_position; l_sign_position--) {
        size_t l_sign_offset = (byte_t *)l_sign - (byte_t *)a_receipt;
        if (a_control_size < l_sign_offset + sizeof(dap_sign_t))
            return -2;          // Left space is too samll to contain a sign
        uint64_t l_sign_size = dap_sign_get_size(l_sign);
        if (l_sign_size + l_sign_offset <= l_sign_offset || l_sign_size + l_sign_offset > a_control_size)
            return -3;
        l_sign = (dap_sign_t *)((byte_t *)l_sign + l_sign_size);
    }
    size_t l_sign_offset = (byte_t *)l_sign - (byte_t *)a_receipt;
    return l_sign_offset == a_control_size ? 0 : -4; // Receipt is lagrer that two signs need
}
