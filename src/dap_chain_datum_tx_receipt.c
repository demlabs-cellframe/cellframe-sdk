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
 * @return
 */
dap_chain_datum_tx_receipt_t * dap_chain_datum_tx_receipt_create( dap_chain_net_srv_uid_t a_srv_uid,
                                                                  dap_chain_net_srv_price_unit_uid_t a_units_type,
                                                                    uint64_t a_units, uint64_t a_value_datoshi)
{
    dap_chain_datum_tx_receipt_t * l_ret = DAP_NEW_Z(dap_chain_datum_tx_receipt_t);
    l_ret->type = TX_ITEM_TYPE_RECEIPT;
    l_ret->receipt_info.units_type = a_units_type;
    l_ret->receipt_info.srv_uid = a_srv_uid;
    l_ret->receipt_info.units = a_units;
    l_ret->receipt_info.value_datoshi = a_value_datoshi;
    l_ret->size = 1+sizeof (l_ret->receipt_info);
    return  l_ret;
}

size_t dap_chain_datum_tx_receipt_sign_add(dap_chain_datum_tx_receipt_t * a_receipt, size_t a_receipt_size, dap_enc_key_t *a_key )
{
    if ( ! a_receipt ){
        log_it( L_ERROR, "NULL receipt, can't add sign");
        return 0;
    }
    dap_sign_t * l_sign = dap_sign_create(a_key,&a_receipt->receipt_info,sizeof (a_receipt->receipt_info),0);
    size_t l_sign_size = l_sign? dap_sign_get_size( l_sign ) : 0;
    if ( ! l_sign || ! l_sign_size ){
        log_it( L_ERROR, "Can't sign the receipt, may be smth with key?");
        return 0;
    }
    a_receipt= (dap_chain_datum_tx_receipt_t*) DAP_REALLOC(a_receipt, a_receipt_size+l_sign_size);
    memcpy(a_receipt->signs+a_receipt_size, l_sign, l_sign_size);
    a_receipt_size += l_sign_size;
    a_receipt->size = a_receipt_size;
    DAP_DELETE( l_sign );
    return a_receipt_size;
}

/**
 * @brief dap_chain_datum_tx_receipt_sign_get
 * @param l_receipt
 * @param a_sign_position
 * @return
 */
dap_sign_t* dap_chain_datum_tx_receipt_sign_get(dap_chain_datum_tx_receipt_t * l_receipt,  size_t l_receipt_size,uint16_t a_sign_position  )
{
    if ( l_receipt_size <= sizeof (l_receipt->receipt_info)+1)
        return NULL;
    dap_sign_t * l_sign = (dap_sign_t *) l_receipt->signs;
    for ( ; a_sign_position && l_receipt_size > (size_t) ( (byte_t *) l_sign - (byte_t *) l_receipt ) ; a_sign_position-- ){
        l_sign =(dap_sign_t *) (((byte_t*) l_sign)+  dap_sign_get_size( l_sign ));
    }
    return l_sign;
}

/**
 * @brief dap_chain_datum_tx_receipt_signs_count
 * @param l_receipt
 * @return
 */
uint16_t dap_chain_datum_tx_receipt_signs_count(dap_chain_datum_tx_receipt_t * l_receipt, size_t l_receipt_size)
{
    uint16_t l_ret = 0;
    for (dap_sign_t * l_sign = (dap_sign_t *) l_receipt->signs ; l_receipt_size > (size_t) ( (byte_t *) l_sign - (byte_t *) l_receipt ) ;
        l_sign =(dap_sign_t *) (((byte_t*) l_sign)+  dap_sign_get_size( l_sign )) ){
        l_ret++;
    }
    return l_ret;

}
