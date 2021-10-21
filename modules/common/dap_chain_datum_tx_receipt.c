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
                                                                    uint64_t a_units, uint64_t a_value_datoshi,
                                                                  const void * a_ext, size_t a_ext_size)
{
    dap_chain_datum_tx_receipt_t * l_ret = DAP_NEW_Z_SIZE(dap_chain_datum_tx_receipt_t, dap_chain_datum_tx_receipt_get_size_hdr() +a_ext_size );
    l_ret->type = TX_ITEM_TYPE_RECEIPT;
    l_ret->receipt_info.units_type = a_units_type;
    l_ret->receipt_info.srv_uid = a_srv_uid;
    l_ret->receipt_info.units = a_units;
    l_ret->receipt_info.value_datoshi = a_value_datoshi;
    l_ret->size = dap_chain_datum_tx_receipt_get_size_hdr()+a_ext_size;

    if( a_ext_size && a_ext){
        l_ret->exts_size = a_ext_size;
        memcpy(l_ret->exts_n_signs, a_ext, a_ext_size);
    }
    return  l_ret;
}

size_t dap_chain_datum_tx_receipt_sign_add(dap_chain_datum_tx_receipt_t ** a_receipt, size_t a_receipt_size, dap_enc_key_t *a_key )
{
    dap_chain_datum_tx_receipt_t *l_receipt = *a_receipt;
    if ( ! *a_receipt ){
        log_it( L_ERROR, "NULL receipt, can't add sign");
        return 0;
    }
    dap_sign_t * l_sign = dap_sign_create(a_key,&l_receipt->receipt_info,sizeof (l_receipt->receipt_info),0);
    size_t l_sign_size = l_sign? dap_sign_get_size( l_sign ) : 0;
    if ( ! l_sign || ! l_sign_size ){
        log_it( L_ERROR, "Can't sign the receipt, may be smth with key?");
        return 0;
    }
    l_receipt= (dap_chain_datum_tx_receipt_t*) DAP_REALLOC(l_receipt, a_receipt_size+l_sign_size);
    memcpy(l_receipt->exts_n_signs + l_receipt->exts_size, l_sign, l_sign_size);
    a_receipt_size += l_sign_size;
    l_receipt->size = a_receipt_size;
    l_receipt->exts_size += l_sign_size;
    DAP_DELETE( l_sign );
    *a_receipt = l_receipt;
    return a_receipt_size;
}

/**
 * @brief dap_chain_datum_tx_receipt_sign_get
 * @param l_receipt
 * @param a_sign_position
 * @return
 */
dap_sign_t* dap_chain_datum_tx_receipt_sign_get(dap_chain_datum_tx_receipt_t * l_receipt, size_t l_receipt_size, uint16_t a_sign_position)
{
    if ( !l_receipt ||  l_receipt_size != l_receipt->size || l_receipt_size <= sizeof (l_receipt->receipt_info)+1)
        return NULL;
    dap_sign_t * l_sign = (dap_sign_t *)l_receipt->exts_n_signs;//+l_receipt->exts_size);
    for ( ; a_sign_position && l_receipt_size > (size_t) ( (byte_t *) l_sign - (byte_t *) l_receipt ) ; a_sign_position-- ){
        l_sign =(dap_sign_t *) (((byte_t*) l_sign)+  dap_sign_get_size( l_sign ));
    }
    // not enough signs in receipt
    if(a_sign_position>0)
        return NULL;
    // too big sign size
    if((l_sign->header.sign_size + ((byte_t*) l_sign - (byte_t*) l_receipt->exts_n_signs)) >= l_receipt->exts_size)
        return NULL;
    return l_sign;
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
