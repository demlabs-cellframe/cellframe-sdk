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

#include <memory.h>
#include <assert.h>
#include "dap_common.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_sign.h"

#define LOG_TAG "dap_chain_datum_tx"

size_t dap_chain_tx_in_get_size(dap_chain_tx_in_t *item)
{
    size_t size = sizeof(dap_chain_tx_in_t);// + item->header.sig_size;
    return size;
}

size_t dap_chain_tx_out_get_size(dap_chain_tx_out_t *item)
{
    size_t size = sizeof(dap_chain_tx_out_t);
    return size;
}

size_t dap_chain_tx_pkey_get_size(dap_chain_tx_pkey_t *item)
{
    size_t size = sizeof(dap_chain_tx_pkey_t) + item->header.sig_size;
    return size;
}

size_t dap_chain_tx_sig_get_size(dap_chain_tx_sig_t *item)
{
    size_t size = sizeof(dap_chain_tx_sig_t) + item->header.sig_size;
    return size;
}

/**
 * Get item type
 *
 * return type, 0xff Error
 */
static dap_chain_tx_item_type_t dap_chain_datum_item_get_type(const uint8_t *item)
{
    dap_chain_tx_in_t *item_tx_in = (dap_chain_tx_in_t*) item;
    dap_chain_tx_item_type_t type = (item_tx_in) ? item_tx_in->header.type : 0xff;
    return type;
}

/**
 * Get item size
 *
 * return size, 0 Error
 */
static int dap_chain_datum_item_get_size(const uint8_t *item)
{
    dap_chain_tx_in_t *item_tx_in = (dap_chain_tx_in_t*) item;
    dap_chain_tx_item_type_t type = dap_chain_datum_item_get_type(item);
    size_t size = 0;
    switch (type) {
    case TX_ITEM_TYPE_IN: // Transaction inputs
        size = dap_chain_tx_in_get_size((dap_chain_tx_in_t*) item);
        break;
    case TX_ITEM_TYPE_OUT: // Transaction outputs
        size = dap_chain_tx_out_get_size((dap_chain_tx_out_t*) item);
        break;
    case TX_ITEM_TYPE_PKEY: // Transaction public keys
        size = dap_chain_tx_pkey_get_size((dap_chain_tx_pkey_t*) item);
        break;
    case TX_ITEM_TYPE_SIG: // Transaction signatures
        size = dap_chain_tx_sig_get_size((dap_chain_tx_sig_t*) item);
        break;
    default:
        return 0;
    }
    return size;
}

/**
 * Get size of transaction
 *
 * return size, 0 Error
 */
int dap_chain_datum_tx_get_size(dap_chain_datum_tx_t *tx)
{
    if(!tx)
        return 0;
    return (sizeof(dap_chain_datum_tx_t) + tx->header.tx_items_size);
}

/**
 * Insert item to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_item(dap_chain_datum_tx_t **tx, const uint8_t *item)
{
    size_t size = dap_chain_datum_item_get_size(item);
    if(!size)
        return -1;
    dap_chain_datum_tx_t *tx_cur = *tx;
    tx_cur = (dap_chain_datum_tx_t*) realloc(tx_cur, dap_chain_datum_tx_get_size(tx_cur) + size);
    memcpy((uint8_t*)tx_cur->tx_items + tx_cur->header.tx_items_size, item, size);
    tx_cur->header.tx_items_size += size;
    *tx = tx_cur;
    return 1;
}

/**
* Sign a transaction (Add sign item to transaction)
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_sign(dap_chain_datum_tx_t **tx, dap_enc_key_t *a_key)
{
    if(!tx || !a_key)
        return -1;
    const void *a_data = (*tx)->tx_items;
    const size_t a_data_size = (*tx)->header.tx_items_size;
    // sign all items in transaction
    dap_chain_sign_t *a_chain_sign = dap_chain_sign_create(a_key, a_data, a_data_size, 0);
    size_t a_chain_sign_size = dap_chain_sign_get_size(a_chain_sign);
    // add sign to datum_tx
    if(a_chain_sign) {
        // check valid sign
        assert(1 == dap_chain_sign_verify (a_chain_sign,a_data, a_data_size));
        dap_chain_tx_sig_t *tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t,
                sizeof(dap_chain_tx_sig_t) + a_chain_sign_size);
        tx_sig->header.type = TX_ITEM_TYPE_SIG;
        tx_sig->header.sig_size = a_chain_sign_size;
        memcpy(tx_sig->sig, a_chain_sign, a_chain_sign_size);
        DAP_DELETE(a_chain_sign);
        return dap_chain_datum_tx_add_item(tx, (const uint8_t*) tx_sig);
    }
    return -1;
}

/**
 * Verify all sign item in transaction
 *
 * return 1 Ok, 0 Invalid sign, -1 Not found sing or other Error
 */
int dap_chain_datum_tx_verify_sign(dap_chain_datum_tx_t *tx)
{
    int ret = -1;
    if(!tx)
        return -1;
    uint32_t tx_items_pos = 0, tx_items_size = tx->header.tx_items_size;
    while(tx_items_pos < tx_items_size) {
        uint8_t *item = tx->tx_items+tx_items_pos;
        int item_size = dap_chain_datum_item_get_size(item);
        if(!item_size)
            return -1;
        if(dap_chain_datum_item_get_type(item)==TX_ITEM_TYPE_SIG){
            dap_chain_tx_sig_t *item_tx_sig = (dap_chain_tx_sig_t*) item;
            dap_chain_sign_t *a_chain_sign = (dap_chain_sign_t*)item_tx_sig->sig;
            if(dap_chain_sign_verify (a_chain_sign, tx->tx_items, tx_items_pos)!=1){
                ret = 0;
                break;
            }
            // sign verify successfully
            ret = 1;
        }
        // sign item must be at the end
        else
            ret = -1;
        // go to text item
        tx_items_pos+=item_size;
    }
    assert(tx_items_pos == tx_items_size);
    return ret;
}
