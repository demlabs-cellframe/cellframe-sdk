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
#include "dap_chain_sign.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx.h"

#define LOG_TAG "dap_chain_datum_tx"

/**
 * Create empty transaction
 *
 * return transaction, 0 Error
 */
dap_chain_datum_tx_t* dap_chain_datum_tx_create(void)
{
    dap_chain_datum_tx_t *tx = DAP_NEW_Z(dap_chain_datum_tx_t);
    tx->header.lock_time = time(NULL);
    return tx;
}

/**
 * Delete transaction
 */
void dap_chain_datum_tx_delete(dap_chain_datum_tx_t *a_tx)
{
    if(a_tx)
        DAP_DELETE(a_tx);
}


/**
 * Get size of transaction
 *
 * return size, 0 Error
 */
int dap_chain_datum_tx_get_size(dap_chain_datum_tx_t *a_tx)
{
    if(!a_tx)
        return 0;
    return (sizeof(dap_chain_datum_tx_t) + a_tx->header.tx_items_size);
}

/**
 * Insert item to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_item(dap_chain_datum_tx_t **a_tx, const uint8_t *a_item)
{
    size_t size = dap_chain_datum_item_tx_get_size(a_item);
    if(!size)
        return -1;
    dap_chain_datum_tx_t *tx_cur = *a_tx;
    tx_cur = (dap_chain_datum_tx_t*) realloc(tx_cur, dap_chain_datum_tx_get_size(tx_cur) + size);
    memcpy((uint8_t*) tx_cur->tx_items + tx_cur->header.tx_items_size, a_item, size);
    tx_cur->header.tx_items_size += size;
    *a_tx = tx_cur;
    return 1;
}

/**
 * Sign a transaction (Add sign item to transaction)
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_sign(dap_chain_datum_tx_t **a_tx, dap_enc_key_t *a_key)
{
    if(!a_tx || !a_key)
        return -1;
    // sign all previous items in transaction
    const void *l_data = (*a_tx)->tx_items;
    const size_t l_data_size = (*a_tx)->header.tx_items_size;
    dap_chain_tx_sig_t *l_tx_sig = dap_chain_datum_tx_item_sign_create(a_key, l_data, l_data_size);
    if(l_tx_sig) {
        int l_ret = dap_chain_datum_tx_add_item(a_tx, (const uint8_t*) l_tx_sig);
        DAP_DELETE(l_tx_sig);
        return l_ret;
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
        uint8_t *item = tx->tx_items + tx_items_pos;
        int item_size = dap_chain_datum_item_tx_get_size(item);
        if(!item_size)
            return -1;
        if(dap_chain_datum_tx_item_get_type(item) == TX_ITEM_TYPE_SIG) {
            dap_chain_tx_sig_t *item_tx_sig = (dap_chain_tx_sig_t*) item;
            dap_chain_sign_t *a_chain_sign = (dap_chain_sign_t*) item_tx_sig->sig;
            if(dap_chain_sign_verify(a_chain_sign, tx->tx_items, tx_items_pos) != 1) {
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
        tx_items_pos += item_size;
    }
    assert(tx_items_pos == tx_items_size);
    return ret;
}
