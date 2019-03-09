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
#include "dap_chain_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_items.h"

static size_t dap_chain_tx_in_get_size(dap_chain_tx_in_t *a_item)
{
    size_t size = sizeof(dap_chain_tx_in_t); // + item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_out_get_size(dap_chain_tx_out_t *a_item)
{
    size_t size = sizeof(dap_chain_tx_out_t);
    return size;
}

static size_t dap_chain_tx_pkey_get_size(dap_chain_tx_pkey_t *a_item)
{
    size_t size = sizeof(dap_chain_tx_pkey_t) + a_item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_sig_get_size(dap_chain_tx_sig_t *item)
{
    size_t size = sizeof(dap_chain_tx_sig_t) + item->header.sig_size;
    return size;
}

static size_t dap_chain_tx_token_get_size(dap_chain_tx_token_t *a_item)
{
    size_t size = sizeof(dap_chain_tx_token_t);
    return size;
}

/**
 * Get item type
 *
 * return type, or TX_ITEM_TYPE_ANY if error
 */
dap_chain_tx_item_type_t dap_chain_datum_tx_item_get_type(const uint8_t *a_item)
{
    dap_chain_tx_in_t *l_item_tx_in = (dap_chain_tx_in_t*) a_item;
    dap_chain_tx_item_type_t type = (l_item_tx_in) ? l_item_tx_in->header.type : TX_ITEM_TYPE_ANY;
    return type;
}

/**
 * Get item size
 *
 * return size, 0 Error
 */
int dap_chain_datum_item_tx_get_size(const uint8_t *a_item)
{
    dap_chain_tx_in_t *item_tx_in = (dap_chain_tx_in_t*) a_item;
    dap_chain_tx_item_type_t type = dap_chain_datum_tx_item_get_type(a_item);
    size_t size = 0;
    switch (type) {
    case TX_ITEM_TYPE_IN: // Transaction inputs
        size = dap_chain_tx_in_get_size((dap_chain_tx_in_t*) a_item);
        break;
    case TX_ITEM_TYPE_OUT: // Transaction outputs
        size = dap_chain_tx_out_get_size((dap_chain_tx_out_t*) a_item);
        break;
    case TX_ITEM_TYPE_PKEY: // Transaction public keys
        size = dap_chain_tx_pkey_get_size((dap_chain_tx_pkey_t*) a_item);
        break;
    case TX_ITEM_TYPE_SIG: // Transaction signatures
        size = dap_chain_tx_sig_get_size((dap_chain_tx_sig_t*) a_item);
        break;
    case TX_ITEM_TYPE_TOKEN: // token item
        size = dap_chain_tx_token_get_size((dap_chain_tx_token_t*) a_item);
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
dap_chain_tx_token_t* dap_chain_datum_tx_item_token_create(const char *a_name)
{
    if(!a_name)
        return NULL;
    int a_name_len = strlen(a_name);
    dap_chain_tx_token_t *l_item = DAP_NEW_Z(dap_chain_tx_token_t);
    l_item->header.type = TX_ITEM_TYPE_TOKEN;
    if(a_name_len >= sizeof(l_item->header.id))
        a_name_len = sizeof(l_item->header.id) - 1;
    strncpy(l_item->header.id, a_name, a_name_len);
    return l_item;
}

/**
 * Create item dap_chain_tx_out_t
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
    memcpy(&l_item->header.tx_prev_hash, a_tx_prev_hash, sizeof(dap_chain_hash_fast_t));
    return l_item;
}

/**
 * Create item dap_chain_tx_out_t
 *
 * return item, NULL Error
 */
dap_chain_tx_out_t* dap_chain_datum_tx_item_out_create(dap_chain_addr_t *a_addr, uint64_t a_value)
{
    if(!a_addr)
        return NULL;
    dap_chain_tx_out_t *l_item = DAP_NEW_Z(dap_chain_tx_out_t);
    l_item->header.type = TX_ITEM_TYPE_OUT;
    l_item->header.value = a_value;
    memcpy(&l_item->addr, a_addr, sizeof(dap_chain_addr_t));
    return l_item;
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
    dap_chain_sign_t *l_chain_sign = dap_chain_sign_create(a_key, a_data, a_data_size, 0);
    size_t l_chain_sign_size = dap_chain_sign_get_size(l_chain_sign); // sign data
    if(!l_chain_sign) {
        return NULL;
    }
    dap_chain_tx_sig_t *l_tx_sig = DAP_NEW_Z_SIZE(dap_chain_tx_sig_t,
            sizeof(dap_chain_tx_sig_t) + l_chain_sign_size);
    l_tx_sig->header.type = TX_ITEM_TYPE_SIG;
    l_tx_sig->header.sig_size = l_chain_sign_size;
    memcpy(l_tx_sig->sig, l_chain_sign, l_chain_sign_size);
    DAP_DELETE(l_chain_sign);
    return l_tx_sig;
}

/**
 * Get sign from sign item
 *
 * return sign, NULL Error
 */
dap_chain_sign_t* dap_chain_datum_tx_item_sign_get_sig(dap_chain_tx_sig_t *a_tx_sig)
{
    if(!a_tx_sig || !a_tx_sig->header.sig_size)
        return NULL;
    dap_chain_sign_t *l_chain_sign = (dap_chain_sign_t*) a_tx_sig->sig;
    return l_chain_sign;
}

/**
 * Get item from transaction
 *
 * a_tx [in] transaction
 * a_item_idx_start[in/out] start index / found index of item in transaction, if 0 then from beginning
 * a_type[in] type of item being find, if TX_ITEM_TYPE_ANY - any item
 * a_item_out_size size[out] size of returned item
 * return item data, NULL Error index or bad format transaction
 */
const uint8_t* dap_chain_datum_tx_item_get(dap_chain_datum_tx_t *a_tx, int *a_item_idx_start,
        dap_chain_tx_item_type_t a_type, int *a_item_out_size)
{
    if(!a_tx)
        return NULL;
    uint32_t l_tx_items_pos = 0, l_tx_items_size = a_tx->header.tx_items_size;
    int l_item_idx = 0;
    while(l_tx_items_pos < l_tx_items_size) {
        uint8_t *l_item = a_tx->tx_items + l_tx_items_pos;
        int l_item_size = dap_chain_datum_item_tx_get_size(l_item);
        if(!l_item_size)
            return NULL;
        // check index
        if(!a_item_idx_start || l_item_idx >= *a_item_idx_start) {
            // check type
            if(a_type == TX_ITEM_TYPE_ANY || a_type == dap_chain_datum_tx_item_get_type(l_item)) {
                if(a_item_idx_start)
                    *a_item_idx_start = l_item_idx;
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
GList* dap_chain_datum_tx_items_get(dap_chain_datum_tx_t *a_tx, dap_chain_tx_item_type_t a_type, int *a_item_count)
{
    GList *items_list = NULL;
    int l_items_count = 0, l_item_idx_start = 0;
    // Get sign item from transaction
    while(1) {
        const uint8_t *l_tx_item = dap_chain_datum_tx_item_get(a_tx, &l_item_idx_start, a_type, NULL);
        if(!l_tx_item)
            break;
        items_list = g_list_append(items_list, (uint8_t*)l_tx_item);
        l_items_count++;
        l_item_idx_start++;
    }
    if(a_item_count)
        *a_item_count = l_items_count;
    return items_list;
}
