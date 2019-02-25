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

#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"

typedef enum dap_chain_tx_item_type{
    TX_ITEM_TYPE_IN = 0x00, /// @brief  Transaction inputs
    TX_ITEM_TYPE_OUT = 0x10, /// @brief  Transaction outputs
    TX_ITEM_TYPE_PKEY = 0x20,
    TX_ITEM_TYPE_SIG = 0x30,
    TX_ITEM_TYPE_TOKEN = 0x40,

    TX_ITEM_TYPE_ANY = 0xff,
} dap_chain_tx_item_type_t;

/**
  * @struct dap_chain_datum_tx
  * @brief Transaction section, consists from lot of tx_items
  */
typedef struct dap_chain_datum_tx{
    struct {
        uint64_t lock_time;
        uint32_t tx_items_size; // size of next sequencly lying tx_item sections would be decided to belong this transaction
    } DAP_ALIGN_PACKED header;
    uint8_t tx_items[];
} DAP_ALIGN_PACKED dap_chain_datum_tx_t;


/**
 * Create empty transaction
 *
 * return transaction, 0 Error
 */
dap_chain_datum_tx_t* dap_chain_datum_tx_create(void);

/**
 * Delete transaction
 */
void dap_chain_datum_tx_delete(dap_chain_datum_tx_t *a_tx);

/**
 * Get size of transaction
 *
 * return size, 0 Error
 */
int dap_chain_datum_tx_get_size(dap_chain_datum_tx_t *a_tx);

/**
 * Insert item to transaction
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_item(dap_chain_datum_tx_t **a_tx, const uint8_t *a_item);

/**
* Sign a transaction (Add sign item to transaction)
 *
 * return 1 Ok, -1 Error
 */
int dap_chain_datum_tx_add_sign(dap_chain_datum_tx_t **a_tx, dap_enc_key_t *a_key);

/**
 * Verify all sign item in transaction
 *
 * return 1 Ok, 0 Invalid sign, -1 Not found sing or other Error
 */
int dap_chain_datum_tx_verify_sign(dap_chain_datum_tx_t *a_tx);
