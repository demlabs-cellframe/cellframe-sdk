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

#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"

/**
 * Add new transaction to the cache
 *
 * return 0 OK, -1 error, -2 already present
 */
int chain_node_datum_tx_list_hash_add(dap_chain_hash_fast_t *tx_hash, dap_chain_datum_tx_t *tx);

/**
 * Delete transaction from the cache
 *
 * return 0 OK, -1 error, -2 tx_hash not found
 */
int chain_node_datum_tx_list_hash_del(dap_chain_hash_fast_t *tx_hash);

/**
 * Delete all transactions from the cache
 */
void chain_node_datum_tx_list_hash_del_all(void);

/**
 * Get transaction by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
const dap_chain_datum_tx_t* chain_node_datum_tx_list_hash_find(dap_chain_hash_fast_t *tx_hash);
