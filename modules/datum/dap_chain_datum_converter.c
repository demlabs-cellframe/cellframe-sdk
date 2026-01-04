/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024
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

#include "dap_chain_datum_converter.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_datum_converter"

/**
 * @brief Convert signed transaction to datum
 * 
 * Pure conversion function - no side effects
 */
dap_chain_datum_t *dap_chain_datum_from_tx(const dap_chain_datum_tx_t *a_tx)
{
    if (!a_tx) {
        log_it(L_ERROR, "Invalid transaction for datum conversion");
        return NULL;
    }
    
    // Get TX size
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    if (l_tx_size == 0) {
        log_it(L_ERROR, "Transaction has zero size");
        return NULL;
    }
    
    // Create datum
    dap_chain_datum_t *l_datum = dap_chain_datum_create(
        DAP_CHAIN_DATUM_TX,
        a_tx,
        l_tx_size
    );
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to create datum from transaction");
        return NULL;
    }
    
    log_it(L_DEBUG, "Converted transaction to datum (%zu bytes)", l_tx_size);
    return l_datum;
}

