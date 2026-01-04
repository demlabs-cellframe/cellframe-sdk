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

#include "dap_chain_tx_sign.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_tx_sign"

/**
 * @brief Sign transaction by adding signature
 * 
 * Pure signing function - no side effects
 */
int dap_chain_tx_sign(dap_chain_datum_tx_t **a_tx, dap_sign_t *a_sign)
{
    if (!a_tx || !*a_tx || !a_sign) {
        log_it(L_ERROR, "Invalid parameters for tx_sign");
        return -1;
    }
    
    // Use existing function to add sign
    int l_result = dap_chain_datum_tx_add_sign(a_tx, a_sign);
    
    if (l_result != 1) {
        log_it(L_ERROR, "Failed to sign transaction");
        return -1;
    }
    
    log_it(L_DEBUG, "Transaction signed successfully");
    return 0;
}

/**
 * @brief Get data that needs to be signed
 */
const void *dap_chain_tx_get_signing_data(
    const dap_chain_datum_tx_t *a_tx,
    size_t *a_sign_data_size
)
{
    if (!a_tx || !a_sign_data_size) {
        log_it(L_ERROR, "Invalid parameters for tx_get_signing_data");
        return NULL;
    }
    
    // Use existing function to get sign data
    const void *l_sign_data = dap_chain_datum_tx_get_sign_data(a_tx, a_sign_data_size);
    
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data from transaction");
        return NULL;
    }
    
    log_it(L_DEBUG, "Got signing data: %zu bytes", *a_sign_data_size);
    return l_sign_data;
}

