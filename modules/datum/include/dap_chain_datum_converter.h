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

#pragma once

#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"

/**
 * @brief Datum Converter API - converts transactions to datum format
 * 
 * LAYER 3: Pure conversion layer (no building, no signing, no mempool)
 * 
 * Single Responsibility: Convert TX to Datum
 * 
 * Input: Signed dap_chain_datum_tx_t*
 * Output: dap_chain_datum_t*
 */

/**
 * @brief Convert signed transaction to datum
 * 
 * Pure function: TX → Datum conversion
 * 
 * @param a_tx Signed transaction
 * @return New datum, or NULL on error (caller must free)
 */
dap_chain_datum_t *dap_chain_datum_from_tx(const dap_chain_datum_tx_t *a_tx);


