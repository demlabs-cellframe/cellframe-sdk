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

#include "dap_chain_datum_tx.h"
#include "dap_sign.h"
#include "dap_enc_key.h"

/**
 * @brief TX Signer API - adds signatures to unsigned transactions
 * 
 * LAYER 2: Pure signing layer (no building, no mempool)
 * 
 * Single Responsibility: Sign transactions using provided signature data
 * 
 * Input: Unsigned dap_chain_datum_tx_t*
 * Output: Signed dap_chain_datum_tx_t*
 * 
 * Hardware wallet friendly:
 * - Accepts pre-generated signatures (from any source)
 * - No direct key access
 * - Can wait for external signing (hardware wallet, remote signer, etc)
 */

/**
 * @brief Sign transaction by adding signature
 * 
 * Pure function: takes unsigned TX, adds signature, returns signed TX
 * 
 * @param a_tx Transaction to sign (modified in place)
 * @param a_sign Signature to add
 * @return 0 on success, -1 on error
 */
int dap_chain_tx_sign(dap_chain_datum_tx_t **a_tx, dap_sign_t *a_sign);

/**
 * @brief Get data that needs to be signed
 * 
 * Helper for external signers (hardware wallets, etc)
 * 
 * @param a_tx Transaction
 * @param a_sign_data_size Output: size of sign data
 * @return Pointer to data that should be signed, or NULL on error
 */
const void *dap_chain_tx_get_signing_data(
    const dap_chain_datum_tx_t *a_tx,
    size_t *a_sign_data_size
);

