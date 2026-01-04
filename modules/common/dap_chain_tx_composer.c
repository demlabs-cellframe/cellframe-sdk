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

#include "dap_chain_tx_composer.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_tx_composer"

/**
 * @brief Compose transfer transaction
 * 
 * Perfect composition pattern:
 * 1. Get public key from ledger
 * 2. Build unsigned TX (Layer 1: TX Builder)
 * 3. Get signing data
 * 4. Sign via ledger callback (Layer 2: may wait 30s for hardware!)
 * 5. Add signature (Layer 2: TX Signer)
 * 6. Convert to datum (Layer 3: Converter)
 * 7. Return datum (caller submits to mempool)
 */
dap_chain_datum_t *dap_chain_tx_compose_transfer(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    dap_chain_t *a_chain,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee
)
{
    // Validate
    if (!a_ledger || !a_wallet_name || !a_chain || !a_addr_from || !a_addr_to || !a_token_ticker) {
        log_it(L_ERROR, "Invalid parameters for tx_compose_transfer");
        return NULL;
    }
    
    // STEP 1: Get public key from ledger
    dap_pkey_t *l_pkey = dap_ledger_get_pkey(a_ledger, a_wallet_name, 0);
    if (!l_pkey) {
        log_it(L_ERROR, "Failed to get public key from wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    // STEP 2: Build unsigned TX (LAYER 1: TX Builder)
    log_it(L_INFO, "Building unsigned transfer transaction...");
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_transfer(
        a_chain->net_id,
        l_pkey,
        a_addr_from,
        a_addr_to,
        a_token_ticker,
        a_value,
        a_value_fee
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build unsigned transaction");
        return NULL;
    }
    
    // STEP 3: Get signing data
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // STEP 4: Sign via ledger callback (LAYER 2: may wait 30s for hardware wallet!)
    log_it(L_INFO, "Signing transaction with wallet '%s' (may take up to 30s for hardware wallet)...",
           a_wallet_name);
    
    dap_sign_t *l_sign = dap_ledger_sign_data(
        a_ledger,
        a_wallet_name,
        l_sign_data,
        l_sign_data_size,
        0  // key index
    );
    
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign transaction");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Transaction signed successfully");
    
    // STEP 5: Add signature (LAYER 2: TX Signer)
    if (dap_chain_tx_add_signature(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Signature is now part of TX
    
    // STEP 6: Convert to datum (LAYER 3: Converter)
    log_it(L_INFO, "Converting signed transaction to datum...");
    dap_chain_datum_t *l_datum = dap_chain_datum_from_tx(l_tx);
    
    // TX is copied into datum, can free original
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to convert transaction to datum");
        return NULL;
    }
    
    // STEP 7: Return datum (caller submits to mempool!)
    log_it(L_NOTICE, "Transfer transaction composed successfully (ready for mempool submission)");
    
    return l_datum;
}

// TODO: Implement remaining 4 functions following the same 7-step pattern:
// - dap_chain_tx_compose_multi_transfer
// - dap_chain_tx_compose_cond_output
// - dap_chain_tx_compose_event
// - dap_chain_tx_compose_from_emission
//
// Each function:
// 1. Get public key
// 2. Build TX (Layer 1)
// 3. Get signing data
// 4. Sign (Layer 2 - wait 30s)
// 5. Add signature (Layer 2)
// 6. Convert to datum (Layer 3)
// 7. Return datum (caller decides where to send it!)

