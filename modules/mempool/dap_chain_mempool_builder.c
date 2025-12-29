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

#include "dap_chain_mempool_builder.h"
#include "dap_chain_mempool.h"
#include "dap_chain_datum.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_mempool_builder"

/**
 * @brief Create and submit transfer transaction
 * 
 * This is the IDEAL architecture for hardware wallet support:
 * 1. Create unsigned TX via TX Builder
 * 2. Sign TX via Ledger Sign API (wallet callback - may wait 30s!)
 * 3. Add signature to TX
 * 4. Convert TX to datum
 * 5. Submit datum to mempool
 */
char *dap_chain_mempool_tx_create_and_submit_transfer(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    dap_chain_t *a_chain,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee,
    const char *a_hash_out_type
)
{
    // Validate parameters
    if (!a_ledger || !a_wallet_name || !a_chain || !a_addr_from || !a_addr_to || !a_token_ticker) {
        log_it(L_ERROR, "Invalid parameters for mempool_tx_create_and_submit_transfer");
        return NULL;
    }
    
    // Get public key for sender
    dap_pkey_t *l_pkey = dap_ledger_get_pkey(a_ledger, a_wallet_name, 0);
    if (!l_pkey) {
        log_it(L_ERROR, "Failed to get public key from wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    // STEP 1: Create unsigned transaction via TX Builder
    log_it(L_INFO, "Creating unsigned transfer transaction...");
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
        log_it(L_ERROR, "Failed to create unsigned transaction");
        return NULL;
    }
    
    // STEP 2: Get data for signing
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_datum_tx_get_sign_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get sign data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // STEP 3: Sign transaction via Ledger Sign API
    // THIS MAY WAIT UP TO 30 SECONDS for hardware wallet!
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
    
    // STEP 4: Add signature to transaction
    if (dap_chain_datum_tx_add_sign(&l_tx, l_sign) != 1) {
        log_it(L_ERROR, "Failed to add signature to transaction");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Signature is now part of TX, don't free it separately
    
    // STEP 5: Convert TX to datum
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    
    // TX is copied into datum, can free original
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to create datum");
        return NULL;
    }
    
    // STEP 6: Submit datum to mempool
    log_it(L_INFO, "Submitting signed transaction to mempool...");
    char *l_tx_hash_str = dap_chain_mempool_datum_add(l_datum, a_chain, a_hash_out_type);
    
    // Datum is copied by mempool, can free it
    DAP_DELETE(l_datum);
    
    if (!l_tx_hash_str) {
        log_it(L_ERROR, "Failed to add datum to mempool");
        return NULL;
    }
    
    log_it(L_NOTICE, "Transfer transaction submitted successfully: %s", l_tx_hash_str);
    
    return l_tx_hash_str;
}

// TODO: Implement remaining functions following the same pattern:
// - dap_chain_mempool_tx_create_and_submit_multi_transfer
// - dap_chain_mempool_tx_create_and_submit_cond_output
// - dap_chain_mempool_tx_create_and_submit_event
// - dap_chain_mempool_tx_create_and_submit_from_emission
//
// Each follows identical 6-step pattern:
// 1. Get public key
// 2. Create unsigned TX
// 3. Get sign data
// 4. Sign via ledger (wait up to 30s)
// 5. Add signature
// 6. Convert to datum
// 7. Submit to mempool

