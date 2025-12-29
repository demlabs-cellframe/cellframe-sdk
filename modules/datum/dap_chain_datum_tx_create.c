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

#include "dap_chain_datum_tx_create.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"

#define LOG_TAG "dap_chain_datum_tx_create"

/**
 * @brief Get transaction data for signing
 * 
 * Returns pointer to the transaction data that needs to be signed.
 * For hardware wallet, this data will be sent to the device for signing.
 */
const void *dap_chain_datum_tx_get_sign_data(const dap_chain_datum_tx_t *a_tx, size_t *a_data_size)
{
    if (!a_tx || !a_data_size) {
        log_it(L_ERROR, "Invalid parameters for get_sign_data");
        return NULL;
    }
    
    // Sign everything except the header's reserved bytes
    // This is the standard cellframe signing approach
    *a_data_size = dap_chain_datum_tx_get_size(a_tx);
    return (const void *)a_tx;
}

/**
 * @brief Add signature to transaction
 * 
 * Reallocates transaction to add signature item.
 * This is hardware wallet friendly - signature comes from external source.
 */
int dap_chain_datum_tx_add_sign(dap_chain_datum_tx_t **a_tx, dap_sign_t *a_sign)
{
    if (!a_tx || !*a_tx || !a_sign) {
        log_it(L_ERROR, "Invalid parameters for add_sign");
        return 0;
    }
    
    // Use existing datum_tx function to add sign item
    return dap_chain_datum_tx_add_sign_item(a_tx, a_sign);
}

/**
 * @brief Helper: Find outputs to cover required value
 * 
 * Internal helper to find previous transaction outputs that cover the required amount.
 * This is used by all tx creation functions.
 */
static dap_list_t *_find_outs_to_cover_value(
    dap_ledger_t *a_ledger,
    const dap_chain_addr_t *a_addr_from,
    const char *a_token_ticker,
    uint256_t a_value_need,
    uint256_t *a_value_found
)
{
    if (!a_ledger || !a_addr_from || !a_token_ticker || !a_value_found) {
        return NULL;
    }
    
    // Get list of unspent outputs for this address
    dap_list_t *l_list_outs = dap_ledger_get_list_tx_outs_with_val(
        a_ledger,
        a_token_ticker,
        a_addr_from,
        a_value_need,
        a_value_found
    );
    
    if (!l_list_outs) {
        log_it(L_WARNING, "No unspent outputs found for address");
        return NULL;
    }
    
    if (compare256(*a_value_found, a_value_need) < 0) {
        log_it(L_WARNING, "Insufficient funds: need %s, found %s",
               dap_chain_balance_to_coins(a_value_need),
               dap_chain_balance_to_coins(*a_value_found));
        dap_list_free_full(l_list_outs, NULL);
        return NULL;
    }
    
    return l_list_outs;
}

/**
 * @brief Helper: Add inputs from list of outputs
 */
static int _add_inputs_from_outs_list(
    dap_chain_datum_tx_t **a_tx,
    dap_list_t *a_list_outs
)
{
    if (!a_tx || !*a_tx || !a_list_outs) {
        return -1;
    }
    
    for (dap_list_t *l_iter = a_list_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_out_cond_t *l_out = (dap_chain_tx_out_cond_t *)l_iter->data;
        if (!l_out) continue;
        
        // Add in item
        if (dap_chain_datum_tx_add_in_item(a_tx, &l_out->tx_hash_fast, l_out->out_idx) != 1) {
            log_it(L_ERROR, "Failed to add input item");
            return -1;
        }
    }
    
    return 0;
}

/**
 * @brief Create simple transfer transaction WITHOUT signature
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_transfer(
    dap_chain_net_id_t a_net_id,
    dap_pkey_t *a_pkey_from,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee
)
{
    // Validate parameters
    if (!a_pkey_from || !a_addr_from || !a_addr_to || !a_token_ticker) {
        log_it(L_ERROR, "Invalid parameters for tx_create_transfer");
        return NULL;
    }
    
    if (IS_ZERO_256(a_value)) {
        log_it(L_ERROR, "Transfer value is zero");
        return NULL;
    }
    
    // Get network and ledger
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    if (!l_net || !l_net->pub.ledger) {
        log_it(L_ERROR, "Network or ledger not found");
        return NULL;
    }
    
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    
    // Calculate total needed
    uint256_t l_total_need = {};
    SUM_256_256(a_value, a_value_fee, &l_total_need);
    
    // Find outputs to cover the value
    uint256_t l_value_found = {};
    dap_list_t *l_list_outs = _find_outs_to_cover_value(
        l_ledger,
        a_addr_from,
        a_token_ticker,
        l_total_need,
        &l_value_found
    );
    
    if (!l_list_outs) {
        log_it(L_ERROR, "Insufficient funds for transfer");
        return NULL;
    }
    
    // Create transaction structure
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        dap_list_free_full(l_list_outs, NULL);
        return NULL;
    }
    
    // Add inputs
    if (_add_inputs_from_outs_list(&l_tx, l_list_outs) != 0) {
        log_it(L_ERROR, "Failed to add inputs");
        dap_chain_datum_tx_delete(l_tx);
        dap_list_free_full(l_list_outs, NULL);
        return NULL;
    }
    
    // Add output to recipient
    if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) != 1) {
        log_it(L_ERROR, "Failed to add output");
        dap_chain_datum_tx_delete(l_tx);
        dap_list_free_full(l_list_outs, NULL);
        return NULL;
    }
    
    // Add change if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_found, l_total_need, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_change) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            dap_list_free_full(l_list_outs, NULL);
            return NULL;
        }
    }
    
    // Add fee if needed
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            dap_list_free_full(l_list_outs, NULL);
            return NULL;
        }
    }
    
    dap_list_free_full(l_list_outs, NULL);
    
    log_it(L_NOTICE, "Created unsigned transfer transaction: %s -> %s, amount: %s %s",
           dap_chain_addr_to_str_static(a_addr_from),
           dap_chain_addr_to_str_static(a_addr_to),
           dap_chain_balance_to_coins(a_value),
           a_token_ticker);
    
    return l_tx;
}

/**
 * @brief Create multi-output transfer transaction WITHOUT signature
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_multi_transfer(
    dap_chain_net_id_t a_net_id,
    dap_pkey_t *a_pkey_from,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t **a_addr_to,
    uint256_t *a_values,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value_fee,
    size_t a_outputs_count,
    dap_time_t *a_time_unlock
)
{
    // Validate parameters
    if (!a_pkey_from || !a_addr_from || !a_addr_to || !a_values || 
        !a_token_ticker || !a_outputs_count) {
        log_it(L_ERROR, "Invalid parameters for tx_create_multi_transfer");
        return NULL;
    }
    
    // Get network and ledger
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    if (!l_net || !l_net->pub.ledger) {
        log_it(L_ERROR, "Network or ledger not found");
        return NULL;
    }
    
    dap_ledger_t *l_ledger = l_net->pub.ledger;
    
    // Calculate total needed
    uint256_t l_total_need = a_value_fee;
    for (size_t i = 0; i < a_outputs_count; i++) {
        if (!a_addr_to[i] || IS_ZERO_256(a_values[i])) {
            log_it(L_ERROR, "Invalid output %zu", i);
            return NULL;
        }
        SUM_256_256(l_total_need, a_values[i], &l_total_need);
    }
    
    // Find outputs to cover the value
    uint256_t l_value_found = {};
    dap_list_t *l_list_outs = _find_outs_to_cover_value(
        l_ledger, a_addr_from, a_token_ticker, l_total_need, &l_value_found
    );
    
    if (!l_list_outs) {
        log_it(L_ERROR, "Insufficient funds for multi-transfer");
        return NULL;
    }
    
    // Create transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        dap_list_free_full(l_list_outs, NULL);
        return NULL;
    }
    
    // Add inputs
    if (_add_inputs_from_outs_list(&l_tx, l_list_outs) != 0) {
        log_it(L_ERROR, "Failed to add inputs");
        dap_chain_datum_tx_delete(l_tx);
        dap_list_free_full(l_list_outs, NULL);
        return NULL;
    }
    
    // Add outputs to recipients
    for (size_t i = 0; i < a_outputs_count; i++) {
        if (a_time_unlock && a_time_unlock[i]) {
            // Add time-locked output
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i], a_values[i], a_time_unlock[i]) != 1) {
                log_it(L_ERROR, "Failed to add time-locked output %zu", i);
                dap_chain_datum_tx_delete(l_tx);
                dap_list_free_full(l_list_outs, NULL);
                return NULL;
            }
        } else {
            // Add regular output
            if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to[i], a_values[i]) != 1) {
                log_it(L_ERROR, "Failed to add output %zu", i);
                dap_chain_datum_tx_delete(l_tx);
                dap_list_free_full(l_list_outs, NULL);
                return NULL;
            }
        }
    }
    
    // Add change if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_found, l_total_need, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_change) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            dap_list_free_full(l_list_outs, NULL);
            return NULL;
        }
    }
    
    // Add fee if needed
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            dap_list_free_full(l_list_outs, NULL);
            return NULL;
        }
    }
    
    dap_list_free_full(l_list_outs, NULL);
    
    log_it(L_NOTICE, "Created unsigned multi-transfer transaction: %zu outputs", a_outputs_count);
    
    return l_tx;
}

// TODO: Implement remaining functions:
// - dap_chain_datum_tx_create_cond_output  
// - dap_chain_datum_tx_create_event
// - dap_chain_datum_tx_create_from_emission

// These will follow the same pattern:
// 1. Validate parameters
// 2. Find inputs to cover value
// 3. Create TX structure
// 4. Add inputs
// 5. Add outputs
// 6. Add fees
// 7. Return UNSIGNED transaction

