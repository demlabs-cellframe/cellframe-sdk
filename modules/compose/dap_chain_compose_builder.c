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

#include "dap_chain_compose_builder.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_common.h"
#include "dap_strfuncs.h"

#define LOG_TAG "dap_chain_compose_builder"

/**
 * @brief PURE TX Builder - Creates unsigned transactions from UTXO
 * 
 * ARCHITECTURE PRINCIPLES:
 * - PURE functions - no side effects
 * - NO network access
 * - NO ledger queries
 * - Accept ALL data as parameters
 * - Zero coupling with external modules
 * 
 * Caller (Orchestrator) finds UTXO via ledger and provides them.
 * Builder just assembles TX structure from UTXO.
 */

/**
 * @brief Create simple transfer transaction (PURE)
 * 
 * Caller must provide pre-found UTXO list via a_list_used_outs
 */
dap_chain_datum_tx_t *dap_chain_compose_tx_transfer(
    dap_list_t *a_list_used_outs,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee
)
{
    // Validate parameters
    if (!a_list_used_outs || !a_addr_to || !a_token_ticker) {
        log_it(L_ERROR, "Invalid parameters for compose_tx_transfer");
        return NULL;
    }
    
    if (IS_ZERO_256(a_value)) {
        log_it(L_ERROR, "Transfer value is zero");
        return NULL;
    }
    
    // Calculate total value from provided UTXO
    uint256_t l_value_found = {};
    const dap_chain_addr_t *a_addr_from = NULL;
    
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (l_used_out) {
            SUM_256_256(l_value_found, l_used_out->value, &l_value_found);
            if (!a_addr_from) {
                a_addr_from = &l_used_out->addr;
            }
        }
    }
    
    if (!a_addr_from) {
        log_it(L_ERROR, "No valid UTXO provided");
        return NULL;
    }
    
    // Calculate total needed
    uint256_t l_total_need = {};
    SUM_256_256(a_value, a_value_fee, &l_total_need);
    
    // Verify we have enough
    if (compare256(l_value_found, l_total_need) < 0) {
        log_it(L_ERROR, "Insufficient UTXO provided: need %s, got %s",
               dap_chain_balance_to_coins(l_total_need),
               dap_chain_balance_to_coins(l_value_found));
        return NULL;
    }
    
    // Create transaction structure
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // Add inputs from provided UTXO
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (!l_used_out) continue;
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_hash, l_used_out->out_idx) != 1) {
            log_it(L_ERROR, "Failed to add input item");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add output to recipient
    if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, a_value) != 1) {
        log_it(L_ERROR, "Failed to add output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add change if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_found, l_total_need, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_change) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add fee if needed
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    log_it(L_INFO, "Created unsigned transfer transaction (PURE)");
    return l_tx;
}

/**
 * @brief Create multi-transfer transaction (PURE)
 */
dap_chain_datum_tx_t *dap_chain_compose_tx_multi_transfer(
    dap_list_t *a_list_used_outs,
    const dap_chain_addr_t **a_addr_to,
    uint256_t *a_values,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value_fee,
    size_t a_outputs_count,
    dap_time_t *a_time_unlock
)
{
    // Validate parameters
    if (!a_list_used_outs || !a_addr_to || !a_values || !a_token_ticker || a_outputs_count == 0) {
        log_it(L_ERROR, "Invalid parameters for compose_tx_multi_transfer");
        return NULL;
    }
    
    // Calculate total value needed
    uint256_t l_total_value = {};
    for (size_t i = 0; i < a_outputs_count; i++) {
        SUM_256_256(l_total_value, a_values[i], &l_total_value);
    }
    
    // Calculate total value from provided UTXO
    uint256_t l_value_found = {};
    const dap_chain_addr_t *a_addr_from = NULL;
    
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (l_used_out) {
            SUM_256_256(l_value_found, l_used_out->value, &l_value_found);
            if (!a_addr_from) {
                a_addr_from = &l_used_out->addr;
            }
        }
    }
    
    if (!a_addr_from) {
        log_it(L_ERROR, "No valid UTXO provided");
        return NULL;
    }
    
    // Calculate total needed (value + fee)
    uint256_t l_total_need = {};
    SUM_256_256(l_total_value, a_value_fee, &l_total_need);
    
    // Verify we have enough
    if (compare256(l_value_found, l_total_need) < 0) {
        log_it(L_ERROR, "Insufficient UTXO provided");
        return NULL;
    }
    
    // Create transaction structure
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // Add inputs from provided UTXO
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (!l_used_out) continue;
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_hash, l_used_out->out_idx) != 1) {
            log_it(L_ERROR, "Failed to add input item");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add outputs to recipients
    for (size_t i = 0; i < a_outputs_count; i++) {
        dap_time_t l_time_unlock = a_time_unlock ? a_time_unlock[i] : 0;
        
        if (l_time_unlock > 0) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i], a_values[i], NULL, l_time_unlock) != 1) {
                log_it(L_ERROR, "Failed to add output with unlock time");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        } else {
            if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to[i], a_values[i]) != 1) {
                log_it(L_ERROR, "Failed to add output");
                dap_chain_datum_tx_delete(l_tx);
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
            return NULL;
        }
    }
    
    // Add fee if needed
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    log_it(L_INFO, "Created unsigned multi-transfer transaction (PURE)");
    return l_tx;
}

/**
 * @brief Create conditional output transaction (PURE)
 */
dap_chain_datum_tx_t *dap_chain_compose_tx_cond_output(
    dap_list_t *a_list_used_outs,
    dap_hash_fast_t *a_pkey_cond_hash,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_per_unit_max,
    dap_chain_net_srv_price_unit_uid_t a_unit,
    dap_chain_srv_uid_t a_srv_uid,
    uint256_t a_value_fee,
    const void *a_cond,
    size_t a_cond_size
)
{
    // Validate parameters
    if (!a_list_used_outs || !a_pkey_cond_hash || !a_token_ticker || !a_cond) {
        log_it(L_ERROR, "Invalid parameters for compose_tx_cond_output");
        return NULL;
    }
    
    // Calculate total value from provided UTXO
    uint256_t l_value_found = {};
    const dap_chain_addr_t *a_addr_from = NULL;
    
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (l_used_out) {
            SUM_256_256(l_value_found, l_used_out->value, &l_value_found);
            if (!a_addr_from) {
                a_addr_from = &l_used_out->addr;
            }
        }
    }
    
    if (!a_addr_from) {
        log_it(L_ERROR, "No valid UTXO provided");
        return NULL;
    }
    
    // Calculate total needed
    uint256_t l_total_need = {};
    SUM_256_256(a_value, a_value_fee, &l_total_need);
    
    // Verify we have enough
    if (compare256(l_value_found, l_total_need) < 0) {
        log_it(L_ERROR, "Insufficient UTXO provided");
        return NULL;
    }
    
    // Create transaction structure
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // Add inputs from provided UTXO
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (!l_used_out) continue;
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_hash, l_used_out->out_idx) != 1) {
            log_it(L_ERROR, "Failed to add input item");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add conditional output
    if (dap_chain_datum_tx_add_out_cond_item(&l_tx, a_pkey_cond_hash, a_srv_uid, a_value, 
                                              a_value_per_unit_max, a_unit, a_cond, a_cond_size) != 1) {
        log_it(L_ERROR, "Failed to add conditional output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add change if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_found, l_total_need, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_change) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add fee if needed
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    log_it(L_INFO, "Created unsigned conditional output transaction (PURE)");
    return l_tx;
}

/**
 * @brief Create event transaction (PURE)
 */
dap_chain_datum_tx_t *dap_chain_compose_tx_event(
    dap_list_t *a_list_used_outs,
    dap_pkey_t *a_pkey_service,
    dap_chain_srv_uid_t a_srv_uid,
    const char *a_group_name,
    uint16_t a_event_type,
    const void *a_event_data,
    size_t a_event_data_size,
    uint256_t a_value_fee
)
{
    // Validate parameters
    if (!a_list_used_outs || !a_pkey_service || !a_event_data) {
        log_it(L_ERROR, "Invalid parameters for compose_tx_event");
        return NULL;
    }
    
    // Calculate total value from provided UTXO
    uint256_t l_value_found = {};
    const dap_chain_addr_t *a_addr_from = NULL;
    
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (l_used_out) {
            SUM_256_256(l_value_found, l_used_out->value, &l_value_found);
            if (!a_addr_from) {
                a_addr_from = &l_used_out->addr;
            }
        }
    }
    
    if (!a_addr_from) {
        log_it(L_ERROR, "No valid UTXO provided");
        return NULL;
    }
    
    // Verify we have enough for fee
    if (compare256(l_value_found, a_value_fee) < 0) {
        log_it(L_ERROR, "Insufficient UTXO for fee");
        return NULL;
    }
    
    // Create transaction structure
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // Add inputs from provided UTXO
    for (dap_list_t *l_iter = a_list_used_outs; l_iter; l_iter = l_iter->next) {
        dap_chain_tx_used_out_t *l_used_out = (dap_chain_tx_used_out_t *)l_iter->data;
        if (!l_used_out) continue;
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_hash, l_used_out->out_idx) != 1) {
            log_it(L_ERROR, "Failed to add input item");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add event item
    if (dap_chain_datum_tx_add_event_item(&l_tx, a_pkey_service, a_srv_uid, 
                                          a_group_name, a_event_type, 
                                          a_event_data, a_event_data_size) != 1) {
        log_it(L_ERROR, "Failed to add event item");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add change if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_found, a_value_fee, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_from, l_change) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    // Add fee if needed
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    log_it(L_INFO, "Created unsigned event transaction (PURE)");
    return l_tx;
}

/**
 * @brief Create base transaction from emission (PURE)
 */
dap_chain_datum_tx_t *dap_chain_compose_tx_from_emission(
    dap_chain_hash_fast_t *a_emission_hash,
    dap_chain_id_t a_emission_chain_id,
    uint256_t a_emission_value,
    const char *a_ticker,
    dap_chain_addr_t *a_addr_to,
    uint256_t a_value_fee
)
{
    // Validate parameters
    if (!a_emission_hash || !a_ticker || !a_addr_to) {
        log_it(L_ERROR, "Invalid parameters for compose_tx_from_emission");
        return NULL;
    }
    
    if (IS_ZERO_256(a_emission_value)) {
        log_it(L_ERROR, "Emission value is zero");
        return NULL;
    }
    
    // Verify emission value covers output + fee
    uint256_t l_total_need = {};
    SUM_256_256(a_emission_value, a_value_fee, &l_total_need);
    
    // Create transaction structure
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // Add input from emission
    if (dap_chain_datum_tx_add_in_item(&l_tx, a_emission_hash, 0) != 1) {
        log_it(L_ERROR, "Failed to add emission input");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add output to recipient
    uint256_t l_value_out = {};
    SUBTRACT_256_256(a_emission_value, a_value_fee, &l_value_out);
    
    if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, l_value_out) != 1) {
        log_it(L_ERROR, "Failed to add output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add fee if needed
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            log_it(L_ERROR, "Failed to add fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    
    log_it(L_INFO, "Created unsigned emission transaction (PURE)");
    return l_tx;
}

/**
 * @brief CLEAN TX BUILDER - ZERO EXTERNAL DEPENDENCIES!
 * 
 * All 5 functions are PURE:
 * ✅ dap_chain_compose_tx_transfer
 * ✅ dap_chain_compose_tx_multi_transfer
 * ✅ dap_chain_compose_tx_cond_output
 * ✅ dap_chain_compose_tx_event
 * ✅ dap_chain_compose_tx_from_emission
 * 
 * Hardware wallet friendly: Returns unsigned TX
 * Orchestrator responsibility: Find UTXO, sign, convert to datum
 */
