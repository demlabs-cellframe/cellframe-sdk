/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
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

#include "dap_chain_wallet_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_datum.h"
#include "dap_chain_tx_sign.h"
#include "dap_chain_ledger.h"
#include "dap_common.h"

#define LOG_TAG "dap_wallet_tx"

/**
 * @brief Create simple transfer transaction (PURE)
 */
dap_chain_datum_tx_t *dap_wallet_tx_create_transfer(
    dap_list_t *a_list_used_outs,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee
)
{
    // Validate parameters
    if (!a_list_used_outs || !a_addr_to || !a_token_ticker) {
        log_it(L_ERROR, "Invalid parameters for wallet_tx_create_transfer");
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
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
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
    
    log_it(L_INFO, "Created unsigned transfer transaction (wallet)");
    return l_tx;
}

/**
 * @brief Create multi-transfer transaction (PURE)
 */
dap_chain_datum_tx_t *dap_wallet_tx_create_multi_transfer(
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
        log_it(L_ERROR, "Invalid parameters for wallet_tx_create_multi_transfer");
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
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
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
    
    log_it(L_INFO, "Created unsigned multi-transfer transaction (wallet)");
    return l_tx;
}

// ============================================================================
// TX Compose API Integration (Callback wrappers + registration)
// ============================================================================

/**
 * @brief Parameters structure for transfer callback
 */
typedef struct {
    const dap_chain_addr_t *addr_to;
    const char *ticker;
    uint256_t value;
    uint256_t fee;
    const char *wallet_name;  // For signing
} wallet_transfer_params_t;

/**
 * @brief Parameters structure for multi-transfer callback
 */
typedef struct {
    const dap_chain_addr_t **addr_to;
    uint256_t *values;
    const char *ticker;
    uint256_t fee;
    size_t outputs_count;
    dap_time_t *time_unlock;
    const char *wallet_name;  // For signing
} wallet_multi_transfer_params_t;

/**
 * @brief TX Compose callback для transfer
 */
static dap_chain_datum_t* s_wallet_transfer_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    wallet_transfer_params_t *l_params = (wallet_transfer_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid transfer parameters");
        return NULL;
    }
    
    // 1. Build unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_wallet_tx_create_transfer(
        a_list_used_outs,
        l_params->addr_to,
        l_params->ticker,
        l_params->value,
        l_params->fee
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build transfer TX");
        return NULL;
    }
    
    // 2. Get sign data
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 3. Sign via ledger
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, l_params->wallet_name, 
                                                l_sign_data, l_sign_data_size, 0);
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign transfer TX");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 4. Add signature
    if (dap_chain_tx_sign_add(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 5. Convert to datum
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, 
                                                         dap_chain_datum_tx_get_size(l_tx));
    dap_chain_datum_tx_delete(l_tx);
    
    return l_datum;
}

/**
 * @brief TX Compose callback для multi-transfer
 */
static dap_chain_datum_t* s_wallet_multi_transfer_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    wallet_multi_transfer_params_t *l_params = (wallet_multi_transfer_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid multi-transfer parameters");
        return NULL;
    }
    
    // 1. Build unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_wallet_tx_create_multi_transfer(
        a_list_used_outs,
        l_params->addr_to,
        l_params->values,
        l_params->ticker,
        l_params->fee,
        l_params->outputs_count,
        l_params->time_unlock
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build multi-transfer TX");
        return NULL;
    }
    
    // 2. Get sign data
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 3. Sign via ledger
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, l_params->wallet_name, 
                                                l_sign_data, l_sign_data_size, 0);
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign multi-transfer TX");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 4. Add signature
    if (dap_chain_tx_sign_add(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // 5. Convert to datum
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, 
                                                         dap_chain_datum_tx_get_size(l_tx));
    dap_chain_datum_tx_delete(l_tx);
    
    return l_datum;
}

/**
 * @brief Register wallet TX builders in TX Compose API
 */
int dap_wallet_tx_builders_register(void)
{
    log_it(L_INFO, "Registering wallet TX builders...");
    
    int l_ret = dap_chain_tx_compose_register("transfer", s_wallet_transfer_compose_cb, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register 'transfer' builder");
        return l_ret;
    }
    
    l_ret = dap_chain_tx_compose_register("multi_transfer", s_wallet_multi_transfer_compose_cb, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register 'multi_transfer' builder");
        dap_chain_tx_compose_unregister("transfer");
        return l_ret;
    }
    
    log_it(L_NOTICE, "Wallet TX builders registered successfully");
    return 0;
}

/**
 * @brief Unregister wallet TX builders
 */
void dap_wallet_tx_builders_unregister(void)
{
    log_it(L_INFO, "Unregistering wallet TX builders...");
    dap_chain_tx_compose_unregister("transfer");
    dap_chain_tx_compose_unregister("multi_transfer");
    log_it(L_NOTICE, "Wallet TX builders unregistered");
}

