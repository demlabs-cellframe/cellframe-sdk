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

#include "dap_chain_net_srv_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_datum.h"
#include "dap_chain_tx_sign.h"
#include "dap_chain_ledger.h"
#include "dap_common.h"

#define LOG_TAG "dap_net_srv_tx"

/**
 * @brief Create conditional output transaction (PURE)
 */
dap_chain_datum_tx_t *dap_net_srv_tx_create_cond_output(
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
        log_it(L_ERROR, "Invalid parameters for net_srv_tx_create_cond_output");
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
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
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
    
    log_it(L_INFO, "Created unsigned conditional output transaction (net/srv)");
    return l_tx;
}

// ============================================================================
// TX Compose API Integration (Callback wrapper + registration)
// ============================================================================

/**
 * @brief Parameters structure for cond_output callback
 */
typedef struct {
    dap_hash_fast_t *pkey_cond_hash;
    const char *ticker;
    uint256_t value;
    uint256_t value_per_unit_max;
    dap_chain_net_srv_price_unit_uid_t unit;
    dap_chain_srv_uid_t srv_uid;
    uint256_t fee;
    const void *cond;
    size_t cond_size;
    const char *wallet_name;  // For signing
} net_srv_cond_output_params_t;

/**
 * @brief TX Compose callback для cond_output
 */
static dap_chain_datum_t* s_net_srv_cond_output_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    net_srv_cond_output_params_t *l_params = (net_srv_cond_output_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid cond_output parameters");
        return NULL;
    }
    
    // 1. Build unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_net_srv_tx_create_cond_output(
        a_list_used_outs,
        l_params->pkey_cond_hash,
        l_params->ticker,
        l_params->value,
        l_params->value_per_unit_max,
        l_params->unit,
        l_params->srv_uid,
        l_params->fee,
        l_params->cond,
        l_params->cond_size
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build cond_output TX");
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
        log_it(L_ERROR, "Failed to sign cond_output TX");
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

// ============================================================================
// COND INPUT TX Builder (for spending conditional outputs with receipt)
// ============================================================================

/**
 * @brief Create conditional input transaction (spend conditional output)
 * 
 * This creates a TX that spends a conditional output using a receipt
 */
dap_chain_datum_tx_t *dap_net_srv_tx_create_cond_input(
    dap_hash_fast_t *a_tx_prev_hash,
    uint32_t a_tx_out_prev_idx,
    dap_chain_datum_tx_receipt_t *a_receipt,
    const dap_chain_addr_t *a_addr_to,
    uint256_t a_value,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX]
)
{
    if (!a_tx_prev_hash || !a_receipt || !a_addr_to || !a_token_ticker) {
        log_it(L_ERROR, "Invalid parameters for cond_input TX");
        return NULL;
    }
    
    // Create transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        return NULL;
    }
    
    // Add conditional input (spending previous conditional output)
    // NOTE: receipt_idx comes from receipt_info - it's the index in receipt chain
    uint32_t l_receipt_idx = 0;  // For now use 0, proper idx should be tracked in receipt flow
    if (dap_chain_datum_tx_add_in_cond_item(&l_tx, a_tx_prev_hash, a_tx_out_prev_idx, l_receipt_idx) != 1) {
        log_it(L_ERROR, "Failed to add conditional input");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add receipt (use actual receipt size from structure)
    if (dap_chain_datum_tx_add_item(&l_tx, (byte_t *)a_receipt) != 1) {
        log_it(L_ERROR, "Failed to add receipt");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add output to destination
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, a_value, a_token_ticker) != 1) {
        log_it(L_ERROR, "Failed to add output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Created unsigned conditional input transaction");
    return l_tx;
}

/**
 * @brief Parameters for cond_input compose callback
 */
typedef struct {
    dap_hash_fast_t *tx_prev_hash;
    uint32_t tx_out_prev_idx;
    dap_chain_datum_tx_receipt_t *receipt;
    const dap_chain_addr_t *addr_to;
    uint256_t value;
    const char *ticker;
    const char *wallet_name;
} net_srv_cond_input_params_t;

/**
 * @brief Compose callback for cond_input TX
 */
static dap_chain_datum_t* s_net_srv_cond_input_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    (void)a_list_used_outs;  // Not used for cond_input - it spends specific cond output
    
    net_srv_cond_input_params_t *l_params = (net_srv_cond_input_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid cond_input parameters");
        return NULL;
    }
    
    // 1. Build unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_net_srv_tx_create_cond_input(
        l_params->tx_prev_hash,
        l_params->tx_out_prev_idx,
        l_params->receipt,
        l_params->addr_to,
        l_params->value,
        l_params->ticker
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create cond_input TX");
        return NULL;
    }
    
    // 2. Sign with wallet
    size_t l_tx_size_for_sign = dap_chain_datum_tx_get_size(l_tx);
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, l_params->wallet_name, l_tx, l_tx_size_for_sign, 0);
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign cond_input TX");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    // Add signature to TX (NOTE: takes pointer to sign, not double pointer)
    size_t l_sign_size = dap_sign_get_size(l_sign);
    if (dap_chain_datum_tx_add_item(&l_tx, (byte_t *)l_sign) != 1) {
        log_it(L_ERROR, "Failed to add signature to cond_input TX");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_sign);
    
    // 3. Convert to datum
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to create datum for cond_input TX");
        return NULL;
    }
    
    log_it(L_INFO, "Created and signed cond_input TX datum (net/srv)");
    return l_datum;
}

/**
 * @brief Register net/srv TX builders in TX Compose API
 */
int dap_net_srv_tx_builders_register(void)
{
    log_it(L_INFO, "Registering net/srv TX builders...");
    
    int l_ret = dap_chain_tx_compose_register("cond_output", s_net_srv_cond_output_compose_cb, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register 'cond_output' builder");
        return l_ret;
    }
    
    l_ret = dap_chain_tx_compose_register("cond_input", s_net_srv_cond_input_compose_cb, NULL);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register 'cond_input' builder");
        return l_ret;
    }
    
    log_it(L_NOTICE, "Net/srv TX builders registered successfully (cond_output, cond_input)");
    return 0;
}

/**
 * @brief Unregister net/srv TX builders
 */
void dap_net_srv_tx_builders_unregister(void)
{
    log_it(L_INFO, "Unregistering net/srv TX builders...");
    dap_chain_tx_compose_unregister("cond_output");
    dap_chain_tx_compose_unregister("cond_input");
    log_it(L_NOTICE, "Net/srv TX builders unregistered");
}

