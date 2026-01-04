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

#include "dap_chain_ledger_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_datum.h"
#include "dap_chain_tx_sign.h"
#include "dap_chain_ledger.h"
#include "dap_common.h"

#define LOG_TAG "dap_ledger_tx"

/**
 * @brief Create event transaction (PURE)
 */
dap_chain_datum_tx_t *dap_ledger_tx_create_event(
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
        log_it(L_ERROR, "Invalid parameters for ledger_tx_create_event");
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
        
        if (dap_chain_datum_tx_add_in_item(&l_tx, &l_used_out->tx_prev_hash, l_used_out->tx_out_prev_idx) != 1) {
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
    
    log_it(L_INFO, "Created unsigned event transaction (ledger)");
    return l_tx;
}

/**
 * @brief Create base transaction from emission (PURE)
 */
dap_chain_datum_tx_t *dap_ledger_tx_create_from_emission(
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
        log_it(L_ERROR, "Invalid parameters for ledger_tx_create_from_emission");
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
    
    log_it(L_INFO, "Created unsigned emission transaction (ledger)");
    return l_tx;
}

// ============================================================================
// TX Compose API Integration (Callback wrappers + registration)
// ============================================================================

/**
 * @brief Parameters structure for event callback
 */
typedef struct {
    dap_pkey_t *pkey_service;
    dap_chain_srv_uid_t srv_uid;
    const char *group_name;
    uint16_t event_type;
    const void *event_data;
    size_t event_data_size;
    uint256_t fee;
    const char *wallet_name;  // For signing
} ledger_event_params_t;

/**
 * @brief Parameters structure for emission callback
 */
typedef struct {
    dap_chain_hash_fast_t *emission_hash;
    dap_chain_id_t emission_chain_id;
    uint256_t emission_value;
    const char *ticker;
    dap_chain_addr_t *addr_to;
    uint256_t fee;
    const char *wallet_name;  // For signing
} ledger_emission_params_t;

/**
 * @brief TX Compose callback для event
 */
static dap_chain_datum_t* s_ledger_event_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    ledger_event_params_t *l_params = (ledger_event_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid event parameters");
        return NULL;
    }
    
    // 1. Build unsigned TX
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_create_event(
        a_list_used_outs,
        l_params->pkey_service,
        l_params->srv_uid,
        l_params->group_name,
        l_params->event_type,
        l_params->event_data,
        l_params->event_data_size,
        l_params->fee
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build event TX");
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
        log_it(L_ERROR, "Failed to sign event TX");
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
 * @brief TX Compose callback для emission
 */
static dap_chain_datum_t* s_ledger_emission_compose_cb(
    dap_ledger_t *a_ledger,
    dap_list_t *a_list_used_outs,
    void *a_params
)
{
    ledger_emission_params_t *l_params = (ledger_emission_params_t *)a_params;
    if (!l_params || !l_params->wallet_name) {
        log_it(L_ERROR, "Invalid emission parameters");
        return NULL;
    }
    
    // 1. Build unsigned TX (no UTXO needed, emission is input)
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_create_from_emission(
        l_params->emission_hash,
        l_params->emission_chain_id,
        l_params->emission_value,
        l_params->ticker,
        l_params->addr_to,
        l_params->fee
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build emission TX");
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
        log_it(L_ERROR, "Failed to sign emission TX");
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
 * @brief Register ledger TX builders in TX Compose API
 */
int dap_ledger_tx_builders_register(void)
{
    log_it(L_INFO, "Registering ledger TX builders...");
    
    int l_ret = 0;
    l_ret |= dap_chain_tx_compose_register("event", s_ledger_event_compose_cb, NULL);
    l_ret |= dap_chain_tx_compose_register("emission", s_ledger_emission_compose_cb, NULL);
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to register ledger builders");
        return l_ret;
    }
    
    log_it(L_NOTICE, "Ledger TX builders registered successfully");
    return 0;
}

/**
 * @brief Unregister ledger TX builders
 */
void dap_ledger_tx_builders_unregister(void)
{
    log_it(L_INFO, "Unregistering ledger TX builders...");
    dap_chain_tx_compose_unregister("event");
    dap_chain_tx_compose_unregister("emission");
    log_it(L_NOTICE, "Ledger TX builders unregistered");
}
