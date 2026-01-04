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
    if (dap_chain_tx_sign(&l_tx, l_sign) != 0) {
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

/**
 * @brief Compose multi-transfer transaction
 */
dap_chain_datum_t *dap_chain_tx_compose_multi_transfer(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    dap_chain_t *a_chain,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t **a_addr_to,
    uint256_t *a_values,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value_fee,
    size_t a_outputs_count,
    dap_time_t *a_time_unlock
)
{
    if (!a_ledger || !a_wallet_name || !a_chain || !a_addr_from || 
        !a_addr_to || !a_values || !a_token_ticker || a_outputs_count == 0) {
        log_it(L_ERROR, "Invalid parameters for tx_compose_multi_transfer");
        return NULL;
    }
    
    dap_pkey_t *l_pkey = dap_ledger_get_pkey(a_ledger, a_wallet_name, 0);
    if (!l_pkey) {
        log_it(L_ERROR, "Failed to get public key from wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    log_it(L_INFO, "Building unsigned multi-transfer transaction (%zu outputs)...", a_outputs_count);
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_multi_transfer(
        a_chain->net_id, l_pkey, a_addr_from, a_addr_to, a_values,
        a_token_ticker, a_value_fee, a_outputs_count, a_time_unlock
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build unsigned multi-transfer transaction");
        return NULL;
    }
    
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Signing multi-transfer with wallet '%s'...", a_wallet_name);
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, a_wallet_name, l_sign_data, l_sign_data_size, 0);
    
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign multi-transfer transaction");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Multi-transfer signed successfully");
    
    if (dap_chain_tx_sign(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Converting multi-transfer to datum...");
    dap_chain_datum_t *l_datum = dap_chain_datum_from_tx(l_tx);
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to convert multi-transfer to datum");
        return NULL;
    }
    
    log_it(L_NOTICE, "Multi-transfer composed successfully (%zu outputs)", a_outputs_count);
    return l_datum;
}

/**
 * @brief Compose conditional output transaction
 */
dap_chain_datum_t *dap_chain_tx_compose_cond_output(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    dap_chain_t *a_chain,
    const dap_chain_addr_t *a_addr_from,
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
    if (!a_ledger || !a_wallet_name || !a_chain || !a_addr_from || 
        !a_pkey_cond_hash || !a_token_ticker) {
        log_it(L_ERROR, "Invalid parameters for tx_compose_cond_output");
        return NULL;
    }
    
    dap_pkey_t *l_pkey = dap_ledger_get_pkey(a_ledger, a_wallet_name, 0);
    if (!l_pkey) {
        log_it(L_ERROR, "Failed to get public key from wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    log_it(L_INFO, "Building unsigned conditional output (service 0x%016"DAP_UINT64_FORMAT_x")...",
           a_srv_uid.uint64);
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_cond_output(
        a_chain->net_id, l_pkey, a_addr_from, a_pkey_cond_hash, a_token_ticker,
        a_value, a_value_per_unit_max, a_unit, a_srv_uid, a_value_fee, a_cond, a_cond_size
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build unsigned conditional output");
        return NULL;
    }
    
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Signing conditional output with wallet '%s'...", a_wallet_name);
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, a_wallet_name, l_sign_data, l_sign_data_size, 0);
    
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign conditional output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Conditional output signed successfully");
    
    if (dap_chain_tx_sign(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Converting conditional output to datum...");
    dap_chain_datum_t *l_datum = dap_chain_datum_from_tx(l_tx);
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to convert conditional output to datum");
        return NULL;
    }
    
    log_it(L_NOTICE, "Conditional output composed (service 0x%016"DAP_UINT64_FORMAT_x")",
           a_srv_uid.uint64);
    return l_datum;
}

/**
 * @brief Compose event transaction
 */
dap_chain_datum_t *dap_chain_tx_compose_event(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    const char *a_service_wallet_name,
    dap_chain_t *a_chain,
    dap_chain_srv_uid_t a_srv_uid,
    const char *a_group_name,
    uint16_t a_event_type,
    const void *a_event_data,
    size_t a_event_data_size,
    uint256_t a_value_fee
)
{
    if (!a_ledger || !a_wallet_name || !a_service_wallet_name || 
        !a_chain || !a_group_name) {
        log_it(L_ERROR, "Invalid parameters for tx_compose_event");
        return NULL;
    }
    
    dap_pkey_t *l_pkey_from = dap_ledger_get_pkey(a_ledger, a_wallet_name, 0);
    if (!l_pkey_from) {
        log_it(L_ERROR, "Failed to get public key from wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    dap_pkey_t *l_pkey_service = dap_ledger_get_pkey(a_ledger, a_service_wallet_name, 0);
    if (!l_pkey_service) {
        log_it(L_ERROR, "Failed to get service public key from wallet '%s'", a_service_wallet_name);
        return NULL;
    }
    
    log_it(L_INFO, "Building unsigned event (group '%s', type %u)...", a_group_name, a_event_type);
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_event(
        a_chain->net_id, l_pkey_from, l_pkey_service, a_srv_uid,
        a_group_name, a_event_type, a_event_data, a_event_data_size, a_value_fee
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build unsigned event");
        return NULL;
    }
    
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Signing event with wallet '%s'...", a_wallet_name);
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, a_wallet_name, l_sign_data, l_sign_data_size, 0);
    
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign event");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Event signed successfully");
    
    if (dap_chain_tx_sign(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Converting event to datum...");
    dap_chain_datum_t *l_datum = dap_chain_datum_from_tx(l_tx);
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to convert event to datum");
        return NULL;
    }
    
    log_it(L_NOTICE, "Event composed (group '%s', type %u)", a_group_name, a_event_type);
    return l_datum;
}

/**
 * @brief Compose base transaction from emission
 */
dap_chain_datum_t *dap_chain_tx_compose_from_emission(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    dap_chain_t *a_chain,
    dap_chain_hash_fast_t *a_emission_hash,
    dap_chain_id_t a_emission_chain_id,
    uint256_t a_emission_value,
    const char *a_ticker,
    dap_chain_addr_t *a_addr_to,
    uint256_t a_value_fee
)
{
    if (!a_ledger || !a_wallet_name || !a_chain || !a_emission_hash || 
        !a_ticker || !a_addr_to) {
        log_it(L_ERROR, "Invalid parameters for tx_compose_from_emission");
        return NULL;
    }
    
    dap_pkey_t *l_pkey = dap_ledger_get_pkey(a_ledger, a_wallet_name, 0);
    if (!l_pkey) {
        log_it(L_ERROR, "Failed to get public key from wallet '%s'", a_wallet_name);
        return NULL;
    }
    
    char l_emission_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_emission_hash, l_emission_hash_str, sizeof(l_emission_hash_str));
    
    log_it(L_INFO, "Building unsigned base transaction from emission %s...", l_emission_hash_str);
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_from_emission(
        a_chain->net_id, a_emission_hash, a_emission_chain_id,
        a_emission_value, a_ticker, a_addr_to, a_value_fee
    );
    
    if (!l_tx) {
        log_it(L_ERROR, "Failed to build unsigned base transaction");
        return NULL;
    }
    
    size_t l_sign_data_size = 0;
    const void *l_sign_data = dap_chain_tx_get_signing_data(l_tx, &l_sign_data_size);
    if (!l_sign_data) {
        log_it(L_ERROR, "Failed to get signing data");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Signing base transaction with wallet '%s'...", a_wallet_name);
    dap_sign_t *l_sign = dap_ledger_sign_data(a_ledger, a_wallet_name, l_sign_data, l_sign_data_size, 0);
    
    if (!l_sign) {
        log_it(L_ERROR, "Failed to sign base transaction");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Base transaction signed successfully");
    
    if (dap_chain_tx_sign(&l_tx, l_sign) != 0) {
        log_it(L_ERROR, "Failed to add signature");
        DAP_DELETE(l_sign);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    
    log_it(L_INFO, "Converting base transaction to datum...");
    dap_chain_datum_t *l_datum = dap_chain_datum_from_tx(l_tx);
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to convert base transaction to datum");
        return NULL;
    }
    
    log_it(L_NOTICE, "Base transaction from emission %s composed successfully", l_emission_hash_str);
    return l_datum;
}

/**
 * ✅ ALL COMPOSER FUNCTIONS COMPLETE!
 * 
 * Perfect 7-step pattern implemented in ALL 5 functions:
 * 1. Validate parameters (fail fast)
 * 2. Get public key from ledger
 * 3. Build unsigned TX (Layer 1: TX Builder)
 * 4. Get signing data
 * 5. Sign via ledger callback (Layer 2: 30s wait)
 * 6. Add signature (Layer 2: TX Signer)
 * 7. Convert to datum (Layer 3: Converter)
 * 
 * Single Responsibility per layer:
 * ✅ Builder - только строит
 * ✅ Signer - только подписывает
 * ✅ Converter - только конвертирует
 * ✅ Composer - только композирует
 * ✅ Mempool - только хранит (не в composer!)
 * 
 * Hardware wallet ready - 30s async signing support
 * Zero coupling - каждый слой независим
 * Fail fast - никаких fallback
 * Clean architecture - идеальное разделение ответственностей
 */

