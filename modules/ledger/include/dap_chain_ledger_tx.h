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

#pragma once

#include "dap_chain_datum_tx.h"
#include "dap_chain_common.h"
#include "dap_chain_utxo.h"
#include "dap_list.h"
#include "dap_enc_key.h"

/**
 * @file dap_chain_ledger_tx.h
 * @brief Ledger TX creation functions
 *
 * Ledger-specific TX operations:
 * - Event TX - события в ledger
 * - Emission TX - эмиссия токенов
 *
 * Эти функции регистрируются в TX Compose API при инициализации ledger модуля
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create event transaction (PURE)
 *
 * @param a_list_used_outs Pre-found UTXO inputs for fee
 * @param a_pkey_service Service public key
 * @param a_srv_uid Service UID
 * @param a_group_name Group name
 * @param a_event_type Event type
 * @param a_event_data Event data
 * @param a_event_data_size Event data size
 * @param a_value_fee Fee amount
 * @return Unsigned TX or NULL on error
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
);

/**
 * @brief Create base transaction from emission (PURE)
 *
 * @param a_emission_hash Emission hash
 * @param a_emission_chain_id Chain ID
 * @param a_emission_value Total emission value
 * @param a_ticker Token ticker
 * @param a_addr_to Recipient address
 * @param a_value_fee Fee amount
 * @return Unsigned TX or NULL on error
 */
dap_chain_datum_tx_t *dap_ledger_tx_create_from_emission(
    dap_hash_sha3_256_t *a_emission_hash,
    dap_chain_id_t a_emission_chain_id,
    uint256_t a_emission_value,
    const char *a_ticker,
    dap_chain_addr_t *a_addr_to,
    uint256_t a_value_fee
);

/**
 * @brief Register ledger TX builders in TX Compose API
 *
 * Called automatically during ledger module initialization
 *
 * @return 0 on success, negative on error
 */
int dap_ledger_tx_builders_register(void);

/**
 * @brief Unregister ledger TX builders
 *
 * Called automatically during ledger module deinitialization
 */
void dap_ledger_tx_builders_unregister(void);

#ifdef __cplusplus
}
#endif

