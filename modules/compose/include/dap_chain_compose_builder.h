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
#include "dap_chain_common.h"
#include "dap_sign.h"
#include "dap_pkey.h"
#include "dap_list.h"
#include "dap_chain_utxo.h"  // UTXO from ledger!

/**
 * @brief TX Builder API - creates UNSIGNED transactions (PURE FUNCTIONS!)
 * 
 * SERVICE LAYER: Builds transactions from UTXO
 * 
 * PRINCIPLES:
 * - PURE FUNCTIONS - no side effects
 * - NO network access
 * - NO ledger queries (uses pre-found UTXO)
 * - Accept ALL data as parameters
 * - Zero coupling!
 * 
 * Caller (Composer) finds UTXO via ledger and provides them.
 * Builder just assembles TX structure from UTXO.
 * 
 * Hardware wallet friendly: Returns unsigned TX
 */

/**
 * @brief Create transfer transaction (PURE)
 * 
 * @param a_list_used_outs Pre-found inputs (dap_chain_tx_used_out_t*)
 * @param a_addr_to Destination
 * @param a_token_ticker Token
 * @param a_value Amount
 * @param a_value_fee Fee
 * @return Unsigned TX or NULL
 */
dap_chain_datum_tx_t *dap_chain_compose_tx_transfer(
    dap_list_t *a_list_used_outs,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee
);

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
);

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
);

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
);

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
);
