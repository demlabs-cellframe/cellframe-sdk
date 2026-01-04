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

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_tx_builder.h"
#include "dap_chain_tx_sign.h"
#include "dap_chain_datum_converter.h"
#include "dap_chain_ledger.h"

/**
 * @brief TX Composer API - high-level composition layer
 * 
 * LAYER 4: Composition layer (uses all lower layers)
 * 
 * Responsibility: Orchestrate TX creation flow
 * - Create unsigned TX (via TX Builder)
 * - Sign TX (via TX Signer + Ledger callbacks)
 * - Convert to Datum (via Converter)
 * 
 * Does NOT submit to mempool - that's caller's responsibility!
 * 
 * Hardware wallet friendly:
 * - Uses ledger callbacks for signing (may wait 30s)
 * - No direct key access
 * - Clean error handling
 */

/**
 * @brief Compose transfer transaction (create + sign + convert)
 * 
 * @param a_ledger Ledger instance (for signing callback)
 * @param a_wallet_name Wallet name for signing
 * @param a_chain Target chain
 * @param a_addr_from Source address
 * @param a_addr_to Destination address
 * @param a_token_ticker Token ticker
 * @param a_value Transfer amount
 * @param a_value_fee Fee amount
 * @return Signed datum ready for mempool, or NULL on error (caller must free)
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
);

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
);

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
);

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
);

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
);

