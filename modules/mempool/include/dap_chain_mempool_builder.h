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
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_create.h"
#include "dap_chain_ledger.h"

/**
 * @brief Mempool Builder API - high-level transaction creation with ledger integration
 * 
 * This is the top layer that combines:
 * - TX Builder (creates unsigned transactions)
 * - Ledger Sign API (signs transactions via wallet callbacks)
 * - Mempool (accepts signed transactions)
 * 
 * Architecture:
 * 1. Create unsigned TX via TX Builder
 * 2. Sign TX via Ledger Sign API (wallet callback)
 * 3. Add signature to TX
 * 4. Submit to mempool
 * 
 * Hardware wallet friendly:
 * - Signing happens via wallet callback (may wait up to 30s)
 * - No direct access to private keys
 * - Clean separation of concerns
 */

/**
 * @brief Create and submit transfer transaction
 * 
 * High-level function that:
 * 1. Creates unsigned transfer TX
 * 2. Signs it via ledger wallet callback
 * 3. Submits to mempool
 * 
 * @param a_ledger Ledger instance
 * @param a_wallet_name Wallet name for signing
 * @param a_chain Target chain
 * @param a_addr_from Source address
 * @param a_addr_to Destination address
 * @param a_token_ticker Token ticker
 * @param a_value Transfer amount
 * @param a_value_fee Fee amount
 * @param a_hash_out_type Hash output format
 * @return Transaction hash string or NULL on error
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
);

/**
 * @brief Create and submit multi-transfer transaction
 */
char *dap_chain_mempool_tx_create_and_submit_multi_transfer(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    dap_chain_t *a_chain,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t **a_addr_to,
    uint256_t *a_values,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value_fee,
    size_t a_outputs_count,
    dap_time_t *a_time_unlock,
    const char *a_hash_out_type
);

/**
 * @brief Create and submit conditional output transaction
 */
char *dap_chain_mempool_tx_create_and_submit_cond_output(
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
    size_t a_cond_size,
    const char *a_hash_out_type
);

/**
 * @brief Create and submit event transaction
 */
char *dap_chain_mempool_tx_create_and_submit_event(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    const char *a_service_wallet_name,
    dap_chain_t *a_chain,
    dap_chain_srv_uid_t a_srv_uid,
    const char *a_group_name,
    uint16_t a_event_type,
    const void *a_event_data,
    size_t a_event_data_size,
    uint256_t a_value_fee,
    const char *a_hash_out_type
);

/**
 * @brief Create and submit base transaction from emission
 */
char *dap_chain_mempool_tx_create_and_submit_from_emission(
    dap_ledger_t *a_ledger,
    const char *a_wallet_name,
    dap_chain_t *a_chain,
    dap_chain_hash_fast_t *a_emission_hash,
    dap_chain_id_t a_emission_chain_id,
    uint256_t a_emission_value,
    const char *a_ticker,
    dap_chain_addr_t *a_addr_to,
    uint256_t a_value_fee,
    const char *a_hash_out_type
);

