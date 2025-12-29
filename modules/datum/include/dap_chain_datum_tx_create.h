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

/**
 * @brief TX Builder API - creates transactions WITHOUT signatures
 * 
 * This is the foundation layer for hardware wallet support.
 * All functions create transaction structures without signing them.
 * Signatures are added separately via dap_chain_datum_tx_add_sign().
 * 
 * Architecture:
 * 1. Create TX structure (this API)
 * 2. Sign TX data (via ledger sign API or hardware wallet)
 * 3. Add signature to TX
 * 4. Submit to mempool
 */

/**
 * @brief Create simple transfer transaction WITHOUT signature
 * 
 * Creates an unsigned transaction for transferring tokens.
 * Caller must add signature(s) using dap_chain_datum_tx_add_sign_item() before submitting to mempool.
 * 
 * @param a_net_id Network ID
 * @param a_pkey_from Public key of sender (for address calculation)
 * @param a_addr_from Source address
 * @param a_addr_to Destination address
 * @param a_token_ticker Token ticker
 * @param a_value Transfer amount
 * @param a_value_fee Fee amount
 * @return Transaction pointer (unsigned) or NULL on error. Must be freed by caller.
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_transfer(
    dap_chain_net_id_t a_net_id,
    dap_pkey_t *a_pkey_from,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee
);

/**
 * @brief Create multi-output transfer transaction WITHOUT signature
 * 
 * @param a_net_id Network ID
 * @param a_pkey_from Public key of sender
 * @param a_addr_from Source address
 * @param a_addr_to Array of destination addresses
 * @param a_values Array of transfer amounts
 * @param a_token_ticker Token ticker
 * @param a_value_fee Fee amount
 * @param a_outputs_count Number of outputs
 * @param a_time_unlock Optional unlock time for outputs (can be NULL)
 * @return Transaction pointer (unsigned) or NULL on error
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
);

/**
 * @brief Create conditional output transaction WITHOUT signature
 * 
 * @param a_net_id Network ID
 * @param a_pkey_from Public key of sender
 * @param a_addr_from Source address
 * @param a_pkey_cond_hash Public key hash for condition
 * @param a_token_ticker Token ticker
 * @param a_value Value to lock
 * @param a_value_per_unit_max Max value per unit
 * @param a_unit Price unit
 * @param a_srv_uid Service UID
 * @param a_value_fee Fee amount
 * @param a_cond Custom condition data (optional)
 * @param a_cond_size Condition data size
 * @return Transaction pointer (unsigned) or NULL on error
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_cond_output(
    dap_chain_net_id_t a_net_id,
    dap_pkey_t *a_pkey_from,
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
 * @brief Create event transaction WITHOUT signature
 * 
 * @param a_net_id Network ID
 * @param a_pkey_from Public key of sender
 * @param a_pkey_service Public key of service
 * @param a_srv_uid Service UID
 * @param a_group_name Event group name
 * @param a_event_type Event type
 * @param a_event_data Event data
 * @param a_event_data_size Event data size
 * @param a_value_fee Fee amount
 * @return Transaction pointer (unsigned) or NULL on error
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_event(
    dap_chain_net_id_t a_net_id,
    dap_pkey_t *a_pkey_from,
    dap_pkey_t *a_pkey_service,
    dap_chain_srv_uid_t a_srv_uid,
    const char *a_group_name,
    uint16_t a_event_type,
    const void *a_event_data,
    size_t a_event_data_size,
    uint256_t a_value_fee
);

/**
 * @brief Create base transaction from emission WITHOUT signature
 * 
 * @param a_net_id Network ID
 * @param a_emission_hash Emission hash
 * @param a_emission_chain_id Emission chain ID
 * @param a_emission_value Emission value
 * @param a_ticker Token ticker
 * @param a_addr_to Destination address
 * @param a_value_fee Fee amount
 * @return Transaction pointer (unsigned) or NULL on error
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_from_emission(
    dap_chain_net_id_t a_net_id,
    dap_chain_hash_fast_t *a_emission_hash,
    dap_chain_id_t a_emission_chain_id,
    uint256_t a_emission_value,
    const char *a_ticker,
    dap_chain_addr_t *a_addr_to,
    uint256_t a_value_fee
);

/**
 * @brief Add signature to unsigned transaction
 * 
 * This function adds a signature item to the transaction.
 * For hardware wallet support, the signature is obtained externally
 * (via dap_ledger_sign_data) and then added to the transaction.
 * 
 * @param a_tx Transaction pointer (will be reallocated)
 * @param a_sign Signature to add
 * @return 1 on success, 0 on error
 */
int dap_chain_datum_tx_add_sign(dap_chain_datum_tx_t **a_tx, dap_sign_t *a_sign);

/**
 * @brief Get transaction data for signing
 * 
 * Extracts the exact data that needs to be signed.
 * This data should be passed to dap_ledger_sign_data().
 * 
 * @param a_tx Transaction pointer
 * @param a_data_size Output: size of data to sign
 * @return Pointer to data buffer (must NOT be freed by caller, it's part of TX)
 */
const void *dap_chain_datum_tx_get_sign_data(const dap_chain_datum_tx_t *a_tx, size_t *a_data_size);

