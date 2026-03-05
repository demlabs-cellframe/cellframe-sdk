/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2026
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
#include "dap_list.h"

/**
 * @brief TX Builder API - creates UNSIGNED transactions (PURE FUNCTIONS)
 *
 * LAYER 1: Foundation - creates transaction structures WITHOUT signatures
 *
 * Single Responsibility: Build TX structures from provided data
 *
 * PURE FUNCTIONS:
 * - NO network access
 * - NO ledger access
 * - NO database queries
 * - Accept ALL data as parameters
 * - Zero coupling!
 *
 * Hardware wallet friendly: Returns unsigned TX for external signing
 *
 * UTXO INPUT:
 * Functions that spend existing tokens accept a_utxo_list (dap_list_t of
 * dap_chain_tx_used_out_item_t*). The caller obtains this list via ledger
 * queries and passes it here. The builder never touches the ledger.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create simple transfer transaction WITHOUT signature
 *
 * @param a_net_id          Network ID
 * @param a_addr_from       Source address (also used for change output)
 * @param a_addr_to         Destination address
 * @param a_token_ticker    Token ticker
 * @param a_value           Transfer amount
 * @param a_value_fee       Fee amount (0 = no fee)
 * @param a_utxo_list       List of dap_chain_tx_used_out_item_t* (pre-found UTXOs)
 * @return Transaction pointer (unsigned) or NULL on error. Must be freed by caller.
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_transfer(
    dap_chain_net_id_t a_net_id,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee,
    dap_list_t *a_utxo_list
);

/**
 * @brief Create multi-output transfer transaction WITHOUT signature
 *
 * @param a_net_id          Network ID
 * @param a_addr_from       Source address (also used for change output)
 * @param a_addr_to         Array of destination addresses
 * @param a_values          Array of transfer amounts
 * @param a_token_ticker    Token ticker
 * @param a_value_fee       Fee amount (0 = no fee)
 * @param a_outputs_count   Number of outputs
 * @param a_time_unlock     Optional per-output unlock times (can be NULL)
 * @param a_utxo_list       List of dap_chain_tx_used_out_item_t*
 * @return Transaction pointer (unsigned) or NULL on error
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_multi_transfer(
    dap_chain_net_id_t a_net_id,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t **a_addr_to,
    uint256_t *a_values,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value_fee,
    size_t a_outputs_count,
    dap_time_t *a_time_unlock,
    dap_list_t *a_utxo_list
);

/**
 * @brief Create conditional output transaction WITHOUT signature
 *
 * @param a_net_id              Network ID
 * @param a_addr_from           Source address (for change output)
 * @param a_pkey_cond_hash      Public key hash for condition
 * @param a_token_ticker        Token ticker
 * @param a_value               Value to lock in condition
 * @param a_value_per_unit_max  Max value per unit
 * @param a_unit                Price unit
 * @param a_srv_uid             Service UID
 * @param a_value_fee           Fee amount (0 = no fee)
 * @param a_cond                Custom condition data (optional)
 * @param a_cond_size           Condition data size
 * @param a_utxo_list           List of dap_chain_tx_used_out_item_t*
 * @return Transaction pointer (unsigned) or NULL on error
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_cond_output(
    dap_chain_net_id_t a_net_id,
    const dap_chain_addr_t *a_addr_from,
    dap_hash_sha3_256_t *a_pkey_cond_hash,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_per_unit_max,
    dap_chain_net_srv_price_unit_uid_t a_unit,
    dap_chain_srv_uid_t a_srv_uid,
    uint256_t a_value_fee,
    const void *a_cond,
    size_t a_cond_size,
    dap_list_t *a_utxo_list
);

/**
 * @brief Create base transaction from emission WITHOUT signature
 *
 * No UTXOs needed: the emission itself is the source.
 * If a_value_fee > 0 it is deducted from a_emission_value.
 *
 * @param a_net_id              Network ID
 * @param a_emission_hash       Emission hash
 * @param a_emission_chain_id   Emission chain ID
 * @param a_emission_value      Emission value (total tokens minted)
 * @param a_ticker              Token ticker
 * @param a_addr_to             Destination address
 * @param a_value_fee           Fee amount (0 = no fee, deducted from emission)
 * @return Transaction pointer (unsigned) or NULL on error
 */
dap_chain_datum_tx_t *dap_chain_datum_tx_create_from_emission(
    dap_chain_net_id_t a_net_id,
    dap_hash_sha3_256_t *a_emission_hash,
    dap_chain_id_t a_emission_chain_id,
    uint256_t a_emission_value,
    const char *a_ticker,
    const dap_chain_addr_t *a_addr_to,
    uint256_t a_value_fee
);

#ifdef __cplusplus
}
#endif
