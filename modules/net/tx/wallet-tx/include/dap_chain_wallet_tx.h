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

/**
 * @file dap_chain_wallet_tx.h
 * @brief Wallet TX creation functions (transfer operations)
 * 
 * Базовые операции wallet-to-wallet:
 * - Transfer - простой перевод
 * - Multi-transfer - множественный перевод
 * 
 * Эти функции регистрируются в TX Compose API при инициализации wallet модуля
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create simple transfer transaction (PURE)
 * 
 * @param a_list_used_outs Pre-found UTXO inputs
 * @param a_addr_to Destination address
 * @param a_token_ticker Token ticker
 * @param a_value Transfer amount
 * @param a_value_fee Fee amount
 * @return Unsigned TX or NULL on error
 */
dap_chain_datum_tx_t *dap_wallet_tx_create_transfer(
    dap_list_t *a_list_used_outs,
    const dap_chain_addr_t *a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value,
    uint256_t a_value_fee
);

/**
 * @brief Create multi-transfer transaction (PURE)
 * 
 * @param a_list_used_outs Pre-found UTXO inputs
 * @param a_addr_to Array of destination addresses
 * @param a_values Array of transfer amounts
 * @param a_token_ticker Token ticker
 * @param a_value_fee Fee amount
 * @param a_outputs_count Number of outputs
 * @param a_time_unlock Optional array of unlock times (can be NULL)
 * @return Unsigned TX or NULL on error
 */
dap_chain_datum_tx_t *dap_wallet_tx_create_multi_transfer(
    dap_list_t *a_list_used_outs,
    const dap_chain_addr_t **a_addr_to,
    uint256_t *a_values,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t a_value_fee,
    size_t a_outputs_count,
    dap_time_t *a_time_unlock
);

/**
 * @brief Register wallet TX builders in TX Compose API
 * 
 * Called automatically during wallet module initialization
 * 
 * @return 0 on success, negative on error
 */
int dap_wallet_tx_builders_register(void);

/**
 * @brief Unregister wallet TX builders
 * 
 * Called automatically during wallet module deinitialization
 */
void dap_wallet_tx_builders_unregister(void);

#ifdef __cplusplus
}
#endif

