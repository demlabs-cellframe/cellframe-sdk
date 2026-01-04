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
#include "dap_chain_net_srv.h"
#include "dap_list.h"

/**
 * @file dap_chain_net_srv_tx.h
 * @brief Network Service TX creation functions
 * 
 * Service-related TX operations:
 * - Conditional output - TX для сервисов с условиями
 * 
 * Эти функции регистрируются в TX Compose API при инициализации net/srv модуля
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create conditional output transaction (PURE)
 * 
 * @param a_list_used_outs Pre-found UTXO inputs
 * @param a_pkey_cond_hash Public key hash for condition
 * @param a_token_ticker Token ticker
 * @param a_value Value to lock
 * @param a_value_per_unit_max Max value per unit
 * @param a_unit Price unit
 * @param a_srv_uid Service UID
 * @param a_value_fee Fee amount
 * @param a_cond Condition data
 * @param a_cond_size Condition data size
 * @return Unsigned TX or NULL on error
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
);

/**
 * @brief Register net/srv TX builders in TX Compose API
 * 
 * Called automatically during net/srv module initialization
 * 
 * @return 0 on success, negative on error
 */
int dap_net_srv_tx_builders_register(void);

/**
 * @brief Unregister net/srv TX builders
 * 
 * Called automatically during net/srv module deinitialization
 */
void dap_net_srv_tx_builders_unregister(void);

#ifdef __cplusplus
}
#endif

