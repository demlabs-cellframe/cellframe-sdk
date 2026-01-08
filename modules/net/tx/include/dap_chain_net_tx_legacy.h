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

#include "dap_chain.h"
#include "dap_chain_datum_tx.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"

// Forward declarations
typedef struct dap_chain_net dap_chain_net_t;
typedef union dap_chain_net_srv_uid dap_chain_net_srv_uid_t;
typedef struct dap_chain_datum_tx_receipt dap_chain_datum_tx_receipt_t;
typedef uint64_t dap_chain_tx_event_type_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Legacy TX creation functions moved from mempool
 * 
 * These functions were incorrectly placed in mempool module, violating
 * Single Responsibility Principle. They have been moved here to wallet-tx.
 * 
 * ARCHITECTURE NOTE:
 * - Mempool should ONLY manage TX storage (add/remove/find)
 * - TX creation belongs in wallet-tx or tx_compose modules
 * - These functions use ledger API for UTXO selection
 */

/**
 * @brief Create a transfer transaction
 * 
 * @param a_chain Chain instance
 * @param a_key_from Source private key
 * @param a_addr_from Source address
 * @param a_addr_to Array of destination addresses
 * @param a_token_ticker Token ticker
 * @param a_value Array of values to transfer
 * @param a_value_fee Fee value
 * @param a_hash_out_type Hash output type
 * @param a_tx_num Number of outputs
 * @param a_time_unlock Array of unlock times (optional)
 * @return TX hash string or NULL on error
 */
char *dap_chain_net_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
                                  const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t **a_addr_to,
                                  const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX], uint256_t *a_value,
                                  uint256_t a_value_fee, const char *a_hash_out_type,
                                  size_t a_tx_num, dap_time_t *a_time_unlock);

/**
 * @brief Create multiple transfer transactions
 * 
 * @return 0 on success, -2 not enough funds, -1 other error
 */
int dap_chain_net_tx_create_massive(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
                                        const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t *a_addr_to,
                                        const char a_token_ticker[10], uint256_t a_value, uint256_t a_value_fee,
                                        const char *a_hash_out_type, size_t a_tx_num);

/**
 * @brief Create conditional transaction input
 */
char* dap_chain_net_tx_create_cond_input(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
                                             const dap_chain_addr_t *a_addr_from,
                                             dap_enc_key_t *a_key, const dap_chain_addr_t *a_addr_to,
                                             dap_pkey_t *a_seller_pkey, const char *a_token_ticker,
                                             uint256_t a_value, uint256_t a_value_fee,
                                             const char *a_hash_out_type);

/**
 * @brief Create conditional transaction
 */
char *dap_chain_net_tx_create_cond(dap_chain_net_t *a_net,
                                       dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
                                       const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                       uint256_t a_value, uint256_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
                                       dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value_fee,
                                       const void *a_cond, size_t a_cond_size,
                                       const char *a_hash_out_type);

/**
 * @brief Create base transaction from emission
 */
char *dap_chain_net_base_tx_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
                                       dap_chain_id_t a_emission_chain_id,
                                       uint256_t a_emission_value, const char *a_ticker,
                                       const dap_chain_addr_t *a_addr_to, uint256_t a_value,
                                       dap_enc_key_t *a_private_key, const char *a_hash_out_type);

/**
 * @brief Create event transaction
 */
char *dap_chain_net_tx_create_event(dap_chain_t *a_chain,
                                        dap_enc_key_t *a_key_from,
                                        dap_enc_key_t *a_service_key,
                                        dap_chain_net_srv_uid_t a_srv_uid,
                                        const char *a_event_name,
                                        dap_chain_tx_event_type_t a_event_type,
                                        const void *a_event_data, size_t a_event_data_size,
                                        uint256_t a_value_fee,
                                        const char *a_hash_out_type);

#ifdef __cplusplus
}
#endif

