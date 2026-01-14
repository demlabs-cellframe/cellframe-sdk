/*
 * Authors:
 * CellFrame Team <https://cellframe.net>
 * DeM Labs Inc.   <https://demlabs.net>
 * DeM Labs Open source community <https://gitlab.demlabs.net>
 *
 * Copyright  (c) 2017-2025
 * All rights reserved.

 * This file is part of CellFrame SDK
 *
 * CellFrame SDK is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CellFrame SDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "dap_chain_type_blocks.h"
#include "dap_enc_key.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_ledger.h"

/**
 * @brief Creates a transaction to collect fees from blocks
 * @param a_blocks Block structure
 * @param a_key_from Private key for signing
 * @param a_addr_to Destination address
 * @param a_block_list List of block hashes to collect fees from
 * @param a_ledger Ledger instance
 * @param a_native_ticker Native token ticker
 * @param a_net_id Network ID
 * @param a_value_fee Validator fee
 * @param a_hash_out_type Hash output type
 * @return Transaction hash string on success, NULL on error
 */
char *dap_chain_block_tx_coll_fee_create(dap_chain_type_blocks_t *a_blocks, 
                                         dap_enc_key_t *a_key_from,
                                         const dap_chain_addr_t *a_addr_to, 
                                         dap_list_t *a_block_list,
                                         dap_ledger_t *a_ledger,
                                         const char *a_native_ticker,
                                         dap_chain_net_id_t a_net_id,
                                         uint256_t a_value_fee, 
                                         const char *a_hash_out_type);

/**
 * @brief Creates a transaction to collect block sign rewards
 * @param a_blocks Block structure
 * @param a_sign_key Private key for signing
 * @param a_addr_to Destination address
 * @param a_block_list List of block hashes to collect rewards from
 * @param a_ledger Ledger instance
 * @param a_native_ticker Native token ticker
 * @param a_net_id Network ID
 * @param a_value_fee Validator fee
 * @param a_hash_out_type Hash output type
 * @return Transaction hash string on success, NULL on error
 */
char *dap_chain_block_tx_reward_create(dap_chain_type_blocks_t *a_blocks, 
                                       dap_enc_key_t *a_sign_key,
                                       dap_chain_addr_t *a_addr_to, 
                                       dap_list_t *a_block_list,
                                       dap_ledger_t *a_ledger,
                                       const char *a_native_ticker,
                                       dap_chain_net_id_t a_net_id,
                                       uint256_t a_value_fee, 
                                       const char *a_hash_out_type);

/**
 * @brief Creates a transaction to collect stacked fees (pre-hardfork)
 * @param a_blocks Block structure
 * @param a_key_from Private key for signing
 * @param a_addr_to Destination address
 * @param a_ledger Ledger instance
 * @param a_native_ticker Native token ticker
 * @param a_net_id Network ID
 * @param a_value_fee Validator fee
 * @param a_hash_out_type Hash output type
 * @return Transaction hash string on success, NULL on error
 */
char *dap_chain_block_tx_coll_fee_stack_create(dap_chain_type_blocks_t *a_blocks, 
                                               dap_enc_key_t *a_key_from,
                                               const dap_chain_addr_t *a_addr_to,
                                               dap_ledger_t *a_ledger,
                                               const char *a_native_ticker,
                                               dap_chain_net_id_t a_net_id,
                                               uint256_t a_value_fee, 
                                               const char *a_hash_out_type);
