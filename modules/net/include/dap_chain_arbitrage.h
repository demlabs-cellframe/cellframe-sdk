/*
 * Authors:
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network  https://github.com/demlabs-cellframe
 * Copyright  (c) 2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DAP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdbool.h>
#include "dap_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx.h"

// dap_ledger_token_item_t is now defined in dap_chain_ledger.h

/**
 * @brief Check if transaction is marked as arbitrage
 * @details Arbitrage TX are marked with DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE TSD section.
 *          These transactions allow token owners to claim ANY output (blocked/conditional).
 * @param a_tx Transaction to check
 * @return true if transaction has arbitrage marker, false otherwise
 */
bool dap_chain_arbitrage_tx_is_arbitrage(dap_chain_datum_tx_t *a_tx);

/**
 * @brief Check if arbitrage TX outputs are directed to fee address ONLY
 * @details Arbitrage transactions can ONLY send funds to the network fee collection address.
 *          This prevents abuse where token owners could steal funds via arbitrage.
 *          Fee address is defined in network configuration (a_ledger->net->pub.fee_addr).
 * @param a_ledger Ledger containing network configuration with fee address
 * @param a_tx Transaction to validate
 * @param a_token_item Token item (for logging)
 * @return 0 if all outputs are to fee address, -1 if any output is not to fee address
 */
int dap_chain_arbitrage_tx_check_outputs(dap_ledger_t *a_ledger,
                                         dap_chain_datum_tx_t *a_tx,
                                         dap_ledger_token_item_t *a_token_item);

/**
 * @brief Check arbitrage transaction authorization
 * @details Validates that TX is signed by required number of token owners.
 *          Token owners are determined from token datum (auth_pkeys).
 *          Also validates that all outputs go to network fee address ONLY.
 *          Wallet signature (first signature) is used ONLY for fee payment authorization,
 *          NOT for arbitrage authorization, unless fee token == arbitrage token.
 * @param a_ledger Ledger containing network configuration
 * @param a_tx Transaction to validate
 * @param a_token_item Token item with owner information
 * @return 0 if authorized, -1 if not authorized, DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS if insufficient signatures
 */
int dap_chain_arbitrage_tx_check_auth(dap_ledger_t *a_ledger,
                                      dap_chain_datum_tx_t *a_tx,
                                      dap_ledger_token_item_t *a_token_item);

