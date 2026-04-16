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

#include "dap_common.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_wallet.h"
#include "dap_enc_key.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_cert.h"
#include <json.h>

/**
 * @brief Create arbitrage transaction with multiple signatures
 * @param a_chain Target chain
 * @param a_key_from Sender's private key (from wallet)
 * @param a_addr_from Sender's address
 * @param a_addr_to Recipient addresses (array)
 * @param a_token_ticker Token ticker
 * @param a_value Transfer values (array)
 * @param a_value_fee Fee value
 * @param a_hash_out_type Output hash type
 * @param a_tx_num Number of outputs
 * @param a_time_unlock Lock times (array, optional)
 * @param a_tsd_list List of TSD sections (must include arbitrage TSD)
 * @param a_arbitrage_certs Array of certificates for additional signatures
 * @param a_arbitrage_certs_count Number of certificates
 * @return Transaction hash string or NULL on error
 */
char *dap_chain_arbitrage_tx_create_with_signatures(
    dap_chain_t *a_chain,
    dap_enc_key_t *a_key_from,
    const dap_chain_addr_t *a_addr_from,
    const dap_chain_addr_t **a_addr_to,
    const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
    uint256_t *a_value,
    uint256_t a_value_fee,
    const char *a_hash_out_type,
    size_t a_tx_num,
    dap_time_t *a_time_unlock,
    dap_list_t *a_tsd_list,
    dap_cert_t **a_arbitrage_certs,
    size_t a_arbitrage_certs_count);

/**
 * @brief Create arbitrage transaction via CLI
 * @details Handles the logic for creating arbitrage transactions from CLI command.
 *          This function processes the -arbitrage flag and all related parameters.
 * @param a_chain Target chain
 * @param a_net Network instance
 * @param a_wallet Wallet instance (will be closed by caller)
 * @param a_priv_key Private key from wallet
 * @param a_addr_from Sender's address
 * @param a_addr_to Recipient addresses (array)
 * @param a_token_ticker Token ticker
 * @param a_value Transfer values (array)
 * @param a_value_fee Fee value
 * @param a_hash_out_type Output hash type
 * @param a_addr_el_count Number of outputs
 * @param a_time_unlock Lock times (array, optional)
 * @param a_certs_str Comma-separated list of certificate names for arbitrage authorization
 * @param a_json_arr_reply JSON array for error responses
 * @param a_jobj_result JSON object for result
 * @return Transaction hash string or NULL on error
 */
char *dap_chain_arbitrage_cli_create_tx(
    dap_chain_t *a_chain,
    dap_chain_net_t *a_net,
    dap_chain_wallet_t *a_wallet,
    dap_enc_key_t *a_priv_key,
    const dap_chain_addr_t *a_addr_from,
    dap_chain_addr_t **a_addr_to,
    const char *a_token_ticker,
    uint256_t *a_value,
    uint256_t a_value_fee,
    const char *a_hash_out_type,
    size_t a_addr_el_count,
    dap_time_t *a_time_unlock,
    const char *a_certs_str,
    json_object **a_json_arr_reply,
    json_object *a_jobj_result);

