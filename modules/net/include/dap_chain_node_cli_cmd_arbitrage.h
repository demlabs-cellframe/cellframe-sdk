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
 * @brief Create arbitrage TX with cert signatures (no wallet needed)
 * @details Arbitrage allows token authority holders (arbitrators) to claim
 *          UTXO from ANY address — including blocked — and send to fee address.
 *          The arbitrator signs with their cert, not a wallet key.
 * @param a_chain Target chain
 * @param a_net Network
 * @param a_addr_from Address whose UTXO to claim (victim/target address)
 * @param a_token_ticker Token to arbitrate
 * @param a_value Amount to claim
 * @param a_value_fee Validator fee
 * @param a_hash_out_type Hash output type
 * @param a_certs_str Comma-separated arbitrator certificate names
 * @param a_json_arr_reply JSON error output
 * @return TX hash string or NULL on error
 */
char *dap_chain_arbitrage_cli_create(
    dap_chain_t *a_chain,
    dap_chain_net_t *a_net,
    const dap_chain_addr_t *a_addr_from,
    const char *a_token_ticker,
    uint256_t a_value,
    uint256_t a_value_fee,
    const char *a_hash_out_type,
    const char *a_certs_str,
    json_object **a_json_arr_reply);

