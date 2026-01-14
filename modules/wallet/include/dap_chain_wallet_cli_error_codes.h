/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2024
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_cli_error_codes.h"

// Wallet CLI error code macros - map to dynamic error code system
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR                          dap_cli_error_code_get("WALLET_PARAM_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR                           dap_cli_error_code_get("WALLET_NAME_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR                      dap_cli_error_code_get("WALLET_NET_PARAM_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_ERR                            dap_cli_error_code_get("WALLET_NET_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR                         dap_cli_error_code_get("WALLET_MEMORY_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR                          dap_cli_error_code_get("WALLET_FOUND_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR                        dap_cli_error_code_get("WALLET_ALREADY_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ACTIVE_ERR                         dap_cli_error_code_get("WALLET_ACTIVE_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_DEACT_ERR                          dap_cli_error_code_get("WALLET_DEACT_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR                           dap_cli_error_code_get("WALLET_PASS_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_TO_LONG_ERR                   dap_cli_error_code_get("WALLET_PASS_TO_LONG_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD dap_cli_error_code_get("WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR                           dap_cli_error_code_get("WALLET_ADDR_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CAN_NOT_GET_ADDR                   dap_cli_error_code_get("WALLET_CAN_NOT_GET_ADDR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR                   dap_cli_error_code_get("WALLET_UNKNOWN_SIGN_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_HASH_ERR                           dap_cli_error_code_get("WALLET_HASH_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR                        dap_cli_error_code_get("WALLET_CONVERT_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR                         dap_cli_error_code_get("WALLET_BACKUP_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PROTECTION_ERR                     dap_cli_error_code_get("WALLET_PROTECTION_ERR")
#define DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INTERNAL_ERR                       dap_cli_error_code_get("WALLET_INTERNAL_ERR")

// Initialization and cleanup functions
int dap_chain_wallet_cli_error_codes_init(void);
void dap_chain_wallet_cli_error_codes_deinit(void);

