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

#include "dap_cli_error_codes.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_common.h"

#define LOG_TAG "ledger_cli_errors"

/**
 * @brief Register all ledger CLI error codes
 * 
 * This function should be called during ledger module initialization
 * to register all error codes used by ledger CLI commands.
 */
void dap_chain_ledger_cli_error_codes_init(void)
{
    // Parameter errors
    dap_cli_error_code_register("LEDGER_PARAM_ERR", -100, "Invalid or missing parameter");
    dap_cli_error_code_register("LEDGER_NET_PARAM_ERR", -101, "Invalid network parameter");
    dap_cli_error_code_register("LEDGER_CHAIN_PARAM_ERR", -102, "Invalid chain parameter");
    dap_cli_error_code_register("LEDGER_TOKEN_PARAM_ERR", -103, "Invalid token parameter");
    dap_cli_error_code_register("LEDGER_ADDR_PARAM_ERR", -104, "Invalid address parameter");
    dap_cli_error_code_register("LEDGER_WALLET_PARAM_ERR", -105, "Invalid wallet parameter");
    
    // Transaction errors
    dap_cli_error_code_register("LEDGER_TX_HASH_ERR", -110, "Invalid transaction hash");
    dap_cli_error_code_register("LEDGER_TX_NOT_FOUND", -111, "Transaction not found");
    dap_cli_error_code_register("LEDGER_TX_INVALID", -112, "Invalid transaction");
    dap_cli_error_code_register("LEDGER_TX_CREATE_ERR", -113, "Failed to create transaction");
    
    // Network/Chain errors
    dap_cli_error_code_register("LEDGER_NET_FIND_ERR", -120, "Network not found");
    dap_cli_error_code_register("LEDGER_CHAIN_FIND_ERR", -121, "Chain not found");
    dap_cli_error_code_register("LEDGER_NO_DECREE_CHAIN", -122, "No decree chain found");
    dap_cli_error_code_register("LEDGER_LACK_ERR", -123, "Ledger not available");
    
    // Token errors
    dap_cli_error_code_register("LEDGER_TOKEN_NOT_FOUND", -130, "Token not found");
    dap_cli_error_code_register("LEDGER_TOKEN_INVALID", -131, "Invalid token");
    dap_cli_error_code_register("LEDGER_INSUFFICIENT_FUNDS", -132, "Insufficient funds");
    
    // Wallet errors
    dap_cli_error_code_register("LEDGER_WALLET_ERR", -140, "Wallet error");
    dap_cli_error_code_register("LEDGER_WALLET_NOT_FOUND", -141, "Wallet not found");
    dap_cli_error_code_register("LEDGER_WALLET_ADDR_ERR", -142, "Invalid wallet address");
    
    log_it(L_INFO, "Ledger CLI error codes registered");
}

