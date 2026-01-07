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

#include "dap_cli_error_codes.h"
#include "dap_chain_wallet_cli_error_codes.h"

#define LOG_TAG "dap_chain_wallet_cli_error_codes"

/**
 * @brief dap_chain_wallet_cli_error_codes_init
 * Register all wallet CLI error codes with the dynamic error code system
 * @return 0 on success
 */
int dap_chain_wallet_cli_error_codes_init(void)
{
    // Wallet parameter errors
    dap_cli_error_code_register("WALLET_PARAM_ERR", -200, "Missing required wallet parameter");
    dap_cli_error_code_register("WALLET_NAME_ERR", -201, "Invalid or missing wallet name");
    dap_cli_error_code_register("WALLET_NET_PARAM_ERR", -202, "Invalid or missing network parameter");
    dap_cli_error_code_register("WALLET_NET_ERR", -203, "Network not found or invalid");
    dap_cli_error_code_register("WALLET_MEMORY_ERR", -204, "Memory allocation error");
    
    // Wallet operation errors
    dap_cli_error_code_register("WALLET_FOUND_ERR", -210, "Wallet not found");
    dap_cli_error_code_register("WALLET_ALREADY_ERR", -211, "Wallet already exists");
    dap_cli_error_code_register("WALLET_ACTIVE_ERR", -212, "Wallet is already active");
    dap_cli_error_code_register("WALLET_DEACT_ERR", -213, "Failed to deactivate wallet");
    
    // Wallet authentication errors
    dap_cli_error_code_register("WALLET_PASS_ERR", -220, "Invalid or missing password");
    dap_cli_error_code_register("WALLET_PASS_TO_LONG_ERR", -221, "Password is too long");
    dap_cli_error_code_register("WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD", -222, "Invalid characters in password");
    
    // Wallet address errors
    dap_cli_error_code_register("WALLET_ADDR_ERR", -230, "Invalid wallet address");
    dap_cli_error_code_register("WALLET_CAN_NOT_GET_ADDR", -231, "Cannot get wallet address");
    
    // Wallet signature errors
    dap_cli_error_code_register("WALLET_UNKNOWN_SIGN_ERR", -240, "Unknown signature type");
    dap_cli_error_code_register("WALLET_HASH_ERR", -241, "Hash calculation error");
    
    // Wallet conversion/backup errors
    dap_cli_error_code_register("WALLET_CONVERT_ERR", -250, "Wallet conversion failed");
    dap_cli_error_code_register("WALLET_BACKUP_ERR", -251, "Wallet backup failed");
    dap_cli_error_code_register("WALLET_PROTECTION_ERR", -252, "Wallet protection error");
    
    // Wallet internal errors
    dap_cli_error_code_register("WALLET_INTERNAL_ERR", -260, "Internal wallet error");
    
    log_it(L_NOTICE, "Wallet CLI error codes registered");
    return 0;
}

/**
 * @brief dap_chain_wallet_cli_error_codes_deinit
 * Cleanup wallet CLI error codes (currently no-op as codes are managed globally)
 */
void dap_chain_wallet_cli_error_codes_deinit(void)
{
    // No cleanup needed - error codes are managed by global system
}

