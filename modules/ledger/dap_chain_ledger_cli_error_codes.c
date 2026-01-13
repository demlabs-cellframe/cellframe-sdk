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
    dap_cli_error_code_register("LEDGER_WALLET_CANNOT_OPEN", -143, "Cannot open wallet");
    
    // Memory and internal errors
    dap_cli_error_code_register("LEDGER_MEMORY_ERR", -150, "Memory allocation error");
    dap_cli_error_code_register("LEDGER_INTERNAL_ERR", -151, "Internal error");
    
    // Ledger-specific errors
    dap_cli_error_code_register("LEDGER_HASH_INVALID", -160, "Invalid hash");
    dap_cli_error_code_register("LEDGER_HASH_GET_ERR", -161, "Failed to get hash");
    dap_cli_error_code_register("LEDGER_MEMPOOL_FAILED", -162, "Mempool operation failed");
    dap_cli_error_code_register("LEDGER_NO_ANCHOR_CHAIN", -163, "No anchor chain found");
    dap_cli_error_code_register("LEDGER_SIGNING_FAILED", -164, "Signing failed");
    dap_cli_error_code_register("LEDGER_THRESHOLD_ERR", -165, "Threshold error");
    dap_cli_error_code_register("LEDGER_TX_TO_JSON_ERR", -166, "TX to JSON conversion error");
    
    // TX Conditional Create errors
    dap_cli_error_code_register("LEDGER_TX_COND_CERT_FOUND", -300, "Certificate found");
    dap_cli_error_code_register("LEDGER_TX_COND_CREATE_FAILED", -301, "Cannot create conditional TX");
    dap_cli_error_code_register("LEDGER_TX_COND_SERVICE_UID_NOT_FOUND", -302, "Service UID not found");
    dap_cli_error_code_register("LEDGER_TX_COND_UNIT_INVALID", -303, "Invalid unit");
    dap_cli_error_code_register("LEDGER_TX_COND_VALUE_INVALID", -304, "Invalid value");
    dap_cli_error_code_register("LEDGER_TX_COND_FEE_INVALID", -305, "Invalid fee value");
    dap_cli_error_code_register("LEDGER_TX_COND_CERT_REQUIRED", -306, "Certificate parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_FEE_REQUIRED", -307, "Fee parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_SRV_UID_REQUIRED", -308, "Service UID parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_TOKEN_REQUIRED", -309, "Token parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_UNIT_REQUIRED", -310, "Unit parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_VALUE_REQUIRED", -311, "Value parameter required");
    
    // TX Conditional Remove errors
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_CHAIN_NOT_FOUND", -320, "Default chain not found");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_ADD_FEE_FAILED", -321, "Cannot add fee output");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_ADD_OUTPUT_FAILED", -322, "Cannot add output");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_ADD_SIGN_FAILED", -323, "Cannot add signature");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_CREATE_FAILED", -324, "Cannot create transaction");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_NATIVE_TICKER_NOT_FOUND", -325, "Native ticker not found");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_SERVICE_UID_NOT_FOUND", -326, "Service UID not found");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_FEE_INVALID", -327, "Invalid fee value");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_OTHER_ERROR", -328, "Other error during remove");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_HASH_NOT_FOUND", -329, "Conditional TX hash not found");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_FEE_REQUIRED", -330, "Fee parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_HASHES_REQUIRED", -331, "Hashes parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_SRV_UID_REQUIRED", -332, "Service UID parameter required");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_VALUE_TOO_SMALL", -333, "Sum of outputs must be greater than fees");
    dap_cli_error_code_register("LEDGER_TX_COND_REMOVE_UNSPENT_IN_LIST", -334, "Unspent conditional TX in hash list");
    
    // TX Conditional Unspent Find errors
    dap_cli_error_code_register("LEDGER_TX_COND_UNSPENT_NATIVE_TICKER_NOT_FOUND", -350, "Native ticker not found");
    dap_cli_error_code_register("LEDGER_TX_COND_UNSPENT_SERVICE_UID_NOT_FOUND", -351, "Service UID not found");
    
    // TX History errors
    dap_cli_error_code_register("LEDGER_TX_HISTORY_ADDR_WALLET_DIFFER", -450, "Address wallet differ");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_DB_ADDR_ERR", -451, "DB history address error");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_DB_ALL_ERR", -452, "DB history all error");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_DB_TX_ERR", -453, "DB history TX error");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_HASH_ERR", -454, "Hash recognition error");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_ID_NET_DIFFER", -455, "ID net address differ");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_PARAMS_INCOMPATIBLE", -456, "Incompatible parameters");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_MEMORY_ERR", -457, "Memory error");
    dap_cli_error_code_register("LEDGER_TX_HISTORY_WALLET_ADDR_ERR", -458, "Wallet address error");
    
    // TX Verify errors  
    dap_cli_error_code_register("LEDGER_TX_VERIFY_NOT_TX_HASH", -470, "Hash is not TX hash");
    dap_cli_error_code_register("LEDGER_TX_VERIFY_HASH_INVALID", -471, "Invalid TX hash");
    dap_cli_error_code_register("LEDGER_TX_VERIFY_NET_CHAIN_UNDEFINED", -472, "Network or chain undefined");
    dap_cli_error_code_register("LEDGER_TX_VERIFY_TX_REQUIRED", -473, "TX parameter required");
    dap_cli_error_code_register("LEDGER_TX_VERIFY_TX_NOT_FOUND", -474, "Specified TX not found");
    dap_cli_error_code_register("LEDGER_TX_VERIFY_FAILED", -475, "TX not verified");
    
    log_it(L_INFO, "Ledger CLI error codes registered");
}


