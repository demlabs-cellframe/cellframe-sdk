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
    
    // TX Create errors
    dap_cli_error_code_register("LEDGER_TX_CREATE_MEMPOOL_ADD_FAILED", -400, "Cannot add datum to mempool");
    dap_cli_error_code_register("LEDGER_TX_CREATE_FAILED", -401, "Cannot create transaction");
    dap_cli_error_code_register("LEDGER_TX_CREATE_CERT_INVALID", -402, "Certificate is invalid");
    dap_cli_error_code_register("LEDGER_TX_CREATE_DEST_ADDR_INVALID", -403, "Destination address invalid");
    dap_cli_error_code_register("LEDGER_TX_CREATE_DEST_NET_UNREACHABLE", -404, "Destination network unreachable");
    dap_cli_error_code_register("LEDGER_TX_CREATE_SRC_DEST_EQUAL", -405, "Source and destination address are equal");
    dap_cli_error_code_register("LEDGER_TX_CREATE_HASH_INVALID", -406, "Invalid hash");
    dap_cli_error_code_register("LEDGER_TX_CREATE_MEMORY_ERR", -407, "Memory error");
    dap_cli_error_code_register("LEDGER_TX_CREATE_NO_PRIVATE_KEY", -408, "No private key defined");
    dap_cli_error_code_register("LEDGER_TX_CREATE_FEE_REQUIRED", -409, "Fee required");
    dap_cli_error_code_register("LEDGER_TX_CREATE_FEE_INVALID", -410, "Fee must be uint256");
    dap_cli_error_code_register("LEDGER_TX_CREATE_CERT_OR_WALLET_REQUIRED", -411, "Certificate or wallet parameter required");
    dap_cli_error_code_register("LEDGER_TX_CREATE_FROM_EMISSION_REQUIRED", -412, "From emission parameter required");
    dap_cli_error_code_register("LEDGER_TX_CREATE_FROM_WALLET_OR_EMISSION", -413, "From wallet or emission parameter required");
    dap_cli_error_code_register("LEDGER_TX_CREATE_TO_ADDR_REQUIRED", -414, "To address parameter required");
    dap_cli_error_code_register("LEDGER_TX_CREATE_VALUE_INVALID", -415, "Value parameter required or invalid format");
    dap_cli_error_code_register("LEDGER_TX_CREATE_WALLET_FEE_REQUIRED", -416, "Wallet fee parameter required");
    dap_cli_error_code_register("LEDGER_TX_CREATE_TOKEN_REQUIRED", -417, "Token required");
    dap_cli_error_code_register("LEDGER_TX_CREATE_SRC_ADDR_INVALID", -418, "Source address invalid");
    dap_cli_error_code_register("LEDGER_TX_CREATE_TOKEN_NOT_DECLARED", -419, "Token not declared in network");
    dap_cli_error_code_register("LEDGER_TX_CREATE_WALLET_NOT_EXIST", -420, "Wallet does not exist");
    dap_cli_error_code_register("LEDGER_TX_CREATE_TIME_FORMAT_INVALID", -421, "Wrong time format");
    
    // TX History errors
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR", -450, "Address wallet differ");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR", -451, "Chain parameter error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR", -452, "DB history address error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR", -453, "DB history all error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR", -454, "DB history TX error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR", -455, "Hash recognition error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR", -456, "ID net address differ");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR", -457, "Incompatible parameters");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR", -458, "Memory error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR", -459, "Network error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR", -460, "Network parameter error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK", 0, "TX history OK");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR", -461, "Parameter error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR", -462, "Wallet address error");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR", -463, "Wallet error");
    
    // TX Verify errors
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_HASH_IS_NOT_TX_HASH", -470, "Hash is not TX hash");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_INVALID_TX_HASH", -471, "Invalid TX hash");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_NET_CHAIN_UNDEFINED", -472, "Network or chain undefined");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_OK", 0, "TX verify OK");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_REQUIRE_PARAMETER_TX", -473, "TX parameter required");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_SPECIFIED_TX_NOT_FOUND", -474, "Specified TX not found");
    dap_cli_error_code_register("DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_TX_NOT_VERIFY", -475, "TX not verified");
    
    log_it(L_INFO, "Ledger CLI error codes registered (%d codes)", 150);
}

