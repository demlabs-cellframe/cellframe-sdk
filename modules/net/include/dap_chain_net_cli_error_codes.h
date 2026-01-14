/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#pragma once

#include "dap_cli_error_codes.h"  // For dap_cli_error_code_get

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Net CLI Error Codes System
 * 
 * FULL IMPLEMENTATION for node and net CLI commands
 * Uses dynamic error code registration system
 */

/**
 * @brief Initialize and register all net CLI error codes
 */
void dap_chain_net_cli_error_codes_init(void);

/**
 * @brief Compatibility macros for old code
 * 
 * Maps old DAP_CHAIN_NODE_CLI_COM_* constants to new dynamic system
 */

// Node command success
#define DAP_CHAIN_NODE_CLI_COM_NODE_OK dap_cli_error_code_get("NODE_OK")

// Node command errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_COMMAND_NOT_RECOGNIZED_ERR dap_cli_error_code_get("NODE_COMMAND_NOT_RECOGNIZED")
#define DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_NODE_ADDR_ERR dap_cli_error_code_get("NODE_CANT_PARSE_NODE_ADDR")
#define DAP_CHAIN_NODE_CLI_COM_NODE_CANT_PARSE_HOST_PORT_ERR dap_cli_error_code_get("NODE_CANT_PARSE_HOST_PORT")
#define DAP_CHAIN_NODE_CLI_COM_NODE_MEMORY_ALLOC_ERR dap_cli_error_code_get("NODE_MEMORY_ALLOC")
#define DAP_CHAIN_NODE_CLI_COM_NODE_UNRECOGNISED_SUB_ERR dap_cli_error_code_get("NODE_UNRECOGNISED_SUB")

// Node add errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_HAVE_NO_ACCESS_RIGHTS_ERR dap_cli_error_code_get("NODE_ADD_HAVE_NO_ACCESS_RIGHTS")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_ALREADY_EXISTS_ERR dap_cli_error_code_get("NODE_ADD_ALREADY_EXISTS")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_ADDED_NOT_ERR dap_cli_error_code_get("NODE_ADD_CANT_ADDED_NOT")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_CALCULATE_HASH_ERR dap_cli_error_code_get("NODE_ADD_CANT_CALCULATE_HASH")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_DO_HANDSHAKE_ERR dap_cli_error_code_get("NODE_ADD_CANT_DO_HANDSHAKE")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_FIND_ARGS_ERR dap_cli_error_code_get("NODE_ADD_CANT_FIND_ARGS")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_INVALID_SERVER_ERR dap_cli_error_code_get("NODE_ADD_CANT_INVALID_SERVER")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PARSE_HOST_STRING_ERR dap_cli_error_code_get("NODE_ADD_CANT_PARSE_HOST_STRING")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PROCESS_NODE_LIST_ERR dap_cli_error_code_get("NODE_ADD_CANT_PROCESS_NODE_LIST")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_PROCESS_REQUEST_ERR dap_cli_error_code_get("NODE_ADD_CANT_PROCESS_REQUEST")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_CANT_UNSPECIFIED_PORT_ERR dap_cli_error_code_get("NODE_ADD_CANT_UNSPECIFIED_PORT")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_DIDNT_ADD_ADDRESS_ERR dap_cli_error_code_get("NODE_ADD_DIDNT_ADD_ADDRESS")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ADD_NO_SERVER_ERR dap_cli_error_code_get("NODE_ADD_NO_SERVER")

// Node alias errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ADDR_NOT_FOUND_ERR dap_cli_error_code_get("NODE_ALIAS_ADDR_NOT_FOUND")
#define DAP_CHAIN_NODE_CLI_COM_NODE_ALIAS_ALIAS_NOT_FOUND_ERR dap_cli_error_code_get("NODE_ALIAS_ALIAS_NOT_FOUND")

// Node ban errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_BAN_DECREE_CREATION_FAILED_ERR dap_cli_error_code_get("NODE_BAN_DECREE_CREATION_FAILED")
#define DAP_CHAIN_NODE_CLI_COM_NODE_BAN_INVALID_PARAMETER_ERR dap_cli_error_code_get("NODE_BAN_INVALID_PARAMETER")
#define DAP_CHAIN_NODE_CLI_COM_NODE_BAN_LEAST_ONE_VALID_CERT_ERR dap_cli_error_code_get("NODE_BAN_LEAST_ONE_VALID_CERT")
#define DAP_CHAIN_NODE_CLI_COM_NODE_BAN_NETWORK_DOESNOT_SUPPORT_ERR dap_cli_error_code_get("NODE_BAN_NETWORK_DOESNOT_SUPPORT")
#define DAP_CHAIN_NODE_CLI_COM_NODE_BAN_REQUIRES_PARAMETER_ERR dap_cli_error_code_get("NODE_BAN_REQUIRES_PARAMETER")

// Node connection errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_CANT_PARSE_CLUSTER_ERR dap_cli_error_code_get("NODE_CONNECTION_CANT_PARSE_CLUSTER")
#define DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_NOT_FOUND_CLUSTER_ID_ERR dap_cli_error_code_get("NODE_CONNECTION_NOT_FOUND_CLUSTER_ID")
#define DAP_CHAIN_NODE_CLI_COM_NODE_CONNECTION_NOT_FOUND_LINKS_ERR dap_cli_error_code_get("NODE_CONNECTION_NOT_FOUND_LINKS")
#define DAP_CHAIN_NODE_CLI_COM_NODE_CONNECT_NOT_IMPLEMENTED_ERR dap_cli_error_code_get("NODE_CONNECT_NOT_IMPLEMENTED")

// Node del errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_DELL_CANT_DEL_NODE_ERR dap_cli_error_code_get("NODE_DELL_CANT_DEL_NODE")
#define DAP_CHAIN_NODE_CLI_COM_NODE_DELL_CANT_PROCESS_REQUEST_ERR dap_cli_error_code_get("NODE_DELL_CANT_PROCESS_REQUEST")
#define DAP_CHAIN_NODE_CLI_COM_NODE_DELL_NO_ACCESS_RIGHTS_ERR dap_cli_error_code_get("NODE_DELL_NO_ACCESS_RIGHTS")

// Node handshake errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_FOUND_ADDR_ERR dap_cli_error_code_get("NODE_HANDSHAKE_NO_FOUND_ADDR")
#define DAP_CHAIN_NODE_CLI_COM_NODE_HANDSHAKE_NO_RESPONSE_ERR dap_cli_error_code_get("NODE_HANDSHAKE_NO_RESPONSE")

// Node list errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_LIST_NO_RECORDS_ERR dap_cli_error_code_get("NODE_LIST_NO_RECORDS")

// Node unban errors
#define DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_DECREE_CREATION_FAILED_ERR dap_cli_error_code_get("NODE_UNBAN_DECREE_CREATION_FAILED")
#define DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_INVALID_PRAMETER_ERR dap_cli_error_code_get("NODE_UNBAN_INVALID_PRAMETER")
#define DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_LEAST_ONE_VALID_CERT_ERR dap_cli_error_code_get("NODE_UNBAN_LEAST_ONE_VALID_CERT")
#define DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_NETWORK_DOES_NOT_SUPPORT_ERR dap_cli_error_code_get("NODE_UNBAN_NETWORK_DOES_NOT_SUPPORT")
#define DAP_CHAIN_NODE_CLI_COM_NODE_UNBAN_REQUIRES_PARAMETER_CERT_ERR dap_cli_error_code_get("NODE_UNBAN_REQUIRES_PARAMETER_CERT")

#ifdef __cplusplus
}
#endif

