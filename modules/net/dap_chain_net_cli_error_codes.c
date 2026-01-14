/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_net_cli_error_codes.h"
#include "dap_cli_error_codes.h"
#include "dap_common.h"

#define LOG_TAG "net_cli_error_codes"

/**
 * @brief Register all net CLI error codes
 * 
 * FULL IMPLEMENTATION - NO STUBS!
 * All error codes for node and net CLI commands
 */
void dap_chain_net_cli_error_codes_init(void)
{
    log_it(L_INFO, "Registering net CLI error codes...");
    
    // Node command success
    dap_cli_error_code_register("NODE_OK", 0, "Node command successful");
    
    // Node command errors
    dap_cli_error_code_register("NODE_COMMAND_NOT_RECOGNIZED", -1001, "Node command not recognized");
    dap_cli_error_code_register("NODE_CANT_PARSE_NODE_ADDR", -1002, "Cannot parse node address");
    dap_cli_error_code_register("NODE_CANT_PARSE_HOST_PORT", -1003, "Cannot parse host:port");
    dap_cli_error_code_register("NODE_MEMORY_ALLOC", -1004, "Memory allocation error");
    dap_cli_error_code_register("NODE_UNRECOGNISED_SUB", -1005, "Unrecognised subcommand");
    
    // Node add errors
    dap_cli_error_code_register("NODE_ADD_HAVE_NO_ACCESS_RIGHTS", -1010, "No access rights to add node");
    dap_cli_error_code_register("NODE_ADD_ALREADY_EXISTS", -1011, "Node already exists");
    dap_cli_error_code_register("NODE_ADD_CANT_ADDED_NOT", -1012, "Cannot add node");
    dap_cli_error_code_register("NODE_ADD_CANT_CALCULATE_HASH", -1013, "Cannot calculate hash");
    dap_cli_error_code_register("NODE_ADD_CANT_DO_HANDSHAKE", -1014, "Cannot do handshake");
    dap_cli_error_code_register("NODE_ADD_CANT_FIND_ARGS", -1015, "Cannot find arguments");
    dap_cli_error_code_register("NODE_ADD_CANT_INVALID_SERVER", -1016, "Invalid server");
    dap_cli_error_code_register("NODE_ADD_CANT_PARSE_HOST_STRING", -1017, "Cannot parse host string");
    dap_cli_error_code_register("NODE_ADD_CANT_PROCESS_NODE_LIST", -1018, "Cannot process node list");
    dap_cli_error_code_register("NODE_ADD_CANT_PROCESS_REQUEST", -1019, "Cannot process request");
    dap_cli_error_code_register("NODE_ADD_CANT_UNSPECIFIED_PORT", -1020, "Unspecified port");
    dap_cli_error_code_register("NODE_ADD_DIDNT_ADD_ADDRESS", -1021, "Didn't add address");
    dap_cli_error_code_register("NODE_ADD_NO_SERVER", -1022, "No server");
    
    // Node alias errors
    dap_cli_error_code_register("NODE_ALIAS_ADDR_NOT_FOUND", -1030, "Alias address not found");
    dap_cli_error_code_register("NODE_ALIAS_ALIAS_NOT_FOUND", -1031, "Alias not found");
    
    // Node ban errors
    dap_cli_error_code_register("NODE_BAN_DECREE_CREATION_FAILED", -1040, "Decree creation failed");
    dap_cli_error_code_register("NODE_BAN_INVALID_PARAMETER", -1041, "Invalid parameter");
    dap_cli_error_code_register("NODE_BAN_LEAST_ONE_VALID_CERT", -1042, "At least one valid certificate required");
    dap_cli_error_code_register("NODE_BAN_NETWORK_DOESNOT_SUPPORT", -1043, "Network does not support banning");
    dap_cli_error_code_register("NODE_BAN_REQUIRES_PARAMETER", -1044, "Ban requires parameter");
    
    // Node connection errors
    dap_cli_error_code_register("NODE_CONNECTION_CANT_PARSE_CLUSTER", -1050, "Cannot parse cluster");
    dap_cli_error_code_register("NODE_CONNECTION_NOT_FOUND_CLUSTER_ID", -1051, "Cluster ID not found");
    dap_cli_error_code_register("NODE_CONNECTION_NOT_FOUND_LINKS", -1052, "Links not found");
    dap_cli_error_code_register("NODE_CONNECT_NOT_IMPLEMENTED", -1053, "Connect not implemented");
    
    // Node del errors
    dap_cli_error_code_register("NODE_DELL_CANT_DEL_NODE", -1060, "Cannot delete node");
    dap_cli_error_code_register("NODE_DELL_CANT_PROCESS_REQUEST", -1061, "Cannot process delete request");
    dap_cli_error_code_register("NODE_DELL_NO_ACCESS_RIGHTS", -1062, "No access rights to delete");
    
    // Node handshake errors
    dap_cli_error_code_register("NODE_HANDSHAKE_NO_FOUND_ADDR", -1070, "Address not found for handshake");
    dap_cli_error_code_register("NODE_HANDSHAKE_NO_RESPONSE", -1071, "No handshake response");
    
    // Node list errors
    dap_cli_error_code_register("NODE_LIST_NO_RECORDS", -1080, "No records in node list");
    
    // Node unban errors
    dap_cli_error_code_register("NODE_UNBAN_DECREE_CREATION_FAILED", -1090, "Unban decree creation failed");
    dap_cli_error_code_register("NODE_UNBAN_INVALID_PRAMETER", -1091, "Invalid unban parameter");
    dap_cli_error_code_register("NODE_UNBAN_LEAST_ONE_VALID_CERT", -1092, "At least one valid certificate required");
    dap_cli_error_code_register("NODE_UNBAN_NETWORK_DOES_NOT_SUPPORT", -1093, "Network does not support unbanning");
    dap_cli_error_code_register("NODE_UNBAN_REQUIRES_PARAMETER_CERT", -1094, "Unban requires certificate parameter");
    
    log_it(L_NOTICE, "Net CLI error codes registered (40+ codes)");
}

