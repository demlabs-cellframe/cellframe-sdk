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
    
    // Print log errors
    dap_cli_error_code_register("PRINT_LOG_TS_AFTER", -1100, "Invalid ts_after parameter");
    dap_cli_error_code_register("PRINT_LOG_LIMIT", -1101, "Invalid limit parameter");
    dap_cli_error_code_register("PRINT_LOG_NO_FILE", -1102, "Log file not configured");
    dap_cli_error_code_register("PRINT_LOG_NO_LOGS", -1103, "No logs found");
    
    // Remove command errors
    dap_cli_error_code_register("REMOVE_PATH", -1110, "Path not configured");
    dap_cli_error_code_register("REMOVE_CMD", -1111, "Invalid command");
    dap_cli_error_code_register("REMOVE_NET", -1112, "Network not found");
    dap_cli_error_code_register("REMOVE_NOTHING", -1113, "Nothing to remove");
    
    // Decree command errors
    dap_cli_error_code_register("DECREE_INVALID_HASH_TYPE", -1200, "Invalid hash type, use hex or base58");
    dap_cli_error_code_register("DECREE_NET_REQUIRED", -1201, "Parameter -net is required");
    dap_cli_error_code_register("DECREE_NET_NOT_FOUND", -1202, "Network not found");
    dap_cli_error_code_register("DECREE_CERTS_REQUIRED", -1203, "Parameter -certs is required");
    dap_cli_error_code_register("DECREE_CERTS_INVALID", -1204, "Invalid certificates");
    dap_cli_error_code_register("DECREE_CHAIN_NOT_FOUND", -1205, "Chain not found");
    dap_cli_error_code_register("DECREE_CHAIN_NO_SUPPORT", -1206, "Chain doesn't support decree");
    dap_cli_error_code_register("DECREE_NO_DECREE_CHAIN", -1207, "No chain with decree support found");
    dap_cli_error_code_register("DECREE_DECREE_CHAIN_NOT_FOUND", -1208, "Decree chain not found");
    dap_cli_error_code_register("DECREE_DECREE_CHAIN_REQUIRED", -1209, "Parameter -decree_chain is required");
    dap_cli_error_code_register("DECREE_FEE_ADDR_REQUIRED", -1210, "Parameter -to_addr is required for fee");
    dap_cli_error_code_register("DECREE_MIN_OWNERS_ZERO", -1211, "Minimum number of owners can't be zero");
    dap_cli_error_code_register("DECREE_SUBTYPE_REQUIRED", -1212, "Decree subtype is required");
    dap_cli_error_code_register("DECREE_SUBTYPE_NOT_SUPPORTED", -1213, "Decree subtype not supported by chain");
    dap_cli_error_code_register("DECREE_SERVICE_NOT_IMPL", -1214, "Service decree not implemented");
    dap_cli_error_code_register("DECREE_TYPE_REQUIRED", -1215, "Decree type is required (common or service)");
    dap_cli_error_code_register("DECREE_SIGN_FAILED", -1216, "Decree signing failed");
    dap_cli_error_code_register("DECREE_DATUM_REQUIRED", -1217, "Parameter -datum is required");
    dap_cli_error_code_register("DECREE_WRONG_DATUM_TYPE", -1218, "Wrong datum type");
    dap_cli_error_code_register("DECREE_DATUM_NOT_FOUND", -1219, "Datum not found in mempool");
    dap_cli_error_code_register("DECREE_CHAIN_NO_ANCHOR", -1220, "Chain doesn't support anchors");
    dap_cli_error_code_register("DECREE_NO_ANCHOR_CHAIN", -1221, "No chain with anchor support found");
    dap_cli_error_code_register("DECREE_ACTION_REQUIRED", -1222, "Decree action required (create/sign/anchor)");
    
    // Exec_cmd command errors
    dap_cli_error_code_register("EXEC_CMD_NOT_INITED", -1300, "JSON-RPC module not initialized");
    dap_cli_error_code_register("EXEC_CMD_MISSING_ARGS", -1301, "Missing required arguments");
    dap_cli_error_code_register("EXEC_CMD_NET_NOT_FOUND", -1302, "Network not found");
    dap_cli_error_code_register("EXEC_CMD_INVALID_ADDR", -1303, "Invalid node address format");
    dap_cli_error_code_register("EXEC_CMD_NODE_NOT_FOUND", -1304, "Node not found");
    
    // Stats command errors
    dap_cli_error_code_register("STATS_WRONG_FORMAT", -1400, "Wrong stats command format");
    dap_cli_error_code_register("STATS_NOT_SUPPORTED", -1401, "Stats not supported on this platform");
    
    // Tx_cond_create command errors (stub)
    dap_cli_error_code_register("TX_COND_NOT_IMPLEMENTED", -1500, "Command not implemented");
    
    // Gdb_export command errors
    dap_cli_error_code_register("GDB_EXPORT_FILENAME_REQUIRED", -1600, "Filename parameter required");
    dap_cli_error_code_register("GDB_EXPORT_PATH_NOT_FOUND", -1601, "GDB path not found in config");
    dap_cli_error_code_register("GDB_EXPORT_DIR_NOT_FOUND", -1602, "GDB directory not found");
    dap_cli_error_code_register("GDB_EXPORT_MEMORY", -1603, "Memory allocation error");
    dap_cli_error_code_register("GDB_EXPORT_FILE_WRITE", -1604, "Failed to write file");
    
    // Gdb_import command errors
    dap_cli_error_code_register("GDB_IMPORT_FILENAME_REQUIRED", -1700, "Filename parameter required");
    dap_cli_error_code_register("GDB_IMPORT_PATH_NOT_FOUND", -1701, "GDB path not found in config");
    dap_cli_error_code_register("GDB_IMPORT_FILE_NOT_FOUND", -1702, "Import file not found");
    dap_cli_error_code_register("GDB_IMPORT_MEMORY", -1703, "Memory allocation error");
    dap_cli_error_code_register("GDB_IMPORT_PARSE", -1704, "Failed to parse JSON");
    
    // Tx_cond_remove command errors
    dap_cli_error_code_register("TX_COND_REMOVE_INVALID_H", -1800, "Invalid -H parameter");
    dap_cli_error_code_register("TX_COND_REMOVE_W_REQUIRED", -1801, "Wallet parameter required");
    dap_cli_error_code_register("TX_COND_REMOVE_FEE_REQUIRED", -1802, "Fee parameter required");
    dap_cli_error_code_register("TX_COND_REMOVE_NET_REQUIRED", -1803, "Network parameter required");
    dap_cli_error_code_register("TX_COND_REMOVE_HASHES_REQUIRED", -1804, "Hashes parameter required");
    dap_cli_error_code_register("TX_COND_REMOVE_SRV_UID_REQUIRED", -1805, "Service UID parameter required");
    dap_cli_error_code_register("TX_COND_REMOVE_SRV_UID_INVALID", -1806, "Invalid service UID");
    dap_cli_error_code_register("TX_COND_REMOVE_NET_NOT_FOUND", -1807, "Network not found");
    dap_cli_error_code_register("TX_COND_REMOVE_WALLET_NOT_FOUND", -1808, "Wallet not found");
    dap_cli_error_code_register("TX_COND_REMOVE_FEE_INVALID", -1809, "Invalid fee value");
    dap_cli_error_code_register("TX_COND_REMOVE_NO_NATIVE_TICKER", -1810, "No native ticker");
    dap_cli_error_code_register("TX_COND_REMOVE_NO_LEDGER", -1811, "Ledger not found");
    dap_cli_error_code_register("TX_COND_REMOVE_TX_CREATE_FAILED", -1812, "TX creation failed");
    dap_cli_error_code_register("TX_COND_REMOVE_NO_HASHES", -1813, "No valid hashes found");
    dap_cli_error_code_register("TX_COND_REMOVE_NO_UNSPENT", -1814, "No unspent conditional TX");
    dap_cli_error_code_register("TX_COND_REMOVE_FEE_TOO_BIG", -1815, "Fee exceeds output value");
    dap_cli_error_code_register("TX_COND_REMOVE_ADD_OUT_FAILED", -1816, "Failed to add output");
    dap_cli_error_code_register("TX_COND_REMOVE_ADD_NET_FEE_FAILED", -1817, "Failed to add network fee");
    dap_cli_error_code_register("TX_COND_REMOVE_ADD_FEE_FAILED", -1818, "Failed to add validator fee");
    dap_cli_error_code_register("TX_COND_REMOVE_ADD_SIGN_FAILED", -1819, "Failed to add signature");
    dap_cli_error_code_register("TX_COND_REMOVE_NO_CHAIN", -1820, "Default chain not found");
    dap_cli_error_code_register("TX_COND_REMOVE_FAILED", -1821, "TX cond remove failed");
    
    // Tx_cond_unspent_find command errors
    dap_cli_error_code_register("TX_COND_FIND_INVALID_H", -1900, "Invalid -H parameter");
    dap_cli_error_code_register("TX_COND_FIND_W_REQUIRED", -1901, "Wallet parameter required");
    dap_cli_error_code_register("TX_COND_FIND_NET_REQUIRED", -1902, "Network parameter required");
    dap_cli_error_code_register("TX_COND_FIND_SRV_UID_REQUIRED", -1903, "Service UID parameter required");
    dap_cli_error_code_register("TX_COND_FIND_SRV_UID_INVALID", -1904, "Invalid service UID");
    dap_cli_error_code_register("TX_COND_FIND_NET_NOT_FOUND", -1905, "Network not found");
    dap_cli_error_code_register("TX_COND_FIND_WALLET_NOT_FOUND", -1906, "Wallet not found");
    dap_cli_error_code_register("TX_COND_FIND_NO_NATIVE_TICKER", -1907, "No native ticker");
    dap_cli_error_code_register("TX_COND_FIND_NO_LEDGER", -1908, "Ledger not found");
    
    // Find command errors
    dap_cli_error_code_register("FIND_UNKNOWN_SUBCMD", -2000, "Unknown subcommand");
    dap_cli_error_code_register("FIND_SUBCMD_REQUIRED", -2001, "Subcommand required");
    dap_cli_error_code_register("FIND_NET_PARSE", -2002, "Network/chain parsing error");
    dap_cli_error_code_register("FIND_HASH_REQUIRED", -2003, "Hash parameter required");
    dap_cli_error_code_register("FIND_HASH_INVALID", -2004, "Invalid hash string");
    dap_cli_error_code_register("FIND_TYPE_REQUIRED", -2005, "Decree type required");
    dap_cli_error_code_register("FIND_TYPE_INVALID", -2006, "Invalid decree type");
    dap_cli_error_code_register("FIND_WHERE_INVALID", -2007, "Invalid where parameter");
    
    // Policy command errors
    dap_cli_error_code_register("POLICY_UNKNOWN_SUBCMD", -2100, "Unknown subcommand");
    dap_cli_error_code_register("POLICY_NET_REQUIRED", -2101, "Network parameter required");
    dap_cli_error_code_register("POLICY_NET_NOT_FOUND", -2102, "Network not found");
    dap_cli_error_code_register("POLICY_NUM_REQUIRED", -2103, "Policy num required");
    dap_cli_error_code_register("POLICY_NUM_ZERO", -2104, "Policy num cannot be 0");
    dap_cli_error_code_register("POLICY_CREATE_DEACTIVATE", -2105, "Deactivate policy creation failed");
    dap_cli_error_code_register("POLICY_CERTS_REQUIRED", -2106, "Certificates required for execute");
    dap_cli_error_code_register("POLICY_CERTS_NOT_FOUND", -2107, "Certificates not found");
    dap_cli_error_code_register("POLICY_ALREADY_EXIST", -2108, "Policy already exists");
    dap_cli_error_code_register("POLICY_TS_START_INVALID", -2109, "Invalid ts_start format");
    dap_cli_error_code_register("POLICY_CHAIN_REQUIRED", -2110, "Chain required with block_start");
    dap_cli_error_code_register("POLICY_CHAIN_NOT_FOUND", -2111, "Chain not found");
    dap_cli_error_code_register("POLICY_CREATE_ACTIVATE", -2112, "Activate policy creation failed");
    dap_cli_error_code_register("POLICY_COLLECT_FAILED", -2113, "Policy info collection failed");
    dap_cli_error_code_register("POLICY_SIGN_FAILED", -2114, "Policy decree signing failed");
    dap_cli_error_code_register("POLICY_PUT_FAILED", -2115, "Policy decree put failed");
    
    log_it(L_NOTICE, "Net CLI error codes registered (143+ codes)");
}

