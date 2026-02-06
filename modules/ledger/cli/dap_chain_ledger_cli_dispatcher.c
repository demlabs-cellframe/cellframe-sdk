/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_tx.h"
#include "dap_chain_ledger_cli_cmd_registry.h"
#include "dap_cli_server.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_cli_error_codes.h"
#include "dap_json_rpc_errors.h"

#define LOG_TAG "ledger_cli_dispatcher"

/**
 * @brief Main ledger CLI dispatcher
 * 
 * PLUGIN-BASED ROUTING:
 * - No hardcoded commands!
 * - All routing via registry lookup
 * - Modules register their commands independently
 * - Zero coupling to specific modules
 */
int dap_chain_ledger_cli_dispatcher(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    // Command format: tx <subcommand> [args]
    // argv[0] = "tx" (command name)
    // argv[1] = subcommand (e.g., "create", "verify", "history")
    
    if (a_argc < 2) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "tx command requires subcommand (e.g., create, verify, history)");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    // The category is "tx" (same as the command name in argv[0])
    const char *l_category = a_argv[0];  // "tx"
    const char *l_command = a_argv[1];   // subcommand like "create"
    
    // Execute via registry - plugin system!
    int l_result = dap_ledger_cli_cmd_execute(
        l_category, 
        l_command,
        a_argc - 1,      // Pass argc from subcommand level
        a_argv + 1,      // Pass argv from subcommand level
        a_json_arr_reply, 
        a_version
    );
    
    if (l_result == -2) {  // Command not found
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Unknown tx subcommand '%s'. Available: create, create_json, history, verify", l_command);
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    return l_result;
}

/**
 * @brief Initialize new modular ledger CLI
 */
int dap_chain_ledger_cli_module_init(void)
{
    log_it(L_INFO, "Initializing modular ledger CLI system");
    
    // Initialize registry
    dap_ledger_cli_cmd_registry_init();
    
    // Register error codes
    dap_chain_ledger_cli_error_codes_init();
    
    // Initialize command modules - they will self-register
    dap_chain_ledger_cli_tx_init();
    
    // Register the "tx" command with CLI server to route to dispatcher
    dap_cli_server_cmd_add("tx", dap_chain_ledger_cli_dispatcher, NULL, 
        "Transaction commands", 0,
        "tx <subcommand> [options]\n\n"
        "==Subcommands==\n"
        "  create -net <net_name> [-chain <chain_name>] -value <value> -token <token_ticker>\n"
        "         -to_addr <addr> {-from_wallet <wallet_name> | -from_emission <emission_hash>\n"
        "         -chain_emission <chain_name> -cert <cert_name>} [-fee <value>] [-H {hex|base58}]\n"
        "\tCreate transaction from wallet or emission\n\n"
        "  create_json -net <net_name> [-chain <chain_name>] {-json <json_file_path> | -tx_obj <json_string>}\n"
        "\tCreate transaction from JSON file or string\n\n"
        "  history {-addr <addr> | -w <wallet_name>} -net <net_name> [-chain <chain_name>]\n"
        "          [-limit <N>] [-offset <N>] [-head] [-srv <service>] [-act <action>] [-H {hex|base58}]\n"
        "  history -all -net <net_name> [-chain <chain_name>] [-limit <N>] [-offset <N>] [-head] [-brief]\n"
        "  history -tx <tx_hash> -net <net_name> [-chain <chain_name>]\n"
        "  history -count -net <net_name>\n"
        "\tShow transaction history for address, wallet, specific tx, or all transactions\n\n"
        "  verify -net <net_name> [-chain <chain_name>] -tx <tx_hash>\n"
        "\tVerify transaction in mempool before processing\n");
    
    // Future modules will register themselves:
    // dap_chain_ledger_cli_token_init();
    // dap_chain_ledger_cli_event_init();
    // dap_chain_ledger_cli_balance_init();
    
    log_it(L_NOTICE, "Modular ledger CLI initialized successfully (plugin-based)");
    return 0;
}

/**
 * @brief Deinitialize ledger CLI module
 */
void dap_chain_ledger_cli_module_deinit(void)
{
    log_it(L_INFO, "Deinitializing ledger CLI module");
    
    // Deinitialize command modules
    dap_chain_ledger_cli_tx_deinit();
    
    // Deinitialize registry
    dap_ledger_cli_cmd_registry_deinit();
}



