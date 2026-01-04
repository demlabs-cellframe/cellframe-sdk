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
    if (a_argc < 2) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Ledger command requires subcommand (e.g., tx, token, event)");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    const char *l_category = a_argv[1];
    
    // Check if category has any registered commands
    if (!dap_ledger_cli_cmd_is_registered(l_category, NULL)) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Unknown command category '%s'", l_category);
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    if (a_argc < 3) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Category '%s' requires subcommand", l_category);
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    const char *l_command = a_argv[2];
    
    // Execute via registry - plugin system!
    int l_result = dap_ledger_cli_cmd_execute(
        l_category, 
        l_command,
        a_argc - 2,      // Pass argc from command level
        a_argv + 2,      // Pass argv from command level
        a_json_arr_reply, 
        a_version
    );
    
    if (l_result == -2) {  // Command not found
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Unknown command '%s %s'", l_category, l_command);
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



