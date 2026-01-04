/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_internal.h"
#include "dap_cli_server.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_cli_error_codes.h"  // For dap_cli_error_code_get()
#include "dap_json_rpc_errors.h"

#define LOG_TAG "ledger_cli_dispatcher"

/**
 * @brief Main ledger CLI dispatcher
 * 
 * This is a temporary dispatcher that will gradually replace the old monolithic CLI.
 * Commands will be migrated one by one to the new modular structure.
 */
int dap_chain_ledger_cli_dispatcher(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    // For now, forward to old implementation
    // This will be gradually replaced command by command
    
    if (a_argc < 2) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Ledger command requires subcommand");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    // TODO: Dispatch to specific command modules as they are migrated:
    // - history_cmd
    // - token_cmd
    // - event_cmd
    // - tx_cmd
    
    log_it(L_DEBUG, "Ledger CLI dispatcher called with command: %s", a_argv[1]);
    
    // Temporary: return error for unmigrated commands
    dap_json_rpc_error_add(a_json_arr_reply, 
        dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
        "Command '%s' not yet migrated to new CLI system", a_argv[1]);
    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
}

/**
 * @brief Initialize new modular ledger CLI
 */
int dap_chain_ledger_cli_module_init(void)
{
    log_it(L_INFO, "Initializing modular ledger CLI system");
    
    // Register error codes
    dap_chain_ledger_cli_error_codes_init();
    
    // TODO: Register command modules as they are created
    
    log_it(L_NOTICE, "Modular ledger CLI initialized");
    return 0;
}

/**
 * @brief Deinitialize ledger CLI module
 */
void dap_chain_ledger_cli_module_deinit(void)
{
    log_it(L_INFO, "Deinitializing ledger CLI module");
    // Cleanup will be added as modules are created
}

