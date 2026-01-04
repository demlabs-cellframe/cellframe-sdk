/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_tx.h"
#include "dap_cli_server.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_cli_error_codes.h"  // For dap_cli_error_code_get()
#include "dap_json_rpc_errors.h"

#define LOG_TAG "ledger_cli_dispatcher"

/**
 * @brief Main ledger CLI dispatcher
 * 
 * Routes commands to appropriate modules.
 * NEW MODULAR ARCHITECTURE - each command category has its own module.
 */
int dap_chain_ledger_cli_dispatcher(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    if (a_argc < 2) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Ledger command requires subcommand");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    const char *l_subcmd = a_argv[1];
    
    // Route to TX commands module
    if (strcmp(l_subcmd, "tx") == 0) {
        if (a_argc < 3) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                "tx command requires subcommand (create, verify, history)");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        const char *l_tx_cmd = a_argv[2];
        
        if (strcmp(l_tx_cmd, "create") == 0) {
            return ledger_cli_tx_create(a_argc - 2, a_argv + 2, a_json_arr_reply, a_version);
        } else if (strcmp(l_tx_cmd, "create_json") == 0) {
            return ledger_cli_tx_create_json(a_argc - 2, a_argv + 2, a_json_arr_reply, a_version);
        } else if (strcmp(l_tx_cmd, "verify") == 0) {
            return ledger_cli_tx_verify(a_argc - 2, a_argv + 2, a_json_arr_reply, a_version);
        } else if (strcmp(l_tx_cmd, "history") == 0) {
            return ledger_cli_tx_history(a_argc - 2, a_argv + 2, a_json_arr_reply, a_version);
        }
        
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
            "Unknown tx subcommand '%s'", l_tx_cmd);
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    // TODO: Add more command categories:
    // - token (token list, token info, etc.)
    // - history (account history)  
    // - balance (balance check)
    // - event (event create, event list)
    
    dap_json_rpc_error_add(a_json_arr_reply, 
        dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
        "Unknown command '%s' (available: tx)", l_subcmd);
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
    
    // Initialize command modules
    dap_chain_ledger_cli_tx_init();
    
    log_it(L_NOTICE, "Modular ledger CLI initialized successfully");
    return 0;
}

/**
 * @brief Deinitialize ledger CLI module
 */
void dap_chain_ledger_cli_module_deinit(void)
{
    log_it(L_INFO, "Deinitializing ledger CLI module");
    dap_chain_ledger_cli_tx_deinit();
}


