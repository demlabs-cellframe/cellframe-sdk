/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_tx.h"
#include "dap_chain_ledger_cli_token.h"
#include "dap_chain_ledger_cli_ledger.h"
#include "dap_chain_ledger_cli_tx_history.h"
#include "dap_chain_ledger_cli_cmd_registry.h"
#include "dap_cli_server.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_cli_error_codes.h"
#include "dap_json_rpc_errors.h"

#define LOG_TAG "ledger_cli_dispatcher"

static int s_print_for_tx_history_all(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt);
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
 * @return 0 on success, already initialized returns 0 silently
 */
int dap_chain_ledger_cli_module_init(void)
{
    // Guard against multiple initialization
    static bool s_initialized = false;
    if (s_initialized) {
        log_it(L_DEBUG, "Ledger CLI module already initialized, skipping");
        return 0;
    }

    log_it(L_INFO, "Initializing modular ledger CLI system");
    
    // Initialize registry
    dap_ledger_cli_cmd_registry_init();
    
    // Register error codes
    dap_chain_ledger_cli_error_codes_init();
    
    // Initialize command modules - they will self-register
    dap_chain_ledger_cli_tx_init();
    dap_chain_ledger_cli_token_init();
    dap_chain_ledger_cli_ledger_init();
    dap_chain_ledger_cli_tx_history_init();
    
    // Register the "tx" command with CLI server to route to dispatcher
    dap_cli_server_cmd_add("tx", dap_chain_ledger_cli_dispatcher, s_print_for_tx_history_all, 
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
    // dap_chain_ledger_cli_event_init();
    // dap_chain_ledger_cli_balance_init();
    
    s_initialized = true;
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
    dap_chain_ledger_cli_token_deinit();
    dap_chain_ledger_cli_ledger_deinit();
    dap_chain_ledger_cli_tx_history_deinit();
    
    // Deinitialize registry
    dap_ledger_cli_cmd_registry_deinit();
}

/**
 * @brief Public API: Initialize ledger CLI
 * @details Wrapper for dap_chain_ledger_cli_module_init (provides compatibility interface)
 * @return 0 on success, negative error code on failure
 */
int dap_chain_ledger_cli_init(void)
{
    return dap_chain_ledger_cli_module_init();
}

/**
 * @brief Public API: Deinitialize ledger CLI
 * @details Wrapper for dap_chain_ledger_cli_module_deinit
 */
void dap_chain_ledger_cli_deinit(void)
{
    dap_chain_ledger_cli_module_deinit();
}


/**
 * @brief s_print_for_tx_history_all
 * Post-processing callback for tx_history command. Formats JSON input into
 * human-readable table output.
 *
 * @param a_json_input Input JSON from command handler
 * @param a_json_output Output JSON array to write formatted result
 * @param a_cmd_param Command parameters array
 * @param a_cmd_cnt Count of command parameters
 * @return 0 on success (result written to a_json_output), non-zero to use original input
*/
static int s_print_for_tx_history_all(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt)
{
    dap_return_val_if_pass(!a_json_input || !a_json_output, -1);

    bool l_table_mode = dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "-h") != -1;
    if (!l_table_mode)
        return -1;

    if (dap_json_get_type(a_json_input) != DAP_JSON_TYPE_ARRAY)
        return -1;

    int result_count = dap_json_array_length(a_json_input);
    if (result_count <= 0)
        return -1;

    dap_string_t *l_str = dap_string_new("\n");

    // Special handling for -addr and -w
    if (dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "-addr") != -1 ||
        dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "-w") != -1) {
        dap_json_t *tx_array = dap_json_array_get_idx(a_json_input, 0);
        dap_json_t *summary_obj = dap_json_array_get_idx(a_json_input, 1);
        if (tx_array && dap_json_get_type(tx_array) == DAP_JSON_TYPE_ARRAY) {
            dap_json_t *first_el = dap_json_array_get_idx(tx_array, 0);
            dap_json_t *addr_obj = NULL;
            if (first_el && dap_json_get_type(first_el) == DAP_JSON_TYPE_OBJECT &&
               (dap_json_object_get_ex(first_el, "addr", &addr_obj) ||
                dap_json_object_get_ex(first_el, "address", &addr_obj))) {
                dap_string_append_printf(l_str, "Address: %s\n", dap_json_get_string(addr_obj));
            }

            dap_string_append(l_str, "_________________________________________________________________________________________________________________"
                "________________________________________________\n");
            dap_string_append(l_str, " # \t| Hash \t\t\t\t\t\t\t\t     | Status   | Action \t  | Service \t     | Time create\n");
            dap_string_append(l_str, "_________________________________________________________________________________________________________________"
                "________________________________________________\n");
            char *l_limit = NULL; char *l_offset = NULL; int row_num = 0;
            for (size_t i = 0; i < (size_t)dap_json_array_length(tx_array); i++) {
                dap_json_t *tx_obj = dap_json_array_get_idx(tx_array, (int)i);
                if (!tx_obj || dap_json_get_type(tx_obj) != DAP_JSON_TYPE_OBJECT)
                    continue;
                dap_json_t *tmp = NULL;
                if (dap_json_object_get_ex(tx_obj, "addr", &tmp) || dap_json_object_get_ex(tx_obj, "address", &tmp))
                    continue;
                dap_json_t *j_obj_lim = NULL, *j_obj_off = NULL;
                if (dap_json_object_get_ex(tx_obj, "limit", &j_obj_lim)) {
                    dap_json_object_get_ex(tx_obj, "offset", &j_obj_off);
                    l_limit = dap_json_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT, dap_json_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                    if (j_obj_off)
                        l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT, dap_json_get_int64(j_obj_off));
                    continue;
                }
                dap_json_t *hash_obj = NULL, *status_obj = NULL, *action_obj = NULL, *service_obj = NULL, *created_obj = NULL;
                if (dap_json_object_get_ex(tx_obj, "hash", &hash_obj) &&
                    dap_json_object_get_ex(tx_obj, "status", &status_obj) &&
                    dap_json_object_get_ex(tx_obj, "action", &action_obj) &&
                    dap_json_object_get_ex(tx_obj, "service", &service_obj) &&
                    dap_json_object_get_ex(tx_obj, "tx_created", &created_obj)) {
                    row_num++;
                    dap_string_append_printf(l_str, "%d\t| %-60s | %s\t| %-15s |  %-16s| %s\t|\n",
                        row_num,
                        dap_json_get_string(hash_obj),
                        dap_json_get_string(status_obj),
                        dap_json_get_string(action_obj),
                        dap_json_get_string(service_obj),
                        dap_json_get_string(created_obj));
                }
            }
            dap_string_append(l_str, "_________________________________________________________________________________________________________________"
                "________________________________________________\n");
            if (l_limit) { dap_string_append_printf(l_str, "\tlimit: %s \n", l_limit); DAP_DELETE(l_limit); }
            if (l_offset) { dap_string_append_printf(l_str, "\toffset: %s \n", l_offset); DAP_DELETE(l_offset); }
            if (summary_obj && dap_json_get_type(summary_obj) == DAP_JSON_TYPE_OBJECT) {
                dap_json_t *tx_sum_obj = NULL, *accepted_obj = NULL, *rejected_obj = NULL;
                dap_json_object_get_ex(summary_obj, "tx_sum", &tx_sum_obj);
                dap_json_object_get_ex(summary_obj, "accepted_tx", &accepted_obj);
                dap_json_object_get_ex(summary_obj, "rejected_tx", &rejected_obj);
                if (tx_sum_obj || accepted_obj || rejected_obj)
                    dap_string_append_printf(l_str, "Total: %d transactions (Accepted: %d, Rejected: %d)\n",
                        tx_sum_obj ? (int)dap_json_get_int64(tx_sum_obj) : row_num,
                        accepted_obj ? (int)dap_json_get_int64(accepted_obj) : 0,
                        rejected_obj ? (int)dap_json_get_int64(rejected_obj) : 0);
            }
            goto finalize;
        }
    }

    // Check if this is a count response
    if (result_count == 1) {
        dap_json_t *first_obj = dap_json_array_get_idx(a_json_input, 0);
        dap_json_t *count_obj = NULL;
        if (dap_json_object_get_ex(first_obj, "Number of transaction", &count_obj) ||
            dap_json_object_get_ex(first_obj, "total_tx_count", &count_obj)) {
            dap_string_append_printf(l_str, "Total transactions count: %"DAP_INT64_FORMAT"\n", dap_json_get_int64(count_obj));
            goto finalize;
        }
    }

    // Handle transaction history list
    if (result_count >= 2) {
        dap_json_t *tx_array = dap_json_array_get_idx(a_json_input, 0);
        dap_json_t *summary_obj = dap_json_array_get_idx(a_json_input, 1);

        dap_string_append(l_str, "_________________________________________________________________________________________________________________"
            "________________________________________________\n");
        dap_string_append(l_str, " # \t| Hash \t\t\t\t\t\t\t\t     | Status   | Action \t  | Token \t     | Time create\n");
        dap_string_append(l_str, "_________________________________________________________________________________________________________________"
            "________________________________________________\n");

        if (dap_json_get_type(tx_array) == DAP_JSON_TYPE_ARRAY) {
            char *l_limit = NULL;
            char *l_offset = NULL;
            int tx_count = dap_json_array_length(tx_array);
            for (int i = 0; i < tx_count; i++) {
                dap_json_t *tx_obj = dap_json_array_get_idx(tx_array, i);
                if (!tx_obj) continue;

                dap_json_t *tx_num_obj = NULL, *hash_obj = NULL;
                dap_json_t *status_obj = NULL, *action_obj = NULL;
                dap_json_t *token_obj = NULL, *j_obj_lim = NULL, *j_obj_off = NULL;
                dap_json_t *j_obj_create = NULL;

                // Try both v1 and v2 field naming styles
                bool l_found_fields = (dap_json_object_get_ex(tx_obj, "tx number", &tx_num_obj) ||
                                       dap_json_object_get_ex(tx_obj, "tx_num", &tx_num_obj)) &&
                                      dap_json_object_get_ex(tx_obj, "hash", &hash_obj) &&
                                      dap_json_object_get_ex(tx_obj, "status", &status_obj) &&
                                      dap_json_object_get_ex(tx_obj, "action", &action_obj) &&
                                      (dap_json_object_get_ex(tx_obj, "token ticker", &token_obj) ||
                                       dap_json_object_get_ex(tx_obj, "token_ticker", &token_obj)) &&
                                      (dap_json_object_get_ex(tx_obj, "tx created", &j_obj_create) ||
                                       dap_json_object_get_ex(tx_obj, "tx_created", &j_obj_create));
                if (l_found_fields) {
                    // tx_num can be int or string depending on version
                    int64_t l_tx_num = dap_json_get_int64(tx_num_obj);
                    dap_string_append_printf(l_str, "%"DAP_INT64_FORMAT"\t| %-60s | %s\t| %-15s |  %-16s| %s\t|\n",
                       l_tx_num,
                       dap_json_get_string(hash_obj),
                       dap_json_get_string(status_obj),
                       dap_json_get_string(action_obj),
                       dap_json_get_string(token_obj),
                       dap_json_get_string(j_obj_create));
                } else if (dap_json_object_get_ex(tx_obj, "limit", &j_obj_lim)) {
                    dap_json_object_get_ex(tx_obj, "offset", &j_obj_off);
                    l_limit = dap_json_get_int64(j_obj_lim) ? dap_strdup_printf("%"DAP_INT64_FORMAT, dap_json_get_int64(j_obj_lim)) : dap_strdup_printf("unlimit");
                    if (j_obj_off)
                        l_offset = dap_strdup_printf("%"DAP_INT64_FORMAT, dap_json_get_int64(j_obj_off));
                } else {
                    char *l_json_str = dap_json_to_string(tx_obj);
                    if (l_json_str) {
                        dap_string_append(l_str, l_json_str);
                        dap_string_append(l_str, "\n");
                        DAP_DELETE(l_json_str);
                    }
                }
            }
            dap_string_append(l_str, "_________________________________________________________________________________________________________________"
                "________________________________________________\n");
            if (l_limit) {
                dap_string_append_printf(l_str, "\tlimit: %s \n", l_limit);
                DAP_DELETE(l_limit);
            }
            if (l_offset) {
                dap_string_append_printf(l_str, "\toffset: %s \n", l_offset);
                DAP_DELETE(l_offset);
            }
        }

        if (summary_obj) {
            dap_json_t *network_obj = NULL, *chain_obj = NULL;
            dap_json_t *tx_sum_obj = NULL, *accepted_obj = NULL, *rejected_obj = NULL;
            
            dap_json_object_get_ex(summary_obj, "network", &network_obj);
            dap_json_object_get_ex(summary_obj, "chain", &chain_obj);
            dap_json_object_get_ex(summary_obj, "tx_sum", &tx_sum_obj);
            dap_json_object_get_ex(summary_obj, "accepted_tx", &accepted_obj);
            dap_json_object_get_ex(summary_obj, "rejected_tx", &rejected_obj);

            dap_string_append(l_str, "\n=== Transaction History ===\n");
            if (network_obj && chain_obj) {
                dap_string_append_printf(l_str, "Network: %s, Chain: %s\n", 
                       dap_json_get_string(network_obj),
                       dap_json_get_string(chain_obj));
            }
            if (tx_sum_obj && accepted_obj && rejected_obj) {
                dap_string_append_printf(l_str, "Total: %d transactions (Accepted: %d, Rejected: %d)\n\n",
                       (int)dap_json_get_int64(tx_sum_obj),
                       (int)dap_json_get_int64(accepted_obj),
                       (int)dap_json_get_int64(rejected_obj));
            }
        }
        goto finalize;
    }

    // No handler matched - use original JSON
    dap_string_free(l_str, true);
    return -1;

finalize:
    {
        dap_json_t *l_json_result = dap_json_object_new();
        dap_json_object_add_string(l_json_result, "output", l_str->str);
        dap_json_array_add(a_json_output, l_json_result);
        dap_string_free(l_str, true);
    }
    return 0;
}
    
    
