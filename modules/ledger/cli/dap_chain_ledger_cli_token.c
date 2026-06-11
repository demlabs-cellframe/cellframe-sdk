/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_token.h"
#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_cmd_registry.h"
#include "dap_cli_error_codes.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_json_rpc_errors.h"
#include "dap_cli_server.h"

#define LOG_TAG "ledger_cli_token"

/**
 * @brief token info - Query token info from ledger
 *
 * Usage: ledger token info -net <network> -token <ticker>
 *
 * Returns JSON with token_name, subtype, decimals, supply_current, supply_total, etc.
 */
int ledger_cli_token_info(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int l_arg_index = 1;
    const char *l_net_name = NULL;
    const char *l_token_ticker = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_ticker);

    if (!l_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply,
            dap_cli_error_code_get("LEDGER_PARAM_ERR"),
            "token info requires -net parameter");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    if (!l_token_ticker) {
        dap_json_rpc_error_add(a_json_arr_reply,
            dap_cli_error_code_get("LEDGER_PARAM_ERR"),
            "token info requires -token parameter");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply,
            dap_cli_error_code_get("LEDGER_PARAM_ERR"),
            "Network '%s' not found", l_net_name);
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    dap_ledger_t *l_ledger = l_net->pub.ledger;
    if (!l_ledger) {
        dap_json_rpc_error_add(a_json_arr_reply,
            dap_cli_error_code_get("LEDGER_PARAM_ERR"),
            "Ledger not available for network '%s'", l_net_name);
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    dap_json_t *l_token_info = dap_ledger_token_info_by_name(l_ledger, l_token_ticker, a_version);
    if (!l_token_info) {
        dap_json_rpc_error_add(a_json_arr_reply,
            dap_cli_error_code_get("LEDGER_PARAM_ERR"),
            "Token '%s' not found in ledger", l_token_ticker);
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    dap_json_array_add_object(a_json_arr_reply, l_token_info);
    return 0;
}

/**
 * @brief Initialize Token commands module
 */
int dap_chain_ledger_cli_token_init(void)
{
    log_it(L_INFO, "Initializing token CLI commands");

    dap_ledger_cli_cmd_register("token", "info", ledger_cli_token_info,
        "Query token info (decimals, type, supply) from ledger");

    log_it(L_NOTICE, "Token CLI commands initialized");
    return 0;
}

/**
 * @brief Deinitialize Token commands module
 */
void dap_chain_ledger_cli_token_deinit(void)
{
    dap_ledger_cli_cmd_unregister("token", "info");
}
