/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_internal.h"
#include "dap_cli_server.h"
#include "dap_cli_error_codes.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_json_rpc_errors.h"

#define LOG_TAG "ledger_cli_internal"

/**
 * @brief Parse hash output type parameter
 */
int cli_parse_hash_out_type(char **a_argv, int a_arg_index, int a_argc, const char **a_hash_out_type)
{
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-H", a_hash_out_type);
    if (!*a_hash_out_type) {
        *a_hash_out_type = "hex";
    }
    
    if (dap_strcmp(*a_hash_out_type, "hex") && dap_strcmp(*a_hash_out_type, "base58")) {
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    
    return 0;
}

/**
 * @brief Get ledger by network name
 */
dap_ledger_t* cli_get_ledger_by_net_name(const char *a_net_name, dap_json_t *a_json_arr_reply)
{
    if (!a_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), 
            "Network name required");
        return NULL;
    }
    
    dap_ledger_t *l_ledger = dap_ledger_find_by_name(a_net_name);
    if (!l_ledger) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_NET_FIND_ERR"), 
            "Ledger not found for network '%s'", a_net_name);
        return NULL;
    }
    
    return l_ledger;
}

/**
 * @brief Validate and parse pagination parameters
 */
int cli_parse_pagination(char **a_argv, int a_argc, size_t *a_limit, size_t *a_offset)
{
    const char *l_limit_str = NULL;
    const char *l_offset_str = NULL;
    
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-limit", &l_limit_str);
    dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-offset", &l_offset_str);
    
    *a_limit = l_limit_str ? strtoull(l_limit_str, NULL, 10) : 0;
    *a_offset = l_offset_str ? strtoull(l_offset_str, NULL, 10) : 0;
    
    return 0;
}

