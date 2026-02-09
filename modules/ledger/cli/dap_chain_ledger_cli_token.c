/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 *
 * This file is part of CellFrame SDK the open source project
 *
 * Modular token CLI commands implementation
 * Migrated from dap_chain_ledger_cli.c as part of CLI modularization
 */

#include "dap_chain_ledger_cli_token.h"
#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_cmd_registry.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_chain_ledger_cli_compat.h"  // For DAP_CHAIN_NODE_CLI_COM_TOKEN_* error codes
#include "dap_cli_server.h"
#include "dap_cli_error_codes.h"
#include "dap_json_rpc_errors.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_ledger.h"
#include "dap_enc_base58.h"

#define LOG_TAG "ledger_cli_token"

/**
 * @brief Helper to get ticker object from JSON object
 * @param a_jobj_tickers JSON object containing tickers
 * @param a_token_ticker Token ticker to find
 * @return JSON object for ticker or NULL if not found
 */
static dap_json_t *s_get_ticker(dap_json_t *a_jobj_tickers, const char *a_token_ticker)
{
    dap_json_t *l_result = NULL;
    dap_json_object_get_ex(a_jobj_tickers, a_token_ticker, &l_result);
    return l_result;
}

/**
 * @brief Show all tokens in a single chain
 * @param a_json_arr_reply JSON array for errors
 * @param a_chain Chain to iterate
 * @param a_ledger Ledger instance
 * @param a_token_name Optional token name filter (NULL for all)
 * @param a_hash_out_type Hash output type ("hex" or "base58")
 * @param a_token_num OUT: Number of tokens found
 * @param a_version API version
 * @return JSON object with token information
 */
static dap_json_t *s_db_chain_history_token_list(dap_json_t *a_json_arr_reply, 
                                                  dap_chain_t *a_chain, 
                                                  dap_ledger_t *a_ledger, 
                                                  const char *a_token_name, 
                                                  const char *a_hash_out_type, 
                                                  size_t *a_token_num, 
                                                  int a_version)
{
    dap_json_t *l_jobj_tickers = dap_json_object_new();
    if (!a_chain->callback_datum_iter_create) {
        log_it(L_WARNING, "Not defined datum iterators for chain \"%s\"", a_chain->name);
        return NULL;
    }
    
    size_t l_token_num = 0;
    dap_chain_datum_iter_t *l_datum_iter = a_chain->callback_datum_iter_create(a_chain);
    
    for (dap_chain_datum_t *l_datum = a_chain->callback_datum_iter_get_first(l_datum_iter);
            l_datum; l_datum = a_chain->callback_datum_iter_get_next(l_datum_iter)) {
        
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TOKEN)
            continue;
            
        size_t l_token_size = l_datum->header.data_size;
        dap_chain_datum_token_t *l_token = dap_chain_datum_token_read(l_datum->data, &l_token_size);
        
        if (a_token_name) {
            if (dap_strcmp(a_token_name, l_token->ticker) != 0) {
                DAP_DELETE(l_token);
                continue;
            }
        }
        
        dap_json_t *l_jobj_ticker = s_get_ticker(l_jobj_tickers, l_token->ticker);
        dap_json_t *l_jobj_decls = NULL;
        dap_json_t *l_jobj_updates = NULL;
        
        if (!l_jobj_ticker) {
            l_jobj_ticker = dap_json_object_new();
            // Get current token state from ledger
            dap_json_t *l_current_state = dap_ledger_token_info_by_name(a_ledger, l_token->ticker, a_version);
            dap_json_object_add_object(l_jobj_ticker, a_version == 1 ? "current state" : "current_state", l_current_state);
            l_jobj_decls = dap_json_array_new();
            l_jobj_updates = dap_json_array_new();
            dap_json_object_add_object(l_jobj_ticker, "declarations", l_jobj_decls);
            dap_json_object_add_object(l_jobj_ticker, "updates", l_jobj_updates);
            dap_json_object_add_object(l_jobj_tickers, l_token->ticker, l_jobj_ticker);
            l_token_num++;
        } else {
            dap_json_object_get_ex(l_jobj_ticker, "declarations", &l_jobj_decls);
            dap_json_object_get_ex(l_jobj_ticker, "updates", &l_jobj_updates);
        }
        
        int l_ret_code = l_datum_iter->ret_code;
        dap_json_t *json_history_token = dap_json_object_new();
        dap_json_object_add_string(json_history_token, "status", l_ret_code ? "DECLINED" : "ACCEPTED");
        dap_json_object_add_int(json_history_token, a_version == 1 ? "Ledger return code" : "ledger_ret_code", l_ret_code);
        
        switch (l_token->type) {
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
                dap_chain_datum_dump_json(a_json_arr_reply, json_history_token, l_datum, a_hash_out_type, a_chain->net_id, true, a_version);
                dap_json_array_add(l_jobj_decls, json_history_token);
                break;
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE:
            case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
                dap_chain_datum_dump_json(a_json_arr_reply, json_history_token, l_datum, a_hash_out_type, a_chain->net_id, false, a_version);
                dap_json_array_add(l_jobj_updates, json_history_token);
                break;
        }
        DAP_DELETE(l_token);
    }
    
    a_chain->callback_datum_iter_delete(l_datum_iter);
    
    if (a_token_num)
        *a_token_num = l_token_num;
        
    return l_jobj_tickers;
}

/**
 * @brief Show all tokens in all chains in network
 * @param a_json_arr_reply JSON array for errors
 * @param a_ledger Ledger instance
 * @param a_token_name Optional token name filter (NULL for all)
 * @param a_hash_out_type Hash output type ("hex" or "base58")
 * @param a_obj_out JSON object for output
 * @param a_version API version
 * @return Total number of tokens found
 */
static size_t s_db_net_history_token_list(dap_json_t *a_json_arr_reply, 
                                           dap_ledger_t *a_ledger, 
                                           const char *a_token_name, 
                                           const char *a_hash_out_type, 
                                           dap_json_t *a_obj_out, 
                                           int a_version)
{
    size_t l_token_num_total = 0;
    dap_json_t *json_arr_obj_tx = dap_json_array_new();
    
    // Iterate through registered chains in ledger
    dap_chain_info_t *l_chain_info, *l_tmp;
    HASH_ITER(hh, a_ledger->chains_registry, l_chain_info, l_tmp) {
        dap_chain_t *l_chain_cur = (dap_chain_t *)l_chain_info->chain_ptr;
        if (!l_chain_cur) continue;
        
        size_t l_token_num = 0;
        dap_json_t *json_obj_tx = s_db_chain_history_token_list(a_json_arr_reply, l_chain_cur, 
                                                                 a_ledger, a_token_name, 
                                                                 a_hash_out_type, &l_token_num, a_version);
        if (json_obj_tx)
            dap_json_array_add(json_arr_obj_tx, json_obj_tx);
        l_token_num_total += l_token_num;
    }
    
    dap_json_object_add_object(a_obj_out, a_version == 1 ? "TOKENS" : "tokens", json_arr_obj_tx);
    return l_token_num_total;
}

/**
 * @brief Main token command handler
 * @details Dispatches to list/info subcommands
 * 
 * Usage:
 *   token list -net <net_name> [-full] [-h]
 *   token info -net <net_name> -name <token_ticker> [-history_limit <N>] [-h]
 */
int com_token(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    enum { CMD_NONE, CMD_LIST, CMD_INFO, CMD_TX };
    int arg_index = 1;
    const char *l_net_str = NULL;
    dap_ledger_t *l_ledger = NULL;

    // Parse hash output type
    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, 
                               "invalid parameter -H, valid values: -H <hex | base58>");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    }

    // Parse network name
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    if (!l_net_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, 
                               "command requires parameter '-net'");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    }
    
    // Get ledger by net name
    l_ledger = dap_ledger_find_by_name(l_net_str);
    if (l_ledger == NULL) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR,
                               "command requires parameter '-net' to be valid chain network name");
        return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
    }

    // Determine subcommand
    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "list", NULL))
        l_cmd = CMD_LIST;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "info", NULL))
        l_cmd = CMD_INFO;
    else if (dap_cli_server_cmd_find_option_val(a_argv, 1, 2, "tx", NULL))
        l_cmd = CMD_TX;
        
    // Handle: token list
    if (l_cmd == CMD_LIST) {
        dap_json_t *json_obj_tx = dap_json_object_new();
        size_t l_total_all_token = s_db_net_history_token_list(a_json_arr_reply, l_ledger, NULL, 
                                                                l_hash_out_type, json_obj_tx, a_version);
        dap_json_object_length(json_obj_tx);
        dap_json_object_add_uint64(json_obj_tx, "tokens", l_total_all_token);
        dap_json_array_add(a_json_arr_reply, json_obj_tx);
        return 0;
    }
    // Handle: token info
    else if (l_cmd == CMD_INFO) {
        const char *l_token_name_str = NULL;
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-name", &l_token_name_str);
        if (!l_token_name_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR, 
                                   "command requires parameter '-name' <token name>");
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_PARAM_ERR;
        }
        dap_json_t *json_obj_tx = dap_json_object_new();
        if (!s_db_net_history_token_list(a_json_arr_reply, l_ledger, l_token_name_str, 
                                          l_hash_out_type, json_obj_tx, a_version)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_FOUND_ERR, 
                                   "token '%s' not found\n", l_token_name_str);
            return -DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
        }
        dap_json_array_add(a_json_arr_reply, json_obj_tx);
        return DAP_CHAIN_NODE_CLI_COM_TOKEN_OK;
    }
    // Handle: token tx (deprecated)
    else if (l_cmd == CMD_TX) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN, 
                               "The cellframe-node-cli token tx command is deprecated and no longer supported.\n");
        return DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
    }

    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN, 
                           "unknown command code %d", l_cmd);
    return -DAP_CHAIN_NODE_CLI_COM_TOKEN_UNKNOWN;
}

/**
 * @brief Initialize token commands module
 * @details Registers token command with CLI server
 */
int dap_chain_ledger_cli_token_init(void)
{
    log_it(L_INFO, "Initializing token CLI commands module");
    
    // Note: The "token" command is registered directly with CLI server
    // because it has its own subcommand structure (list, info, tx)
    // This is different from tx subcommands which use the registry
    
    log_it(L_NOTICE, "Token CLI commands module initialized");
    return 0;
}

/**
 * @brief Deinitialize token commands module
 */
void dap_chain_ledger_cli_token_deinit(void)
{
    log_it(L_INFO, "Deinitializing token CLI commands module");
}
