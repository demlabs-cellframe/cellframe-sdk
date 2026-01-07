/*
 * Authors:
 * Cellframe       https://cellframe.net
 * DeM Labs Inc.   https://demlabs.net
 * Sources         https://gitlab.demlabs.net/cellframe/cellframe-sdk
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of DAP SDK the open source project
 *
 *    DAP SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <dirent.h>
#include <time.h>
#include "dap_chain_wallet_cli.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_wallet_shared.h"
#include "dap_cli_server.h"
#include "dap_json_rpc.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_common.h"
#include "dap_config.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_notify_srv.h"

#define LOG_TAG "dap_chain_wallet_cli"

// Forward declarations for helper functions
static void s_wallet_list(const char *a_wallet_path, dap_json_t *a_json_arr_out, dap_chain_addr_t *a_addr, int a_version);
static void s_new_wallet_info_notify(const char *a_wallet_name);
static dap_json_t *wallet_list_json_collect(int a_version);

// Forward declaration for main command handler
static int com_tx_wallet(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version);

/**
 * @brief Initialize wallet CLI commands
 * 
 * Registers all wallet-related commands with the CLI server.
 * This function should be called during wallet module initialization.
 * 
 * @return 0 on success, negative error code on failure
 */
int dap_chain_wallet_cli_init(void)
{
    // Register wallet command
    dap_cli_server_cmd_add("wallet", com_tx_wallet, NULL,
                           "Wallet operations",
                           -1, // auto ID
                           "wallet { new -w <wallet_name> | list | info | activate | deactivate | convert | outputs | find | shared }\n"
                           "Create, list, and manage wallets\n"
                           "\nExamples:\n"
                           "  wallet new -w myWallet -sign sig_dil -password myPass\n"
                           "  wallet list\n"
                           "  wallet info -w myWallet -net main\n"
                           "  wallet activate -w myWallet\n");

    log_it(L_INFO, "Wallet CLI commands registered");
    return 0;
}

/**
 * @brief Cleanup wallet CLI
 * 
 * Unregisters wallet commands from CLI server.
 */
void dap_chain_wallet_cli_deinit(void)
{
    // Commands are automatically unregistered when CLI server shuts down
    log_it(L_INFO, "Wallet CLI commands unregistered");
}

/**
 * @brief Helper function to list wallets
 */
static void s_wallet_list(const char *a_wallet_path, dap_json_t *a_json_arr_out, dap_chain_addr_t *a_addr, int a_version)
{
    if (!a_wallet_path || !a_json_arr_out)
        return;
    const char *l_addr_str = NULL;
    dap_chain_addr_t * l_addr = NULL;
    DIR * l_dir = opendir(a_wallet_path);
    if(l_dir) {
        struct dirent * l_dir_entry = NULL;
        while( (l_dir_entry = readdir(l_dir)) ) {
            if (dap_strcmp(l_dir_entry->d_name, "..") == 0 || dap_strcmp(l_dir_entry->d_name, ".") == 0)
                continue;
            const char *l_file_name = l_dir_entry->d_name;
            size_t l_file_name_len = (l_file_name) ? strlen(l_file_name) : 0;
            unsigned int res = 0;
            dap_json_t *json_obj_wall = dap_json_object_new();
            if (!json_obj_wall)
                return;
            if ( (l_file_name_len > 8) && (!strcmp(l_file_name + l_file_name_len - 8, ".dwallet")) ) {
                char l_file_path_tmp[MAX_PATH] = {0};
                snprintf(l_file_path_tmp, sizeof(l_file_path_tmp) - 1, "%s/%s", a_wallet_path, l_file_name);
                dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_file_name, a_wallet_path, &res);

                if (l_wallet) {
                    if (a_addr) {
                        l_addr = dap_chain_wallet_get_addr(l_wallet, a_addr->net_id);
                        if (l_addr && dap_chain_addr_compare(l_addr, a_addr)) {
                            dap_json_object_add_string(json_obj_wall, "wallet", l_file_name);
                            if(l_wallet->flags & DAP_WALLET$M_FL_ACTIVE)
                                dap_json_object_add_string(json_obj_wall, "status", "protected-active");
                            else
                                dap_json_object_add_string(json_obj_wall, "status", "unprotected");
                            dap_json_object_add_object(json_obj_wall, "deprecated", dap_json_object_new_string(
                                                        strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ? "true" : "false"));
                        }
                        else {
                            dap_json_object_free(json_obj_wall);
                            dap_chain_wallet_close(l_wallet);
                            DAP_DEL_Z(l_addr);
                            continue;
                        }
                        DAP_DEL_Z(l_addr);
                        dap_chain_wallet_close(l_wallet);
                        dap_json_array_add(a_json_arr_out, json_obj_wall);
                        break;
                    }
                    dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Wallet" : "wallet", l_file_name);
                    if(l_wallet->flags & DAP_WALLET$M_FL_ACTIVE)
                        dap_json_object_add_string(json_obj_wall, "status", "protected-active");
                    else
                        dap_json_object_add_string(json_obj_wall, "status", "unprotected");
                    dap_json_object_add_object(json_obj_wall, "deprecated", dap_json_object_new_string(
                            strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ? "true" : "false"));

                    //Get sign for wallet
                    dap_json_t *l_jobj_sings = NULL;
                    dap_chain_wallet_internal_t *l_w_internal = DAP_CHAIN_WALLET_INTERNAL(l_wallet);
                    if (l_w_internal->certs_count == 1) {
                        l_jobj_sings = dap_json_object_new_string(
                            dap_sign_type_to_str(
                                dap_sign_type_from_key_type(l_w_internal->certs[0]->enc_key->type)));
                    } else {
                        dap_string_t *l_str_signs = dap_string_new("");
                        for (size_t i = 0; i < l_w_internal->certs_count; i++) {
                            dap_string_append_printf(l_str_signs, "%s%s",
                                                    dap_sign_type_to_str(dap_sign_type_from_key_type(
                                                        l_w_internal->certs[i]->enc_key->type)),
                                                    ((i + 1) == l_w_internal->certs_count) ? "" : ", ");
                        }
                        l_jobj_sings = dap_json_object_new_string(l_str_signs->str);
                        dap_string_free(l_str_signs, true);
                    }
                    dap_json_object_add_object(json_obj_wall, "signs", l_jobj_sings);
                    dap_chain_wallet_close(l_wallet);
                } else if (!a_addr){
                    dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Wallet" : "wallet", l_file_name);
                    if(res==4)dap_json_object_add_string(json_obj_wall, "status", "protected-inactive");
                    else if(res != 0)dap_json_object_add_string(json_obj_wall, "status", "invalid");
                }
            } else if (a_addr) {
                dap_json_object_free(json_obj_wall);
                continue;
            } else if ((l_file_name_len > 7) && (!strcmp(l_file_name + l_file_name_len - 7, ".backup"))) {
                dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Wallet" : "wallet", l_file_name);
                dap_json_object_add_string(json_obj_wall, "status", "Backup");
            }
            if (dap_json_object_length(json_obj_wall)) 
                dap_json_array_add(a_json_arr_out, json_obj_wall);
            else 
                dap_json_object_free(json_obj_wall);
        }
        if (a_addr && (dap_json_array_length(a_json_arr_out) == 0)) {
            dap_json_t *json_obj_out = dap_json_object_new();
            if (!json_obj_out) return;
            dap_json_object_add_string(json_obj_out, "status", "not found");
            dap_json_array_add(a_json_arr_out, json_obj_out);
        }
        closedir(l_dir);
    }
}

/**
 * @brief Helper function to collect wallet list in JSON format
 */
static dap_json_t *wallet_list_json_collect(int a_version)
{
    dap_json_t *l_json = dap_json_object_new();
    dap_json_object_add_string(l_json, "class", "WalletList");
    dap_json_t *l_j_wallets = dap_json_array_new();
    s_wallet_list(dap_chain_wallet_get_path(g_config), l_j_wallets, NULL, a_version);
    dap_json_object_add_object(l_json, "wallets", l_j_wallets);
    return l_json;
}

/**
 * @brief Helper function to notify about new wallet info
 */
static void s_new_wallet_info_notify(const char *a_wallet_name)
{
    dap_json_t *l_json = dap_json_object_new();
    dap_json_object_add_string(l_json, "class", "WalletInfo");
    dap_json_t *l_json_wallet_info = dap_json_object_new();
    dap_json_object_add_object(l_json_wallet_info, a_wallet_name, dap_chain_wallet_info_to_json(a_wallet_name, dap_chain_wallet_get_path(g_config)));
    dap_json_object_add_object(l_json, "wallet", l_json_wallet_info);
    char *l_json_str = dap_json_to_string(l_json);
    dap_notify_server_send(l_json_str);
    DAP_DELETE(l_json_str);
    dap_json_object_free(l_json);
}

/**
 * @brief Main wallet command handler
 * 
 * NOTE: This is a MASSIVE function (~650 lines) that handles ALL wallet operations.
 * It should eventually be refactored into smaller functions, but for now we're
 * maintaining compatibility with the original cmd module implementation.
 */
static int com_tx_wallet(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    const char *c_wallets_path = dap_chain_wallet_get_path(g_config);
    enum { CMD_NONE, CMD_WALLET_NEW, CMD_WALLET_LIST, CMD_WALLET_INFO, CMD_WALLET_ACTIVATE, 
                CMD_WALLET_DEACTIVATE, CMD_WALLET_CONVERT, CMD_WALLET_OUTPUTS, CMD_WALLET_FIND, CMD_WALLET_SHARED };
    int l_arg_index = 1, l_rc, cmd_num = CMD_NONE;

    // find  add parameter ('alias' or 'handshake')
    if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "new", NULL))
        cmd_num = CMD_WALLET_NEW;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "list", NULL))
        cmd_num = CMD_WALLET_LIST;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "info", NULL))
        cmd_num = CMD_WALLET_INFO;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "activate", NULL))
        cmd_num = CMD_WALLET_ACTIVATE;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "deactivate", NULL))
        cmd_num = CMD_WALLET_DEACTIVATE;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "convert", NULL))
        cmd_num = CMD_WALLET_CONVERT;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "outputs", NULL))
        cmd_num = CMD_WALLET_OUTPUTS;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "find", NULL))
        cmd_num = CMD_WALLET_FIND;
    else if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "shared", NULL))
        cmd_num = CMD_WALLET_SHARED;

    l_arg_index++;

    if(cmd_num == CMD_NONE) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
                "Format of command: wallet { new -w <wallet_name> | list | info | activate | deactivate | convert | outputs | find | shared }");
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR;        
    }

    const char *l_addr_str = NULL, *l_wallet_name = NULL, *l_net_name = NULL, *l_sign_type_str = NULL, *l_restore_str = NULL,
            *l_pass_str = NULL, *l_ttl_str = NULL, *l_file_path = NULL;

    // find wallet addr
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-addr", &l_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-password", &l_pass_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-sign", &l_sign_type_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-file", &l_file_path);

    // Check if wallet name has only digits and English letter
    if (l_wallet_name && !dap_isstralnum(l_wallet_name)){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
        "Wallet name must contains digits and aplhabetical symbols");
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
    }

    dap_chain_net_t * l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    dap_chain_wallet_t *l_wallet = NULL;
    dap_chain_addr_t *l_addr = NULL;

    if(l_net_name && !l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
        "Not found net by name '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
    }
    dap_json_t *json_obj_out = NULL;
    dap_json_t *json_arr_out = dap_json_array_new();
    if (!json_arr_out) {
        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR;
    }
    switch (cmd_num) {
        // wallet list
        case CMD_WALLET_LIST:
            s_wallet_list(c_wallets_path, json_arr_out, NULL, a_version);
            if (dap_json_array_length(json_arr_out) == 0) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR,
                    "Сouldn't find any wallets");
            }
            break;
        // wallet info
        case CMD_WALLET_INFO: {
            dap_ledger_t *l_ledger = NULL;
            if ((l_wallet_name && l_addr_str) || (!l_wallet_name && !l_addr_str)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
                "You should use either the -w or -addr option for the wallet info command.");
                dap_json_object_free(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
            }
            if(l_wallet_name) {
                if(!l_net) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                           "Subcommand info requires parameter '-net'");
                    dap_json_object_free(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
                l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
                l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id );
            } else {
                l_addr = dap_chain_addr_from_str(l_addr_str);
            }
            
            if (!l_addr || dap_chain_addr_is_blank(l_addr)){
                if (l_wallet) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CAN_NOT_GET_ADDR,
                                           "Wallet %s contains an unknown certificate type, the wallet address could not be calculated.", l_wallet_name);
                    dap_chain_wallet_close(l_wallet);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CAN_NOT_GET_ADDR;
                }
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR,
                                       "Wallet not found or addr not recognized");
                dap_json_object_free(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_FOUND_ERR;
            } else {
                l_net = dap_chain_net_by_id(l_addr->net_id);
                if (l_net) {
                    l_ledger = l_net->pub.ledger;
                    l_net_name = l_net->pub.name;
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_ERR,
                                           "Can't find network id 0x%016"DAP_UINT64_FORMAT_X" from address %s",
                                           l_addr->net_id.uint64, l_addr_str);
                    dap_json_object_free(json_arr_out);
                    DAP_DELETE(l_addr);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_ERR;
                }
            }
            dap_json_t *json_obj_wall = dap_json_object_new();
            const char *l_addr_str = dap_chain_addr_to_str_static((dap_chain_addr_t*) l_addr);
            if(l_wallet)
            {
                dap_json_object_add_object(json_obj_wall, "sign", dap_json_object_new_string(
                                                                  strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ?
                                                                  dap_chain_wallet_check_sign(l_wallet) : "correct"));
                dap_json_object_add_string(json_obj_wall, "wallet", l_wallet->name);
            }
            dap_json_object_add_object(json_obj_wall, "addr", l_addr_str ? dap_json_object_new_string(l_addr_str) : dap_json_object_new_string("-"));
            dap_json_object_add_object(json_obj_wall, "pkey_hash", dap_json_object_new_string(dap_hash_fast_to_str_static(&l_addr->data.hash_fast)));
            dap_json_object_add_object(json_obj_wall, "network", l_net_name? dap_json_object_new_string(l_net_name) : dap_json_object_new_string("-"));

            size_t l_addr_tokens_size = 0;
            char **l_addr_tokens = NULL;
            dap_ledger_addr_get_token_ticker_all(l_ledger, l_addr, &l_addr_tokens, &l_addr_tokens_size);
            if (l_wallet) {
                //Get sign for wallet
                dap_json_t *l_jobj_sings = NULL;
                dap_chain_wallet_internal_t *l_w_internal = DAP_CHAIN_WALLET_INTERNAL(l_wallet);
                if (l_w_internal->certs_count == 1) {
                    l_jobj_sings = dap_json_object_new_string(
                        dap_sign_type_to_str(
                            dap_sign_type_from_key_type(l_w_internal->certs[0]->enc_key->type)));
                } else {
                    dap_string_t *l_str_signs = dap_string_new("");
                    for (size_t i = 0; i < l_w_internal->certs_count; i++) {
                        dap_string_append_printf(l_str_signs, "%s%s",
                                                 dap_sign_type_to_str(dap_sign_type_from_key_type(
                                                     l_w_internal->certs[i]->enc_key->type)),
                                                 ((i + 1) == l_w_internal->certs_count) ? "" : ", ");
                    }
                    l_jobj_sings = dap_json_object_new_string(l_str_signs->str);
                    dap_string_free(l_str_signs, true);
                }
                dap_json_object_add_object(json_obj_wall, "signs", l_jobj_sings);
            } else {
                dap_json_object_add_object(json_obj_wall, "signs",
                                       dap_json_object_new_string(dap_sign_type_to_str(l_addr->sig_type)));
            }
            if (l_addr_tokens_size) {
                dap_json_t *j_arr_balance = dap_json_array_new();
                for(size_t i = 0; i < l_addr_tokens_size; i++) {
                    dap_json_t *l_jobj_token = dap_json_object_new();
                    dap_json_t *l_jobj_ticker = dap_json_object_new_string(l_addr_tokens[i]);
                    const char *l_description =  dap_ledger_get_description_by_ticker(l_ledger, l_addr_tokens[i]);
                    dap_json_t *l_jobj_description = l_description ? dap_json_object_new_string(l_description)
                                                                    : dap_json_object_new();
                    dap_json_object_add_object(l_jobj_token, "ticker", l_jobj_ticker);
                    dap_json_object_add_object(l_jobj_token, "description", l_jobj_description);
                    dap_json_t *j_balance_data = dap_json_object_new();
                    uint256_t l_balance = dap_ledger_calc_balance(l_ledger, l_addr, l_addr_tokens[i]);
                    const char *l_balance_coins, *l_balance_datoshi = dap_uint256_to_char(l_balance, &l_balance_coins);
                    dap_json_object_add_string(j_balance_data, "balance", "");
                    dap_json_object_add_string(j_balance_data, "coins", l_balance_coins);
                    dap_json_object_add_string(j_balance_data, "datoshi", l_balance_datoshi);
                    dap_json_object_add_object(j_balance_data, "token", l_jobj_token);
                    dap_json_array_add(j_arr_balance, j_balance_data);
                    DAP_DELETE(l_addr_tokens[i]);
                }
                DAP_DELETE(l_addr_tokens);
                dap_json_object_add_object(json_obj_wall, "tokens", j_arr_balance);
            }
            dap_ledger_locked_out_t *l_locked_outs = dap_ledger_get_locked_values(l_ledger, l_addr);
            if (l_locked_outs) {
                dap_json_t *j_arr_locked_balance = dap_json_array_new();
                dap_ledger_locked_out_t *it, *tmp;
                LL_FOREACH_SAFE(l_locked_outs, it, tmp) {
                    dap_json_t *l_jobj_token = dap_json_object_new();
                    dap_json_t *l_jobj_ticker = dap_json_object_new_string(it->ticker);
                    const char *l_description =  dap_ledger_get_description_by_ticker(l_ledger, it->ticker);
                    dap_json_t *l_jobj_description = l_description ? dap_json_object_new_string(l_description)
                                                                    : dap_json_object_new();
                    dap_json_object_add_object(l_jobj_token, "ticker", l_jobj_ticker);
                    dap_json_object_add_object(l_jobj_token, "description", l_jobj_description);
                    dap_json_t *j_balance_data = dap_json_object_new();
                    const char *l_balance_coins, *l_balance_datoshi = dap_uint256_to_char(it->value, &l_balance_coins);
                    dap_json_object_add_string(j_balance_data, "coins", l_balance_coins);
                    dap_json_object_add_string(j_balance_data, "datoshi", l_balance_datoshi);
                    dap_json_object_add_object(j_balance_data, "token", l_jobj_token);
                    char ts[DAP_TIME_STR_SIZE];
                    dap_time_to_str_rfc822(ts, DAP_TIME_STR_SIZE, it->unlock_time);
                    dap_json_object_add_string(j_balance_data, "locked_until", ts);
                    dap_json_array_add(j_arr_locked_balance, j_balance_data);
                    LL_DELETE(l_locked_outs, it);
                    DAP_DELETE(it);
                }
                dap_json_object_add_object(json_obj_wall, "locked_outs", j_arr_locked_balance);
            } else if (!l_addr_tokens_size)
                dap_json_object_add_string(json_obj_wall, "balance", "0");

            // add shared wallet tx hashes
            dap_json_t *l_tx_hashes = dap_chain_wallet_shared_get_tx_hashes_json(&l_addr->data.hash_fast, l_net->pub.name);
            if (l_tx_hashes) {
                dap_json_object_add_object(json_obj_wall, "wallet_shared_tx_hashes", l_tx_hashes);
            }

            dap_json_array_add(json_arr_out, json_obj_wall);
            DAP_DELETE(l_addr);
            if(l_wallet)
                dap_chain_wallet_close(l_wallet);
            break;
        }
        case CMD_WALLET_OUTPUTS: {
            if ((l_wallet_name && l_addr_str) || (!l_wallet_name && !l_addr_str)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
                "You should use either the -w or -addr option for the wallet info command.");
                dap_json_object_free(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
            }
            if(l_wallet_name) {
                if(!l_net) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                            "Subcommand info requires parameter '-net'");
                    dap_json_object_free(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
                l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
                if (!l_wallet){
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                           "Can't find wallet (%s)", l_wallet_name);
                    dap_json_object_free(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
                l_addr = (dap_chain_addr_t *) dap_chain_wallet_get_addr(l_wallet, l_net->pub.id );
                if (!l_addr){
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                           "Can't get addr from wallet (%s)", l_wallet_name);
                    dap_json_object_free(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
            } else {
                l_addr = dap_chain_addr_from_str(l_addr_str);
                if (!l_net)
                    l_net = dap_chain_net_by_id(l_addr->net_id);
                
                if(!l_net) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR,
                                            "Can't get net from wallet addr");
                    dap_json_object_free(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NET_PARAM_ERR;
                }
            }

            const char* l_token_tiker = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_tiker);
            if (!l_token_tiker){
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
                                           "Subcommand outputs requires parameter '-token'");
                    dap_json_object_free(json_arr_out);
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR;
            }
            dap_json_t *json_obj_wall = dap_json_object_new();
            const char *l_value_str = NULL, *l_cond_type_str = NULL;
            uint256_t l_value_datoshi = uint256_0, l_value_sum = uint256_0;
            dap_chain_tx_out_cond_subtype_t l_cond_type = DAP_CHAIN_TX_OUT_COND_SUBTYPE_ALL;
            bool l_cond_outs = dap_cli_server_cmd_check_option(a_argv, l_arg_index, a_argc, "-cond") != -1;
            if (!l_cond_outs) {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
                if (l_value_str) {
                    l_value_datoshi = dap_chain_balance_scan(l_value_str);
                    if (IS_ZERO_256(l_value_datoshi)) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
                                                   "Can't convert -value param to 256bit integer");
                            dap_json_object_free(json_arr_out);
                            return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR;
                    }
                }
            } else {
                dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-type", &l_cond_type_str);
                if (l_cond_type_str) {
                    l_cond_type = dap_chain_tx_out_cond_subtype_from_str_short(l_cond_type_str);
                    if (l_cond_type == DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR,
                                               "Invalid conditional output type '%s'. Available types: srv_pay, srv_xchange, srv_stake_pos_delegate, srv_stake_lock, fee", 
                                                l_cond_type_str);
                        dap_json_object_free(json_arr_out);
                        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PARAM_ERR;
                    }
                }
            }

            dap_list_t *l_outs_list = NULL;
            bool l_check_mempool = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-mempool_check", NULL);
            if (l_cond_outs)
                l_outs_list = dap_ledger_get_list_tx_cond_outs(l_net->pub.ledger, l_cond_type, l_token_tiker, l_addr);
            else if (l_value_str) {
                l_outs_list = dap_chain_wallet_get_list_tx_outs_with_val_mempool_check(l_net->pub.ledger, l_token_tiker, l_addr, l_value_datoshi, &l_value_sum, l_check_mempool); 
            } else {
                l_outs_list = dap_chain_wallet_get_list_tx_outs_mempool_check(l_net->pub.ledger, l_token_tiker, l_addr, &l_value_sum, l_check_mempool);
            }
            dap_json_object_add_string(json_obj_wall, "wallet_addr", dap_chain_addr_to_str_static(l_addr));
            dap_json_t *l_json_outs_arr = dap_json_array_new();
            if (!l_json_outs_arr)
                return dap_json_object_free(json_arr_out), DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR;
            for (dap_list_t *l_temp = l_outs_list; l_temp; l_temp = l_temp->next) {
                dap_json_t *json_obj_item = dap_json_object_new();
                if (!json_obj_item)
                    return dap_json_object_free(json_arr_out), DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR;
                dap_chain_tx_used_out_item_t *l_item = l_temp->data;
                const char *l_out_value_coins_str, *l_out_value_str = dap_uint256_to_char(l_item->value, &l_out_value_coins_str);
                dap_json_object_add_object(json_obj_item,"item_type", dap_json_object_new_string(l_cond_outs ? "unspent_cond_out" : "unspent_out"));
                dap_json_object_add_object(json_obj_item,"value_coins", dap_json_object_new_string(l_out_value_coins_str));
                dap_json_object_add_object(json_obj_item,a_version == 1 ? "value_datosi" : "value_datoshi", dap_json_object_new_string(l_out_value_str));
                dap_json_object_add_object(json_obj_item,"prev_hash", dap_json_object_new_string(dap_hash_fast_to_str_static(&l_item->tx_hash_fast)));
                dap_json_object_add_int64(json_obj_item,"out_prev_idx", l_item->num_idx_out);
                dap_json_array_add(l_json_outs_arr, json_obj_item);
                if (l_cond_outs)
                    SUM_256_256(l_value_sum, l_item->value, &l_value_sum);
            }
            dap_list_free_full(l_outs_list, NULL);
            const char * l_out_total_value_coins_str, *l_out_total_value_str = dap_uint256_to_char(l_value_sum, &l_out_total_value_coins_str);
            dap_json_object_add_string(json_obj_wall, "total_value_coins", l_out_total_value_coins_str);
            dap_json_object_add_string(json_obj_wall, "total_value_datoshi", l_out_total_value_str);
            dap_json_object_add_object(json_obj_wall, "outs", l_json_outs_arr);
            dap_json_array_add(json_arr_out, json_obj_wall);
        } break;

        case CMD_WALLET_FIND: {
            if (l_addr_str) {
                l_addr = dap_chain_addr_from_str(l_addr_str);
                if (l_addr) {
                    if (l_file_path)
                        s_wallet_list(l_file_path, json_arr_out, l_addr, a_version);
                    else 
                        s_wallet_list(c_wallets_path, json_arr_out, l_addr, a_version);
                }                    
                else {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR,
                        "addr not recognized");
                    return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR;
                }
            } else {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR,
                                                "You should use -addr option for the wallet find command.");
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ADDR_ERR;
            }           
        } break;
        case CMD_WALLET_SHARED:
            return dap_chain_wallet_shared_cli(a_argc, a_argv, a_json_arr_reply, a_version);
        default: {
            if( !l_wallet_name ) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR,
                                       "Wallet name option <-w>  not defined");
                dap_json_object_free(json_arr_out);
                return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_NAME_ERR;
            }
            if( cmd_num != CMD_WALLET_DEACTIVATE && !l_pass_str && cmd_num != CMD_WALLET_NEW && cmd_num != CMD_WALLET_CONVERT ) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                       "Wallet password option <-password>  not defined");
                dap_json_object_free(json_arr_out);
                return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR;
            }
            if ( cmd_num != CMD_WALLET_DEACTIVATE && l_pass_str && DAP_WALLET$SZ_PASS < strnlen(l_pass_str, DAP_WALLET$SZ_PASS + 1) ) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_TO_LONG_ERR,
                                       "Wallet's password is too long ( > %d)", DAP_WALLET$SZ_PASS);
                log_it(L_ERROR, "Wallet's password is too long ( > %d)", DAP_WALLET$SZ_PASS);
                dap_json_object_free(json_arr_out);
                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_TO_LONG_ERR;
            }
            switch (cmd_num) {
                case CMD_WALLET_ACTIVATE:
                case CMD_WALLET_DEACTIVATE: {
                    dap_json_t *json_obj_wall = dap_json_object_new();
                    const char *l_prefix = cmd_num == CMD_WALLET_ACTIVATE ? "" : "de";
                    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-ttl", &l_ttl_str);
                    l_rc = l_ttl_str ? strtoul(l_ttl_str, NULL, 10) : 60;

                    l_rc = cmd_num == CMD_WALLET_ACTIVATE
                            ? dap_chain_wallet_activate(l_wallet_name, strlen(l_wallet_name), NULL, l_pass_str, strlen(l_pass_str), l_rc)
                            : dap_chain_wallet_deactivate (l_wallet_name, strlen(l_wallet_name));

                    switch (l_rc) {
                    case 0:
                        dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Wallet name" : "wallet_name", l_wallet_name);
                        dap_json_object_add_object(json_obj_wall, "protection", cmd_num == CMD_WALLET_ACTIVATE ?
                        dap_json_object_new_string("is activated") : dap_json_object_new_string("is deactivated"));
                        // Notify about wallet
                        s_new_wallet_info_notify(l_wallet_name);
                        dap_json_t *l_json_wallets = wallet_list_json_collect(a_version);
                        char *l_json_str = dap_json_to_string(l_json_wallets);
                        dap_notify_server_send(l_json_str);
                        DAP_DELETE(l_json_str);
                        dap_json_object_free(l_json_wallets);
                        break;
                    case -EBUSY:
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR,
                                               "Error: wallet %s is already %sactivated\n", l_wallet_name, l_prefix);
                        break;
                    case -EAGAIN:
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                "Wrong password for wallet %s\n", l_wallet_name);
                        break;
                    case -101:
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                "Can't active unprotected wallet: %s\n", l_wallet_name);
                        break;
                    default:
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ACTIVE_ERR,
                                "Wallet %s %sactivation error %d : %s\n", l_wallet_name, l_prefix, l_rc, dap_strerror(l_rc));
                        break;
                    }
                    dap_json_array_add(json_arr_out, json_obj_wall);
                } break;
                // convert wallet
                case CMD_WALLET_CONVERT: {
                    bool l_remove_password = false;
                    if(dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-remove_password", NULL))
                        l_remove_password = true;
                    l_wallet = dap_chain_wallet_open(l_wallet_name, c_wallets_path, NULL);
                    if (!l_wallet) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                               "Can't open wallet");
                        dap_json_object_free(json_arr_out);
                        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR;
                    } else if (l_wallet->flags & DAP_WALLET$M_FL_ACTIVE && !l_remove_password) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR,
                                               "Wallet can't be converted twice");
                        dap_json_object_free(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR;
                    }
                    if (l_pass_str && !dap_check_valid_password(l_pass_str, dap_strlen(l_pass_str))) {
                        dap_json_rpc_error_add(a_json_arr_reply,
                                               DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD,
                                               "Invalid characters used for password.");
                        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD;
                    }
                    // create wallet backup 
                    dap_chain_wallet_internal_t* l_file_name = DAP_CHAIN_WALLET_INTERNAL(l_wallet);
                    snprintf(l_file_name->file_name, sizeof(l_file_name->file_name), "%s/%s_%012lu%s", c_wallets_path, l_wallet_name, time(NULL),".backup");
                    if ( dap_chain_wallet_save(l_wallet, NULL) ) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR,
                                               "Can't create backup wallet file because of internal error");
                        dap_json_object_free(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR;
                    }
                    if (l_remove_password) {  
                        if (dap_chain_wallet_deactivate(l_wallet_name, strlen(l_wallet_name))){
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_BACKUP_ERR,
                                                "Can't deactivate wallet");
                            dap_json_object_free(json_arr_out);
                            return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_DEACT_ERR;
                        }
                    } else if (!l_pass_str) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR,
                                       "Wallet password option <-password>  not defined");
                        dap_json_object_free(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PASS_ERR;
                    }
                    // change to old filename
                    snprintf(l_file_name->file_name, sizeof(l_file_name->file_name), "%s/%s%s", c_wallets_path, l_wallet_name, ".dwallet");
                    if ( dap_chain_wallet_save(l_wallet, l_remove_password ? NULL : l_pass_str) ) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR,
                                               "Wallet is not converted because of internal error");
                        dap_json_object_free(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_CONVERT_ERR;
                    }
                    dap_json_t *json_obj_wall = dap_json_object_new();
                    log_it(L_INFO, "Wallet %s has been converted", l_wallet_name);
                    dap_json_object_add_object(json_obj_wall, a_version == 1 ? "Sign wallet" : "sig_wallet", dap_json_object_new_string(
                                                                              strlen(dap_chain_wallet_check_sign(l_wallet))!=0 ?
                                                                              dap_chain_wallet_check_sign(l_wallet) : "correct"));
                    dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Wallet name" : "wallet_name", l_wallet_name);
                    dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Status" : "status",  a_version == 1 ? "successfully converted" : "success");
                    dap_chain_wallet_close(l_wallet);
                    dap_json_array_add(json_arr_out, json_obj_wall);
                    break;
                }
                // NOTE: CMD_WALLET_NEW case is VERY long (~250 lines) - continued in next section
                case CMD_WALLET_NEW: {
                    int l_restore_opt = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-restore", &l_restore_str);
                    int l_restore_legacy_opt = 0;
                    if (!l_restore_str)
                        l_restore_legacy_opt = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-restore_legacy", &l_restore_str);
                    // rewrite existing wallet
                    int l_is_force = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-force", NULL);

                    // check wallet existence
                    if (!l_is_force) {
                        char *l_file_name = dap_strdup_printf("%s/%s.dwallet", c_wallets_path, l_wallet_name);
                        FILE *l_exists = fopen(l_file_name, "rb");
                        DAP_DELETE(l_file_name);
                        if (l_exists) {
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR,"Wallet %s already exists",l_wallet_name);
                            fclose(l_exists);
                            dap_json_object_free(json_arr_out);
                            return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_ALREADY_ERR;
                        }
                    }

                    dap_sign_type_t l_sign_types[MAX_ENC_KEYS_IN_MULTYSIGN] = {};
                    size_t l_sign_count = 0;
                    if (!l_sign_type_str) {
                        l_sign_types[0].type = SIG_TYPE_DILITHIUM;
                        l_sign_type_str = dap_sign_type_to_str(l_sign_types[0]);
                        l_sign_count = 1;
                    } else {
                        l_sign_types[0] = dap_sign_type_from_str(l_sign_type_str);
                        if (l_sign_types[0].type == SIG_TYPE_NULL){
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                   "'%s' unknown signature type, please use:\n%s",
                                                   l_sign_type_str, dap_sign_get_str_recommended_types());
                            dap_json_object_free(json_arr_out);
                            return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR;
                        }
                        if (l_sign_types[0].type == SIG_TYPE_MULTI_CHAINED) {
                            int l_sign_index = dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, l_sign_type_str, NULL);
                            l_sign_index++;
                            for (;l_sign_index && l_sign_index < a_argc; ++l_sign_index) {
                                l_sign_types[l_sign_count] = dap_sign_type_from_str(a_argv[l_sign_index]);
                                if (l_sign_types[l_sign_count].type == SIG_TYPE_NULL ||
                                    l_sign_types[l_sign_count].type == SIG_TYPE_MULTI_CHAINED) {
                                    break;
                                }
                                l_sign_count++;
                            }
                            if (l_sign_count < 2) {
                                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                      "You did not specify an additional signature after "
                                                      "sig_multi_chained. You must specify at least two more "
                                                      "signatures other than sig_multi_chained.\n"
                                                      "After sig_multi_chained, you must specify two more signatures "
                                                      "from the list:\n%s", dap_cert_get_str_recommended_sign());
                                dap_json_object_free(json_arr_out);
                                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR;
                            }
                        } else {
                            l_sign_count = 1;
                        }
                    }
                    // Check unsupported tesla and bliss algorithm

                    for (size_t i = 0; i < l_sign_count; ++i) {
                        if (dap_sign_type_is_deprecated(l_sign_types[i])) {
                            if (l_restore_opt || l_restore_legacy_opt) {
                                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                   "CAUTION!!! CAUTION!!! CAUTION!!!\nThe Bliss, Tesla and Picnic signatures are deprecated. We recommend you to create a new wallet with another available signature and transfer funds there.\n");
                                break;
                            } else {
                                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR,
                                                   "This signature algorithm is no longer supported, please, use another variant");
                                dap_json_object_free(json_arr_out);
                                return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_UNKNOWN_SIGN_ERR;
                            }
                        }
                    }

                    uint8_t *l_seed = NULL;
                    size_t l_seed_size = 0, l_restore_str_size = dap_strlen(l_restore_str);

                    if(l_restore_opt || l_restore_legacy_opt) {
                        if (l_restore_str_size > 3 && !dap_strncmp(l_restore_str, "0x", 2) && (!dap_is_hex_string(l_restore_str + 2, l_restore_str_size - 2) || l_restore_legacy_opt)) {
                            l_seed_size = (l_restore_str_size - 2) / 2;
                            l_seed = DAP_NEW_Z_SIZE(uint8_t, l_seed_size + 1);
                            if(!l_seed) {
                                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                                dap_json_object_free(json_arr_out);
                                return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_MEMORY_ERR;
                            }
                            dap_hex2bin(l_seed, l_restore_str + 2, l_restore_str_size - 2);
                            if (l_restore_legacy_opt) {
                                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_PROTECTION_ERR,
                                                       "CAUTION!!! CAUTION!!! CAUTION!!!\nYour wallet has a low level of protection. Please create a new wallet again with the option -restore\n");
                            }
                        } else {
                            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_HASH_ERR,
                                                   "Restored hash is invalid or too short, wallet is not created. Please use -restore 0x<hex_value> or -restore_legacy 0x<restore_string>");
                            dap_json_object_free(json_arr_out);
                            return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_HASH_ERR;
                        }
                    }
                    // Checking that if a password is set, it contains only Latin characters, numbers and special characters, except for spaces.
                    if (l_pass_str && !dap_check_valid_password(l_pass_str, dap_strlen(l_pass_str))) {
                        dap_json_rpc_error_add(a_json_arr_reply,
                                               DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD,
                                               "Invalid characters used for password.");
                        return DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INVALID_CHARACTERS_USED_FOR_PASSWORD;
                    }

                    // Creates new wallet
                    l_wallet = dap_chain_wallet_create_with_seed_multi(l_wallet_name, c_wallets_path, l_sign_types, l_sign_count,
                            l_seed, l_seed_size, l_pass_str);
                    DAP_DELETE(l_seed);
                    if (!l_wallet) {
                        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INTERNAL_ERR,
                                               "Wallet is not created because of internal error. Check name or password length (max 64 chars)");
                        dap_json_object_free(json_arr_out);
                        return  DAP_CHAIN_NODE_CLI_COM_TX_WALLET_INTERNAL_ERR;
                    }

                    dap_json_t *json_obj_wall = dap_json_object_new();
                    dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Wallet name" : "wallet_name", l_wallet->name);
                    if (l_sign_count > 1) {
                        dap_string_t *l_signs_types_str = dap_string_new("sig_multi_chained, ");
                        for (size_t i = 0; i < l_sign_count; i++) {
                            dap_string_append_printf(l_signs_types_str, "%s%s",
                                                     dap_sign_type_to_str(l_sign_types[i]), (i+1) == l_sign_count ? "": ", ");
                        }
                        dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Sign type" : "sig_type", l_signs_types_str->str);
                        dap_string_free(l_signs_types_str, true);
                    } else
                        dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Sign type" : "sig_type", l_sign_type_str);
                    dap_json_object_add_string(json_obj_wall, a_version == 1 ? "Status" : "status", a_version == 1 ? "successfully created" : "success");

                    const char *l_addr_str = NULL;
                    if ( l_net && (l_addr_str = dap_chain_addr_to_str_static(dap_chain_wallet_get_addr(l_wallet,l_net->pub.id))) ) {
                        dap_json_object_add_object(json_obj_wall, a_version == 1 ? "new address" : "new_addr", dap_json_object_new_string(l_addr_str) );
                    }
                    dap_json_array_add(json_arr_out, json_obj_wall);
                    dap_chain_wallet_close(l_wallet);
                    // Notify about wallet
                    s_new_wallet_info_notify(l_wallet_name);
                    dap_json_t *l_json_wallets = wallet_list_json_collect(a_version);
                    char *l_json_str = dap_json_to_string(l_json_wallets);
                    dap_notify_server_send(l_json_str);
                    DAP_DELETE(l_json_str);
                    dap_json_object_free(l_json_wallets);
                    break;
                }
            }
        }
    }

    if (json_arr_out) {
            dap_json_array_add(a_json_arr_reply, json_arr_out);
        } else {
            dap_json_array_add(a_json_arr_reply, dap_json_object_new_string("empty"));
        }
    return 0;
}
