/*
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2019-2025
 * All rights reserved.
 *
 * This file is part of DAP (Distributed Applications Platform) the open source project
 *
 * DAP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * DAP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#include "uthash.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_enc_base58.h"
#include "dap_json.h"
#include "dap_json_rpc_errors.h"

#include "dap_cli_server.h"
#include "dap_cli_error_codes.h"

#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_mempool.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_cert.h"

#include "dap_chain_ledger_cli_ledger.h"
#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_chain_ledger_cli_compat.h"

#define LOG_TAG "ledger_cli_ledger"

// Forward declarations for functions from net/tx module (higher-level)
extern void dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, dap_json_t *a_json);
extern char* dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type);

static int s_print_for_ledger_list(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt);

/**
 * @brief Helper structure for tracking processed TX hashes
 */
typedef struct dap_chain_tx_hash_processed_ht {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
} dap_chain_tx_hash_processed_ht_t;

/**
 * @brief Output transaction data to JSON
 */
static bool s_dap_chain_datum_tx_out_data(dap_json_t *a_json_arr_reply,
                                          dap_chain_datum_tx_t *a_datum,
                                          dap_ledger_t *a_ledger,
                                          dap_json_t *json_obj_out,
                                          const char *a_hash_out_type,
                                          dap_chain_hash_fast_t *a_tx_hash,
                                          int a_version)
{
    char l_tx_hash_str[70] = {0};
    char l_tmp_buf[DAP_TIME_STR_SIZE];
    const char *l_ticker = a_ledger
            ? dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash)
            : NULL;
    if (!l_ticker)
        return false;
    const char *l_description = dap_ledger_get_description_by_ticker(a_ledger, l_ticker);
    dap_time_to_str_rfc822(l_tmp_buf, DAP_TIME_STR_SIZE, a_datum->header.ts_created);
    dap_chain_hash_fast_to_str(a_tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));
    dap_json_object_add_string(json_obj_out, a_version == 1 ? "Datum_tx_hash" : "datum_tx_hash", l_tx_hash_str);
    dap_json_object_add_string(json_obj_out, a_version == 1 ? "TS_Created" : "ts_created", l_tmp_buf);
    dap_json_object_add_string(json_obj_out, a_version == 1 ? "Token_ticker" : "token_ticker", l_ticker);
    dap_json_object_add_object(json_obj_out, a_version == 1 ? "Token_description" : "token_description", 
                               l_description ? dap_json_object_new_string(l_description) : dap_json_object_new());
    
    // Use ledger's net_id directly - ledger already knows its network
    dap_chain_datum_dump_tx_json(a_json_arr_reply, a_datum, l_ticker, json_obj_out, a_hash_out_type, a_tx_hash, a_ledger->net_id, a_version);
    
    dap_json_t *json_arr_items = dap_json_array_new();
    bool l_spent = false;
    byte_t *l_item; size_t l_size; int i, l_out_idx = -1;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, i, a_datum) {
        ++l_out_idx;
        dap_hash_fast_t l_spender = { };
        dap_json_t *l_json_obj_out = NULL, *l_json_arr_colours = NULL;
        if (dap_ledger_tx_hash_is_used_out_item(a_ledger, a_tx_hash, l_out_idx, &l_spender)) {
            char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
            dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
            l_json_obj_out = dap_json_object_new();
            dap_json_object_add_int(l_json_obj_out, a_version == 1 ? "OUT - " : "out", l_out_idx);
            dap_json_object_add_string(l_json_obj_out, a_version == 1 ? "is spent by tx" : "spent_by_tx", l_hash_str);
            l_spent = true;
        }
        dap_list_t *l_trackers = dap_ledger_tx_get_trackers(a_ledger, a_tx_hash, l_out_idx);
        if (l_trackers) {
            if (!l_json_obj_out) {
                l_json_obj_out = dap_json_object_new();
                dap_json_object_add_int(l_json_obj_out, "out_number", l_out_idx);
            }
            l_json_arr_colours = dap_json_array_new();
            dap_json_object_add_object(l_json_obj_out, "trackers", l_json_arr_colours);
        }
        for (dap_list_t *it = l_trackers; it; it = it->next) {
            dap_ledger_tracker_t *l_tracker = it->data;
            dap_json_t *l_json_obj_tracker = dap_json_object_new();
            dap_json_array_add(l_json_arr_colours, l_json_obj_tracker);
            const char *l_voling_hash_str = dap_hash_fast_to_str_static(&l_tracker->voting_hash);
            dap_json_object_add_string(l_json_obj_tracker, "voting_hash", l_voling_hash_str);
            dap_json_t *l_json_arr_tracker_items = dap_json_array_new();
            dap_json_object_add_object(l_json_obj_tracker, "items", l_json_arr_tracker_items);
        }
        dap_list_free(l_trackers);
        if (l_json_obj_out)
            dap_json_array_add(json_arr_items, l_json_obj_out);
    }
    if (l_spent || dap_json_array_length(json_arr_items) > 0) {
        dap_json_object_add_object(json_obj_out, a_version == 1 ? "spent_or_coloured_outs" : "spent_or_coloured_outs", json_arr_items);
    } else {
        dap_json_object_free(json_arr_items);
    }
    return true;
}

/**
 * @brief Recursive trace function for building TX chain
 */
static bool s_ledger_trace_recursive(dap_ledger_t *a_ledger, 
                                    dap_chain_hash_fast_t *a_current_hash,
                                    dap_chain_hash_fast_t *a_target_hash,
                                    size_t a_path_depth,
                                    size_t a_max_depth,
                                    dap_json_t *a_json_chain,
                                    const char *a_hash_out_type)
{
    static size_t l_target_depth = 0;
    // Check depth limit
    if (a_path_depth >= a_max_depth) {
        return false;
    }

    // Check if we found the target
    if (dap_hash_fast_compare(a_current_hash, a_target_hash)) {
        // Found target! Add it to chain
        dap_json_t *l_json_tx = dap_json_object_new();
        
        if (dap_strcmp(a_hash_out_type, "base58") == 0) {
            const char *l_hash_base58 = dap_enc_base58_encode_hash_to_str_static(a_current_hash);
            dap_json_object_add_string(l_json_tx, "hash", l_hash_base58 ? l_hash_base58 : "");
        } else {
            const char *l_hash_hex = dap_chain_hash_fast_to_str_static(a_current_hash);
            dap_json_object_add_string(l_json_tx, "hash", l_hash_hex);
        }
        // Add previous output index information
        dap_json_object_add_string(l_json_tx, "prev_out_idx", "unavailable");
        l_target_depth = a_path_depth;
        dap_json_object_add_int(l_json_tx, "position", 1);
        dap_json_object_add_string(l_json_tx, "type", "start");
               
        dap_json_array_add(a_json_chain, l_json_tx);
        
        return true;
    }
        
    // Get current transaction
    dap_chain_datum_tx_t *l_current_tx = dap_ledger_tx_find_by_hash(a_ledger, a_current_hash);
    if (!l_current_tx) {
        return false;
    }
           
    // Try each input until we find a path to target
    byte_t *l_item = NULL;
    size_t l_item_size = 0;
    int l_item_index = 0;
    TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_IN_ALL, l_item_size, l_item_index, l_current_tx) {

        dap_chain_hash_fast_t *l_tx_prev_hash = NULL;
        int l_tx_out_prev_idx = -1;
        
        switch (*l_item) {
            case TX_ITEM_TYPE_IN: {
                dap_chain_tx_in_t *l_tx_in = (dap_chain_tx_in_t *)l_item;
                l_tx_prev_hash = &l_tx_in->header.tx_prev_hash;
                l_tx_out_prev_idx = l_tx_in->header.tx_out_prev_idx;
            } break;
            case TX_ITEM_TYPE_IN_COND: {
                dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t *)l_item;
                l_tx_prev_hash = &l_tx_in_cond->header.tx_prev_hash;
                l_tx_out_prev_idx = l_tx_in_cond->header.tx_out_prev_idx;
            } break;
            default:
                continue;
        }
        
        // Recursively search this branch
        bool l_found_in_branch = s_ledger_trace_recursive(a_ledger, l_tx_prev_hash, a_target_hash,
                                                            a_path_depth + 1, a_max_depth,
                                                            a_json_chain, a_hash_out_type);
        if (l_found_in_branch) {
            // Add current transaction to chain
            dap_json_t *l_json_tx = dap_json_object_new();
            if (dap_strcmp(a_hash_out_type, "base58") == 0) {
                const char *l_hash_base58 = dap_enc_base58_encode_hash_to_str_static(a_current_hash);
                dap_json_object_add_string(l_json_tx, "hash", l_hash_base58 ? l_hash_base58 : "");
            } else {
                const char *l_hash_hex = dap_chain_hash_fast_to_str_static(a_current_hash);
                dap_json_object_add_string(l_json_tx, "hash", l_hash_hex);
            }
            // Add previous output index information
            dap_json_object_add_int(l_json_tx, "prev_out_idx", l_tx_out_prev_idx);
            dap_json_object_add_int(l_json_tx, "position", l_target_depth - a_path_depth + 1);
            if (a_path_depth == 0)
                dap_json_object_add_string(l_json_tx, "type", "target");
            else
                dap_json_object_add_string(l_json_tx, "type", "intermediate");
            
            // Found target in this branch - add current tx to chain and return success
            dap_json_array_add(a_json_chain, l_json_tx);
            return true;
        }
    }
    
    return false;
}

/**
 * @brief Build transaction chain from a_hash_to to a_hash_from using simplified recursive traversal
 */
static int s_ledger_trace_chain(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_hash_from, dap_chain_hash_fast_t *a_hash_to, 
                               const char *a_hash_out_type, size_t a_max_depth, dap_json_t *a_json_arr_reply)
{
    // Validate input parameters
    if (!a_ledger || !a_hash_from || !a_hash_to || !a_json_arr_reply) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Invalid input parameters");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    // Check if starting transaction exists
    dap_chain_datum_tx_t *l_start_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash_to);
    if (!l_start_tx) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), 
                              "Starting transaction %s not found in ledger", dap_hash_fast_to_str_static(a_hash_to));
        return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
    }

    // Check if target transaction exists
    dap_chain_datum_tx_t *l_target_tx = dap_ledger_tx_find_by_hash(a_ledger, a_hash_from);
    if (!l_target_tx) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), 
                              "Target transaction %s not found in ledger", dap_hash_fast_to_str_static(a_hash_from));
        return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
    }

    // Create result JSON object
    dap_json_t *l_json_result = dap_json_object_new();
    dap_json_t *l_json_info = dap_json_object_new();
    dap_json_t *l_json_chain = dap_json_array_new();

    // Add info about the trace
    dap_json_object_add_string(l_json_info, "start_hash", dap_hash_fast_to_str_static(a_hash_from));
    dap_json_object_add_string(l_json_info, "target_hash", dap_hash_fast_to_str_static(a_hash_to));
    dap_json_object_add_string(l_json_info, "direction", "backward");
    dap_json_object_add_int(l_json_info, "max_depth", a_max_depth);
    dap_json_object_add_object(l_json_result, "trace_info", l_json_info);

    // Start recursive search
    bool l_found = s_ledger_trace_recursive(a_ledger, a_hash_to, a_hash_from,
                                           0, a_max_depth,
                                           l_json_chain, a_hash_out_type);

    // Add results to main JSON
    dap_json_object_add_object(l_json_result, "chain", l_json_chain);
    dap_json_object_add_int(l_json_result, "chain_length", dap_json_array_length(l_json_chain));
    dap_json_object_add_object(l_json_result, "target_found", dap_json_object_new_bool(l_found));
    
    if (!l_found) {
        dap_json_object_add_object(l_json_result, "status", 
                              dap_json_object_new_string("No path found from start to target transaction"));
    } else {
        dap_json_object_add_object(l_json_result, "status", 
                              dap_json_object_new_string("Path found from start to target transaction"));
    }

    dap_json_array_add(a_json_arr_reply, l_json_result);
    return 0;
}

/**
 * @brief com_ledger
 * ledger command
 * @param a_argc
 * @param a_argv
 * @param a_json_arr_reply
 * @param a_version
 * @return int
 */
int com_ledger(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    enum { CMD_NONE, CMD_LIST, CMD_TX_INFO, CMD_TRACE, CMD_EVENT };
    int arg_index = 1;
    const char *l_net_str = NULL;
    const char *l_target_chain_str = NULL;
    const char *l_tx_hash_str = NULL;
    const char *l_hash_out_type = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    if (dap_strcmp(l_hash_out_type, "hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                              "invalid parameter -H, valid values: -H <hex | base58>");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }

    // Switch ledger params list | info | trace | event
    int l_cmd = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "list", NULL)) {
        l_cmd = CMD_LIST;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "info", NULL)) {
        l_cmd = CMD_TX_INFO;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "trace", NULL)) {
        l_cmd = CMD_TRACE;
    } else if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, arg_index + 1, "event", NULL)) {
        l_cmd = CMD_EVENT;
    }

    arg_index++;

    if (l_cmd == CMD_EVENT) {
        enum { SUBCMD_NONE, SUBCMD_LIST, SUBCMD_DUMP, SUBCMD_KEY, SUBCMD_CREATE };
        int l_subcmd = SUBCMD_NONE;
        
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "list", NULL)) {
            l_subcmd = SUBCMD_LIST;
        } else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "dump", NULL)) {
            l_subcmd = SUBCMD_DUMP;
        } else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "key", NULL)) {
            l_subcmd = SUBCMD_KEY;
        } else if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "create", NULL)) {
            l_subcmd = SUBCMD_CREATE;
        }
        
        if (l_subcmd == SUBCMD_NONE) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Subcommand 'event' requires subcommand 'list', 'dump', 'create' or 'key'");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        if (l_subcmd == SUBCMD_CREATE) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            // Get ledger by net name
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (!l_ledger) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_FIND_ERR"), "Can't find net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_NET_FIND_ERR");
            }
            
            // TODO: Migrate to new TX Compose API
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Event TX creation temporarily disabled - migration to TX Compose API in progress");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        if (l_subcmd == SUBCMD_KEY) {
            enum { KEY_SUBCMD_NONE, KEY_SUBCMD_ADD, KEY_SUBCMD_REMOVE, KEY_SUBCMD_LIST };
            int l_key_subcmd = KEY_SUBCMD_NONE;
            
            if (dap_cli_server_cmd_find_option_val(a_argv, 3, 4, "add", NULL)) {
                l_key_subcmd = KEY_SUBCMD_ADD;
            } else if (dap_cli_server_cmd_find_option_val(a_argv, 3, 4, "remove", NULL)) {
                l_key_subcmd = KEY_SUBCMD_REMOVE;
            } else if (dap_cli_server_cmd_find_option_val(a_argv, 3, 4, "list", NULL)) {
                l_key_subcmd = KEY_SUBCMD_LIST;
            }
            
            if (l_key_subcmd == KEY_SUBCMD_NONE) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                      "Command 'event key' requires subcommand 'add', 'remove' or 'list'");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            if (l_key_subcmd == KEY_SUBCMD_LIST) {
                dap_json_t *l_json_obj_out = dap_json_object_new();
                dap_json_t *l_json_array_keys = dap_json_array_new();
                
                dap_list_t *l_list = dap_ledger_event_pkey_list(l_ledger);
                if (l_list) {
                    for (dap_list_t *l_item = l_list; l_item; l_item = l_item->next) {
                        dap_hash_fast_t *l_hash = (dap_hash_fast_t *)l_item->data;
                        const char *l_hash_str = dap_strcmp(l_hash_out_type, "hex") 
                                           ? dap_enc_base58_encode_hash_to_str_static(l_hash)
                                           : dap_chain_hash_fast_to_str_static(l_hash);
                        dap_json_array_add(l_json_array_keys, dap_json_object_new_string(l_hash_str));
                    }
                    
                    // Free the list and its elements
                    dap_list_free_full(l_list, free);
                }
                
                dap_json_object_add_object(l_json_obj_out, "keys", l_json_array_keys);
                dap_json_array_add(a_json_arr_reply, l_json_obj_out);
                return 0;
            } else { // ADD or REMOVE key
                const char *l_pkey_hash_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_pkey_hash_str);
                if (!l_pkey_hash_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                          "Command requires parameter -hash for key hash");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }
                
                dap_hash_fast_t l_pkey_hash = {};
                if (dap_chain_hash_fast_from_str(l_pkey_hash_str, &l_pkey_hash)) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR, 
                                          "Invalid hash string format");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR;
                }
                
                // Get certs for signing the decree
                const char *l_certs_str = NULL;
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-certs", &l_certs_str);
                if (!l_certs_str) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                        "Parameter -certs is required to sign the decree");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }

                // Get certificates for signing
                char **l_certs_array = NULL;
                uint16_t l_certs_count = 0;
                dap_cert_t **l_certs = NULL;
                if (l_certs_str && strlen(l_certs_str) > 0) {
                    l_certs_array = dap_strsplit(l_certs_str, ",", -1);
                    if (!l_certs_array) {
                        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                            "Can't parse certs");
                        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                    }
                    for (l_certs_count = 0; l_certs_array[l_certs_count]; l_certs_count++);
                    l_certs = DAP_NEW_SIZE(dap_cert_t*, sizeof(dap_cert_t*) * l_certs_count);
                    for (uint16_t i = 0; i < l_certs_count; i++) {
                        l_certs[i] = dap_cert_find_by_name(l_certs_array[i]);
                        if (!l_certs[i]) {
                            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"),
                                                "Can't find cert \"%s\"", l_certs_array[i]);
                            DAP_DELETE(l_certs);
                            dap_strfreev(l_certs_array);
                            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                        }
                    }
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                            "Parameter -certs is required");
                    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
                }

                // Get decree chain from ledger's chain registry
                dap_chain_t *l_chain = NULL;
                dap_chain_info_t *l_chain_info, *l_tmp;
                HASH_ITER(hh, l_ledger->chains_registry, l_chain_info, l_tmp) {
                    if (l_chain_info->chain_type == CHAIN_TYPE_DECREE) {
                        l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                        break;
                    }
                }
                
                if (!l_chain) {
                    dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NO_DECREE_CHAIN"),
                                            "Network doesn't have a decree chain");
                    DAP_DELETE(l_certs);
                    dap_strfreev(l_certs_array);
                    return dap_cli_error_code_get("LEDGER_NO_DECREE_CHAIN");
                }
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_target_chain_str);
                // Get target chain from ledger's chain registry
                dap_chain_t *l_target_chain = NULL;
                if (l_target_chain_str) {
                    dap_chain_info_t *l_chain_info = dap_ledger_get_chain_info_by_name(l_ledger, l_target_chain_str);
                    if (l_chain_info)
                        l_target_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                } else {
                    // Find default TX chain
                    dap_chain_info_t *l_chain_info = NULL, *l_tmp = NULL;
                    HASH_ITER(hh, l_ledger->chains_registry, l_chain_info, l_tmp) {
                        if (l_chain_info->chain_type == CHAIN_TYPE_TX) {
                            l_target_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                            break;
                        }
                    }
                }
                if (!l_target_chain) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_ANCHOR_CHAIN,
                                            "Network %s doesn't have a chain %s", l_net_str, l_target_chain_str ? l_target_chain_str : "type tx");
                    DAP_DELETE(l_certs);
                    dap_strfreev(l_certs_array);
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_NO_ANCHOR_CHAIN;
                }
                size_t l_tsd_size = sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t); 
                // Create a decree
                size_t l_decree_size = sizeof(dap_chain_datum_decree_t) + l_tsd_size;
                dap_chain_datum_decree_t *l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, l_decree_size);
                l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
                l_decree->header.ts_created = dap_time_now();
                l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
                l_decree->header.common_decree_params.net_id = l_ledger->net_id;
                l_decree->header.common_decree_params.chain_id = l_target_chain->id;
                // Use callback to get current cell_id (defaults to zero if not set)
                l_decree->header.common_decree_params.cell_id = l_ledger->get_cur_cell_callback ? 
                                                                 l_ledger->get_cur_cell_callback(l_ledger) : 
                                                                 (dap_chain_cell_id_t){.uint64 = 0};
                // Set the subtype based on command
                l_decree->header.sub_type = l_key_subcmd == KEY_SUBCMD_ADD ? 
                                        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_ADD : 
                                        DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EVENT_PKEY_REMOVE;
                l_decree->header.data_size = l_tsd_size;
                l_decree->header.signs_size = 0;

                // Add TSD with key hash
                dap_tsd_write(l_decree->data_n_signs, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH, &l_pkey_hash, sizeof(l_pkey_hash));

                // Sign the decree
                size_t l_total_signs_success = 0;
                l_decree = dap_chain_datum_decree_sign_in_cycle(l_certs, l_decree, l_certs_count, &l_total_signs_success);
                DAP_DELETE(l_certs);
                dap_strfreev(l_certs_array);

                if (!l_decree || l_total_signs_success == 0) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_SIGNING_FAILED,
                                        "Decree signing failed");
                    DAP_DELETE(l_decree);
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_SIGNING_FAILED;
                }

                // Create datum and add to mempool
                dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE,
                                                                    l_decree,
                                                                    sizeof(*l_decree) + l_decree->header.data_size +
                                                                    l_decree->header.signs_size);
                DAP_DELETE(l_decree);
                char *l_key_str_out = dap_chain_mempool_datum_add(l_datum, l_chain, l_hash_out_type);
                DAP_DELETE(l_datum);

                if (l_key_str_out) {
                    dap_json_t *l_json_object = dap_json_object_new();
                    dap_json_object_add_string(l_json_object, "status", "success");
                    dap_json_object_add_string(l_json_object, "action", l_key_subcmd == KEY_SUBCMD_ADD ? "add" : "remove");
                    dap_json_object_add_string(l_json_object, "decree_datum", l_key_str_out);
                    dap_json_array_add(a_json_arr_reply, l_json_object);
                    DAP_DELETE(l_key_str_out);
                    return 0;
                } else {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_MEMPOOL_FAILED, "Failed to add decree to mempool");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_MEMPOOL_FAILED;
                }
            }
                
        } else if (l_subcmd == SUBCMD_LIST) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            // Get list of all events
            const char *l_group_name = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-group", &l_group_name);
            
            dap_json_t *l_json_obj_out = dap_json_object_new();
            dap_json_t *l_json_arr_events = dap_json_array_new();
            
            // Get events for specific group or all events
            dap_list_t *l_events = dap_ledger_event_get_list(l_ledger, l_group_name);
            if (l_events) {
                for (dap_list_t *l_item = l_events; l_item; l_item = l_item->next) {
                    dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)l_item->data;
                    dap_json_t *l_json_event = dap_json_object_new();
                    dap_chain_datum_tx_event_to_json(l_json_event, l_event, l_hash_out_type);
                    dap_json_array_add(l_json_arr_events, l_json_event);
                }
                
                // Free the list and its elements
                dap_list_free_full(l_events, dap_chain_tx_event_delete);
            }

            dap_json_object_add_object(l_json_obj_out, "events", l_json_arr_events);
            dap_json_array_add(a_json_arr_reply, l_json_obj_out);
            return 0;
        } else if (l_subcmd == SUBCMD_DUMP) {
            dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
            if (l_net_str == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command requires key -net");
                return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
            }
            
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
            if (!l_tx_hash_str) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                      "Command 'event dump' requires parameter -hash for tx hash");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            
            dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
            if (l_ledger == NULL) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            dap_hash_fast_t l_tx_hash = {};
            if (dap_chain_hash_fast_from_str(l_tx_hash_str, &l_tx_hash)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR, 
                                      "Invalid hash string format");
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_ERR;
            }
            
            dap_chain_tx_event_t *l_event = dap_ledger_event_find(l_ledger, &l_tx_hash);
            if (!l_event) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), 
                                      "Event not found for tx hash %s", l_tx_hash_str);
                return dap_cli_error_code_get("LEDGER_LACK_ERR");
            }
            
            dap_json_t *l_json_obj_out = dap_json_object_new();
            dap_chain_datum_tx_event_to_json(l_json_obj_out, l_event, l_hash_out_type);
            dap_json_array_add(a_json_arr_reply, l_json_obj_out);
            dap_chain_tx_event_delete(l_event);
            return 0;
        }
    } else if (l_cmd == CMD_TRACE) {
        // Handle trace command
        const char *l_hash_from_str = NULL; // starting hash
        const char *l_hash_to_str = NULL;   // target hash
        const char *l_depth_str = NULL;     // recursion depth
        
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from", &l_hash_from_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to", &l_hash_to_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-depth", &l_depth_str);
        
        // Parse recursion depth (default: 30)
        size_t l_max_depth = 30;
        if (l_depth_str) {
            char *l_endptr = NULL;
            unsigned long l_parsed_depth = strtoul(l_depth_str, &l_endptr, 10);
            if (*l_endptr != '\0' || l_parsed_depth == 0 || l_parsed_depth > 10000) {
                dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                      "Invalid depth parameter. Must be a number between 1 and 10000");
                return dap_cli_error_code_get("LEDGER_PARAM_ERR");
            }
            l_max_depth = (size_t)l_parsed_depth;
        }
        
        // Validate required parameters
        if (!l_hash_from_str) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Command 'trace' requires parameter -from");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        if (!l_hash_to_str) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                                  "Command 'trace' requires parameter -to");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        // Parse target hash (hash1)
        dap_chain_hash_fast_t l_hash_from = {};
        if (dap_chain_hash_fast_from_str(l_hash_from_str, &l_hash_from)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, 
                                "Can't parse target hash %s", l_hash_from_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }

        // Parse starting hash (hash2)
        dap_chain_hash_fast_t l_hash_to = {};
        if (dap_chain_hash_fast_from_str(l_hash_to_str, &l_hash_to)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, 
                                "Can't parse starting hash %s", l_hash_to_str);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }
        if (!l_net_str) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), 
                                  "Command 'trace' requires parameter -net");
            return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
        }
        // Get ledger
        dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
        if (!l_ledger) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), 
                                  "Can't get ledger for net %s", l_net_str);
            return dap_cli_error_code_get("LEDGER_LACK_ERR");
        }

        // Execute trace
        return s_ledger_trace_chain(l_ledger, &l_hash_from, &l_hash_to, l_hash_out_type, l_max_depth, a_json_arr_reply);
        
    } else if (l_cmd == CMD_LIST) {
        enum {SUBCMD_NONE, SUBCMD_LIST_COIN, SUB_CMD_LIST_LEDGER_THRESHOLD, SUB_CMD_LIST_LEDGER_BALANCE, SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH};
        int l_sub_cmd = SUBCMD_NONE;
        dap_chain_hash_fast_t l_tx_threshold_hash = {};
        const char *l_limit_str = NULL;
        const char *l_offset_str = NULL;
        const char *l_head_str = NULL;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "coins", NULL))
            l_sub_cmd = SUBCMD_LIST_COIN;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, 3, "balance", NULL))
            l_sub_cmd = SUB_CMD_LIST_LEDGER_BALANCE;
        if (dap_cli_server_cmd_find_option_val(a_argv, 2, a_argc, "threshold", NULL)) {
            l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD;
            const char* l_tx_threshold_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(a_argv, 3, a_argc, "-hash", &l_tx_threshold_hash_str);
            if (l_tx_threshold_hash_str) {
                l_sub_cmd = SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH;
                if (dap_chain_hash_fast_from_str(l_tx_threshold_hash_str, &l_tx_threshold_hash)) {
                    l_tx_hash_str = NULL;
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR, "tx threshold hash not recognized");
                    return DAP_CHAIN_NODE_CLI_COM_LEDGER_TRESHOLD_ERR;
                }
            }
        }
        if (l_sub_cmd == SUBCMD_NONE) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Command 'list' requires subcommands 'coins' or 'threshold'");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        dap_cli_server_cmd_find_option_val(a_argv, 0, a_argc, "-net", &l_net_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
        bool l_head = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-head", &l_head_str) ? true : false;
        size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 0;
        size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
        if (l_net_str == NULL) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Command 'list' requires key -net");
            return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
        }
        dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
        if (l_ledger == NULL) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_LACK_ERR"), "Can't get ledger for net %s", l_net_str);
            return dap_cli_error_code_get("LEDGER_LACK_ERR");
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD) {
            dap_json_t *json_obj_out = dap_ledger_threshold_info(l_ledger, l_limit, l_offset, NULL, l_head, a_version);
            if (json_obj_out) {
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_THRESHOLD_WITH_HASH) {
            dap_json_t *json_obj_out = dap_ledger_threshold_info(l_ledger, 0, 0, &l_tx_threshold_hash, l_head, a_version);
            if (json_obj_out) {
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        if (l_sub_cmd == SUB_CMD_LIST_LEDGER_BALANCE) {
            dap_json_t *json_obj_out = dap_ledger_balance_info(l_ledger, l_limit, l_offset, l_head, a_version);
            if (json_obj_out) {
                dap_json_array_add(a_json_arr_reply, json_obj_out);
            }
            return 0;
        }
        dap_json_t *json_obj_datum = dap_ledger_token_info(l_ledger, l_limit, l_offset, a_version);

        if (json_obj_datum) {
            dap_json_array_add(a_json_arr_reply, json_obj_datum);
        }
        return 0;
    } else if (l_cmd == CMD_TX_INFO) {
        // GET hash
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_tx_hash_str);
        // get net
        dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
        // get search type
        bool l_unspent_flag = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL);
        bool l_need_sign = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-need_sign", NULL);
        (void)l_unspent_flag;
        (void)l_need_sign;
        // check input
        if (l_tx_hash_str == NULL) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Subcommand 'info' requires key -hash");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        if (l_net_str == NULL) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), "Subcommand 'info' requires key -net");
            return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
        }
        // Get ledger by net name
        dap_ledger_t *l_ledger = dap_ledger_find_by_name(l_net_str);
        if (!l_ledger) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_NET_FIND_ERR"), "Can't find net %s", l_net_str);
            return dap_cli_error_code_get("LEDGER_NET_FIND_ERR");
        }
        dap_chain_hash_fast_t *l_tx_hash = DAP_NEW(dap_chain_hash_fast_t);
        if (dap_chain_hash_fast_from_str(l_tx_hash_str, l_tx_hash)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR, "Can't get hash_fast from %s, check that the hash is correct", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return DAP_CHAIN_NODE_CLI_COM_LEDGER_HASH_GET_ERR;
        }
        // Use ledger's TX find function directly
        dap_chain_datum_tx_t *l_datum_tx = dap_ledger_tx_find_by_hash(l_ledger, l_tx_hash);
        if (l_datum_tx == NULL) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), "Can't find datum for transaction hash %s in chains", l_tx_hash_str);
            DAP_DEL_Z(l_tx_hash);
            return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
        }
        dap_json_t *json_datum = dap_json_object_new();
        if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx_to_json", NULL)) {
            const char *l_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, l_tx_hash);
            dap_json_object_add_string(json_datum, "token_ticker", l_ticker);
            bool l_all_outs_unspent = true;
            byte_t *l_item; size_t l_size; int index, l_out_idx = -1;
            dap_json_t *json_arr_items = dap_json_array_new();
            TX_ITEM_ITER_TX_TYPE(l_item, TX_ITEM_TYPE_OUT_ALL, l_size, index, l_datum_tx) {
                dap_hash_fast_t l_spender = { };
                ++l_out_idx;
                if (dap_ledger_tx_hash_is_used_out_item(l_ledger, l_tx_hash, l_out_idx, NULL)) {
                    l_all_outs_unspent = false;
                    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                    dap_hash_fast_to_str(&l_spender, l_hash_str, sizeof(l_hash_str));
                    dap_json_t *l_json_obj_datum = dap_json_object_new();
                    dap_json_object_add_int(l_json_obj_datum, "out_idx", l_out_idx);
                    dap_json_object_add_string(l_json_obj_datum, "spent_by_tx", l_hash_str);
                    dap_json_array_add(json_arr_items, l_json_obj_datum);
                }
            }
            dap_json_object_add_object(json_datum, "all_outs_unspent", dap_json_object_new_bool(l_all_outs_unspent));
            if (l_all_outs_unspent) {
                dap_json_object_free(json_arr_items);
            } else {
                dap_json_object_add_object(json_datum, "spent_or_coloured_outs", json_arr_items);
            }
            dap_chain_net_tx_to_json(l_datum_tx, json_datum);
            if (!dap_json_object_length(json_datum)) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_TO_JSON_ERR, "Can't find transaction hash %s in ledger", l_tx_hash_str);
                dap_json_object_free(json_datum);
                DAP_DELETE(l_tx_hash);
                return DAP_CHAIN_NODE_CLI_COM_LEDGER_TX_TO_JSON_ERR;
            }
            dap_json_array_add(a_json_arr_reply, json_datum);
            DAP_DELETE(l_tx_hash);
            return 0;
        }

        if (!s_dap_chain_datum_tx_out_data(a_json_arr_reply, l_datum_tx, l_ledger, json_datum, l_hash_out_type, l_tx_hash, a_version)) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_TX_HASH_ERR"), "Can't find transaction hash %s in ledger", l_tx_hash_str);
            dap_json_object_free(json_datum);
            DAP_DEL_Z(l_tx_hash);
            return dap_cli_error_code_get("LEDGER_TX_HASH_ERR");
        }
        DAP_DELETE(l_tx_hash);

        if (json_datum) {
            dap_json_array_add(a_json_arr_reply, json_datum);
        }        
    } else {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_PARAM_ERR"), "Command 'ledger' requires parameter 'list', 'info', or 'trace'");
        return dap_cli_error_code_get("LEDGER_PARAM_ERR");
    }
    return 0;
}

/**
 * @brief Initialize ledger CLI module
 */
int dap_chain_ledger_cli_ledger_init(void)
{
    log_it(L_INFO, "Initializing ledger CLI command module");
    
    // Register the "ledger" command
    dap_cli_server_cmd_add("ledger", com_ledger, s_print_for_ledger_list, 
        "Ledger information commands", 0,
        "ledger list coins -net <net_name> [-limit <N>] [-offset <N>] [-head]\n"
        "\tList all tokens in ledger with coin information\n\n"
        "ledger list threshold -net <net_name> [-hash <tx_hash>] [-limit <N>] [-offset <N>] [-head]\n"
        "\tList threshold transactions (pending verification)\n\n"
        "ledger list balance -net <net_name> [-limit <N>] [-offset <N>] [-head]\n"
        "\tList balance information\n\n"
        "ledger info -net <net_name> -hash <tx_hash> [-H {hex|base58}] [-tx_to_json]\n"
        "\tShow transaction info by hash\n\n"
        "ledger trace -net <net_name> -from <hash> -to <hash> [-depth <N>] [-H {hex|base58}]\n"
        "\tTrace transaction chain from one hash to another\n\n"
        "ledger event list -net <net_name> [-group <group_name>]\n"
        "\tList all ledger events\n\n"
        "ledger event dump -net <net_name> -hash <tx_hash>\n"
        "\tDump event details by TX hash\n\n"
        "ledger event key list -net <net_name>\n"
        "\tList authorized event public key hashes\n\n"
        "ledger event key add -net <net_name> -hash <pkey_hash> -certs <cert1,cert2,...> [-chain <chain>]\n"
        "\tAdd public key to authorized event keys\n\n"
        "ledger event key remove -net <net_name> -hash <pkey_hash> -certs <cert1,cert2,...> [-chain <chain>]\n"
        "\tRemove public key from authorized event keys\n");
    
    log_it(L_NOTICE, "Ledger CLI command module initialized");
    return 0;
}

/**
 * @brief Deinitialize ledger CLI module
 */
void dap_chain_ledger_cli_ledger_deinit(void)
{
    log_it(L_INFO, "Deinitializing ledger CLI command module");
    // No specific cleanup needed
}

/**
* @brief s_print_for_ledger_list
* Post-processing callback for ledger list command. Formats JSON input into
* human-readable table output.
*
* @param a_json_input Input JSON from command handler
* @param a_json_output Output JSON array to write formatted result
* @param a_cmd_param Command parameters array
* @param a_cmd_cnt Count of command parameters
* @return 0 on success (result written to a_json_output), non-zero to use original input
*/

static int s_print_for_ledger_list(dap_json_t *a_json_input, dap_json_t *a_json_output, char **a_cmd_param, int a_cmd_cnt)
{
    dap_return_val_if_pass(!a_json_input || !a_json_output, -1);
    
    // If no -h flag, return raw JSON
    bool l_table_mode = dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "-h") != -1;
    if (!l_table_mode)
        return -1;
    if (dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "list") == -1)
        return -1;
    dap_string_t *l_str = dap_string_new("\n");
    // coins
    if (dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "coins") != -1) {
        if (dap_json_get_type(a_json_input) != DAP_JSON_TYPE_ARRAY) {
            dap_string_free(l_str, true);
            return -1;
        }

        dap_json_t *root0 = dap_json_array_get_idx(a_json_input, 0);
        if (!root0) {
            dap_string_free(l_str, true);
            return -1;
        }
        if (dap_json_get_type(root0) == DAP_JSON_TYPE_ARRAY) {
            int arr_len = dap_json_array_length(root0);
            if (arr_len <= 0) {
                dap_string_append(l_str, "No coins found\n");
                goto finalize;
            }
            dap_string_append(l_str, "__________________________________________________________________________________________________________"
                "____________________________\n");
            dap_string_append_printf(l_str, "  %-15s|  %-7s| %-9s|  %-45s|  %-45s|\n",
                "Token Ticker", "Type", "Decimals", "Total Supply", "Current Supply");
            dap_string_append(l_str, "__________________________________________________________________________________________________________"
                "____________________________\n");
            int printed = 0;
            for (int i = 0; i < arr_len; i++) {
                dap_json_t *it = dap_json_array_get_idx(root0, i);
                if (!it || dap_json_get_type(it) != DAP_JSON_TYPE_OBJECT)
                    continue;
                dap_json_t *limit = NULL, *offset = NULL;
                if (dap_json_object_get_ex(it, "limit", &limit) || dap_json_object_get_ex(it, "offset", &offset))
                    continue;
                const char *ticker = NULL;
                const char *type_str = "N/A";
                const char *supply_total = "N/A";
                const char *supply_current = "N/A";
                int decimals = 0;
                dap_json_t *j_ticker = NULL, *j_type = NULL, *j_dec = NULL, *j_supply_total = NULL, *j_supply_current = NULL;
                if (dap_json_object_get_ex(it, "token_name", &j_ticker) ||
                    dap_json_object_get_ex(it, "-->Token name", &j_ticker))
                    ticker = dap_json_get_string(j_ticker);
                if (dap_json_object_get_ex(it, "subtype", &j_type) ||
                    dap_json_object_get_ex(it, "type", &j_type))
                    type_str = dap_json_get_string(j_type);
                if (dap_json_object_get_ex(it, "decimals", &j_dec) ||
                    dap_json_object_get_ex(it, "Decimals", &j_dec))
                    decimals = (int)dap_json_get_int64(j_dec);
                if (dap_json_object_get_ex(it, "supply_total", &j_supply_total) ||
                    dap_json_object_get_ex(it, "Supply total", &j_supply_total))
                    supply_total = dap_json_get_string(j_supply_total);
                if (dap_json_object_get_ex(it, "supply_current", &j_supply_current) ||
                    dap_json_object_get_ex(it, "Supply current", &j_supply_current))
                    supply_current = dap_json_get_string(j_supply_current);
                if (!ticker)
                    ticker = "UNKNOWN";
                dap_string_append_printf(l_str, "  %-15s|  %-7s|    %-6d|  %-45s|  %-45s|\n",
                    ticker, type_str, decimals, supply_total, supply_current);
                printed++;
            }
            if (!printed)
                dap_string_append(l_str, "No coins found\n");
            goto finalize;
        }
        // Object format - fallback to raw JSON
        dap_string_free(l_str, true);
        return -1;
    }
    // threshold
    if (dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "threshold") != -1) {
        bool l_full = dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "-full") != -1;
        if (dap_json_get_type(a_json_input) != DAP_JSON_TYPE_ARRAY) {
            dap_string_free(l_str, true);
            return -1;
        }
        dap_json_t *json_obj_array = dap_json_array_get_idx(a_json_input, 0);
        if (!json_obj_array) {
            dap_string_append(l_str, "Response array is empty\n");
            goto finalize;
        }
        int result_count = dap_json_array_length(json_obj_array);
        if (result_count <= 0) {
            dap_string_append(l_str, "Response array is empty\n");
            goto finalize;
        }
        if (l_full) {
            dap_string_append(l_str, "_________________________________________________________________________________________________________________"
                "_________________________________________________________________________________________________________________\n");
            dap_string_append_printf(l_str, " %-66s | %-31s | %-12s |\n", "Tx Hash", "Time Created", "Items Size");
        } else {
            dap_string_append(l_str, "________________________________________________________________________________________________________\n");
            dap_string_append_printf(l_str, " %-15s | %-31s | %-12s |\n", "Tx Hash", "Time Created", "Items Size");
        }
        char hash_buffer[16];
        for (int i = 0; i < result_count; i++) {
            dap_json_t *json_obj_result = dap_json_array_get_idx(json_obj_array, i);
            if (!json_obj_result)
                continue;
            dap_json_t *j_meta = NULL;
            if (dap_json_object_get_ex(json_obj_result, "limit", &j_meta) ||
                dap_json_object_get_ex(json_obj_result, "offset", &j_meta))
                continue;
            dap_json_t *j_tx_hash = NULL, *j_time_created = NULL, *j_items_size = NULL;
            if (!dap_json_object_get_ex(json_obj_result, "tx_hash", &j_tx_hash))
                dap_json_object_get_ex(json_obj_result, "Ledger thresholded tx_hash_fast", &j_tx_hash);
            dap_json_object_get_ex(json_obj_result, "time_created", &j_time_created);
            dap_json_object_get_ex(json_obj_result, "tx_item_size", &j_items_size);

            const char *tx_hash_full = j_tx_hash ? dap_json_get_string(j_tx_hash) : NULL;
            const char *tx_hash_short = tx_hash_full;
            if (!l_full && tx_hash_full && strlen(tx_hash_full) > 15) {
                strncpy(hash_buffer, tx_hash_full + strlen(tx_hash_full) - 15, 15);
                hash_buffer[15] = '\0';
                tx_hash_short = hash_buffer;
            }
            dap_string_append_printf(l_str, " %-15s | %-31s | %-12s |\n",
                l_full ? (tx_hash_full ? tx_hash_full : "-") : (tx_hash_short ? tx_hash_short : "-"),
                j_time_created ? dap_json_get_string(j_time_created) : "-",
                j_items_size ? dap_json_get_string(j_items_size) : "-");
        }
        goto finalize;
    }

    // balance
    if (dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "balance") != -1) {
        bool l_full = dap_cli_server_cmd_check_option(a_cmd_param, 0, a_cmd_cnt, "-full") != -1;
        if (dap_json_get_type(a_json_input) != DAP_JSON_TYPE_ARRAY) {
            dap_string_free(l_str, true);
            return -1;
        }
        dap_json_t *json_obj_array = dap_json_array_get_idx(a_json_input, 0);
        if (!json_obj_array) {
            dap_string_append(l_str, "Response array is empty\n");
            goto finalize;
        }
        int result_count = dap_json_array_length(json_obj_array);
        if (result_count <= 0) {
            dap_string_append(l_str, "Response array is empty\n");
            goto finalize;
        }
        if (l_full) {
            dap_string_append(l_str, "_________________________________________________________________________________________________________________"
                "____________________________________________________________________________________________\n");
            dap_string_append_printf(l_str, " %-120s | %-10s | %-66s |\n", "Balance Key", "Token", "Balance");
        } else {
            dap_string_append(l_str, "________________________________________________________________________________________________________"
                "__________\n");
            dap_string_append_printf(l_str, " %-30s | %-10s | %-66s |\n", "Balance Key", "Token", "Balance");
        }
        for (int i = 0; i < result_count; i++) {
            dap_json_t *json_obj_result = dap_json_array_get_idx(json_obj_array, i);
            if (!json_obj_result)
                continue;
            dap_json_t *j_meta = NULL;
            if (dap_json_object_get_ex(json_obj_result, "limit", &j_meta) ||
                dap_json_object_get_ex(json_obj_result, "offset", &j_meta))
                continue;

            dap_json_t *j_key = NULL, *j_token = NULL, *j_balance = NULL;
            if (!dap_json_object_get_ex(json_obj_result, "balance_key", &j_key))
                dap_json_object_get_ex(json_obj_result, "Ledger balance key", &j_key);
            dap_json_object_get_ex(json_obj_result, "token_ticker", &j_token);
            dap_json_object_get_ex(json_obj_result, "balance", &j_balance);
            int key_width = l_full ? 120 : 30;
            const char *key_str_full = j_key ? dap_json_get_string(j_key) : "-";
            dap_string_append_printf(l_str, " %-*s | %-10s | %-66s |\n",
                key_width,
                l_full ? key_str_full : key_str_full+85,
                j_token ? dap_json_get_string(j_token) : "-",
                j_balance ? dap_json_get_string(j_balance) : "-");
        }
        goto finalize;
    }
    // No handler matched
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

                   


