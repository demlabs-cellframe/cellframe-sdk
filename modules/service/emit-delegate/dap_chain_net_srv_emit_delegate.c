/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "dap_chain_mempool.h"
#include "dap_cli_server.h"
#include "dap_chain_net_srv_emit_delegate.h"

enum emit_delegation_error {
    NO_ERROR = 0,
    ERROR_MEMORY,
    ERROR_PARAM,
    ERROR_VALUE,
    ERROR_WRONG_HASH,
    ERROR_CREATE,
    ERROR_SUBCOMMAND
};

#define LOG_TAG "dap_chain_net_srv_emit_delegate"

static int s_emit_delegate_verificator(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond, bool a_owner)
{
    size_t l_tsd_hashes_count = a_cond->tsd_size / (sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t));
    dap_sign_t *l_signs[l_tsd_hashes_count];
    uint32_t l_signs_counter = 0, l_signs_verified = 0;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx_in) {
        if (*l_item == TX_ITEM_TYPE_SIG) {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_item);
            bool l_dup = false;
            for (uint32_t i = 0; i < l_signs_counter; i++)
                if (dap_sign_compare_pkeys(l_sign, l_signs[i])) {
                    l_dup = true;
                    break;
                }
            if (l_dup)
                continue;
            l_signs[l_signs_counter++] = l_sign;
            if (l_signs_counter > l_tsd_hashes_count) {
                log_it(L_WARNING, "Too many signs in tx %s, can't process more than %zu", dap_hash_fast_to_str_static(a_tx_in_hash), l_tsd_hashes_count);
                return -1;
            }
            dap_hash_fast_t l_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
            dap_tsd_t *l_tsd; size_t l_tsd_size;
            dap_tsd_iter(l_tsd, l_tsd_size, a_cond->tsd, a_cond->tsd_size) {
                if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t) &&
                        dap_hash_fast_compare(&l_pkey_hash, (dap_hash_fast_t *)l_tsd->data)) {
                    uint32_t l_orig_size = a_tx_in->header.tx_items_size;
                    a_tx_in->header.tx_items_size = 0;
                    if (dap_sign_verify(l_sign, a_tx_in, l_item - (byte_t *)a_tx_in))
                        l_signs_verified++;
                    a_tx_in->header.tx_items_size = l_orig_size;
                }
            }
        }
    }
    if (l_signs_verified < a_cond->subtype.srv_emit_delegate.signers_minimum) {
        log_it(L_WARNING, "Not enough valid signs (%u from %u) for delegated emission in tx %s",
                                    l_signs_verified, a_cond->subtype.srv_emit_delegate.signers_minimum, dap_hash_fast_to_str_static(a_tx_in_hash));
        return -2;
    }
    return 0;
}

static bool s_tag_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{   
    return a_items_grp->items_out_cond_srv_emit_delegate;
}

static int s_emitting_tx_create(json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key, uint256_t a_value, uint256_t a_fee, uint32_t a_signs_min, const char *a_pkeys_str)
{
    dap_chain_hash_fast_t *l_hash_block = DAP_NEW_Z_SIZE();
    char *l_hashes_tmp_ptrs = NULL;
    char *l_hashes_str = strtok_r(l_pkeys_str, ",", &l_hashes_tmp_ptrs);
    size_t l_hashes_pos = 0;
    while (l_hashes_str) {
        l_hashes_str = dap_strstrip(l_hashes_str);
        if (!l_hashes_str || dap_chain_hash_fast_from_str(l_hashes_str, &l_hash_block)) {
            log_it(L_WARNING, "Can't convert string %s to hash", l_hashes_str ? l_hashes_str : "(null)");
            l_hashes_pos = 0;
            break;
        }
        dap_chain_block_t *l_block = (dap_chain_block_t *)dap_chain_get_atom_by_hash(a_chain, &l_hash_block, NULL);
        if (!l_block) {
            log_it(L_WARNING, "There is no block pointed by hash %s", l_hashes_str);
            l_hashes_pos = 0;
            break;
        }
        dap_hash_fast_t *l_block_hash_new = DAP_DUP(&l_hash_block);
        if (!l_block_hash_new) {
            log_it(L_CRITICAL, "Memory allocaton error");
            l_hashes_pos = 0;
            break;
        }
        l_block_list = dap_list_append(l_block_list, l_block_hash_new);
        l_hashes_str = strtok_r(NULL, ",", &l_hashes_tmp_ptrs);
        l_hashes_pos++;
    }
    if (a_hash_size)
        *a_hash_size = l_hashes_pos;
    if (!l_hashes_pos && l_block_list) {
        dap_list_free_full(l_block_list, NULL);
        l_block_list = NULL;
    }
    return l_block_list;
}

static int s_cli_hold(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    const char *l_token_str = NULL, *l_value_str = NULL, *l_wallet_str = NULL, *l_fee_str = NULL, *l_signs_min_str = NULL, *l_pkeys_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-token", &l_token_str);
    if (!l_token_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -token");
        return ERROR_PARAM;
    }
    if (!dap_ledger_token_ticker_check(a_net->pub.ledger, l_token_str)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Token %s not found in ledger", l_token_str);
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-value", &l_value_str);
    if (!l_value_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -value");
        return ERROR_PARAM;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -value <256 bit integer>");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-w", &l_wallet_str);
    if (!l_wallet_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -w");
        return ERROR_PARAM;
    }
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
    if (!l_wallet) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Specified wallet %s not found", l_wallet_str);
        return ERROR_VALUE;
    }
    const char *l_sign_str = dap_chain_wallet_check_sign(l_wallet);
    dap_enc_key_t *l_enc_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);

    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-fee", &l_fee_str);
    if (!l_fee_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -fee");
        return ERROR_PARAM;
    }
    uint256_t l_fee = dap_chain_balance_scan(l_fee_str);
    if (IS_ZERO_256(l_fee)) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -fee <256 bit integer>");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-signs_minimum", &l_signs_min_str);
    if (!l_signs_min_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -signs_minimum");
        return ERROR_PARAM;
    }
    uint32_t l_signs_min = atoi(l_signs_min_str);
    if (l_signs_min) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_VALUE, "Format -signs_minimum <32-bit unsigned integer>");
        return ERROR_VALUE;
    }
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, "-pkey_hashes", &l_pkeys_str);
    if (!l_pkeys_str) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM, "Emitting delegation holding requires parameter -pkey_hashes");
        return ERROR_PARAM;
    }

    // Create conditional transaction for delegated emissions
    dap_chain_datum_tx_t *l_tx = s_emitting_tx_create(a_json_arr_reply, a_net, l_enc_key, l_value, l_fee, l_signs_min, l_pkeys_str);
    DAP_DEL_Z(l_enc_key);
    char *l_tx_hash_str = NULL;
    if (!l_tx || !(l_tx_hash_str = s_emitting_tx_put(l_tx, a_net, a_chain, a_hash_out_type))) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_CREATE, "Can't compose transaction for order, examine log files for details");
        DAP_DEL_Z(l_tx);
        return ERROR_CREATE;
    }
    DAP_DELETE(l_tx);

    json_object * l_json_obj_create_val = json_object_new_object();
    json_object_object_add(l_json_obj_create_val, "status", json_object_new_string("success"));
    if (dap_strcmp(l_sign_str, ""))
        json_object_object_add(l_json_obj_create_val, "sign", json_object_new_string(l_sign_str));
    json_object_object_add(l_json_obj_create_val, "tx_hash", json_object_new_string(l_tx_hash_str));
    json_object_array_add(*a_json_arr_reply, l_json_obj_create_val);
    DAP_DELETE(l_tx_hash_str);
}

static int s_cli_take(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain)
{

}

static int s_cli_sign(int a_argc, char **a_argv, int a_arg_index, json_object **a_json_arr_reply, dap_chain_net_t *a_net, dap_chain_t *a_chain)
{

}

/**
 * @brief s_cli_stake_lock
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return
 */
static int s_cli_emit_delegate(int a_argc, char **a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    enum {
        CMD_NONE, CMD_HOLD, CMD_TAKE, CMD_SIGN
    };
    int l_arg_index = 1;
    dap_chain_net_t *l_net = NULL;
    dap_chain_t *l_chain = NULL;
    const char *l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    if (!l_hash_out_type)
        l_hash_out_type = "hex";
    else if (dap_strcmp(l_hash_out_type," hex") && dap_strcmp(l_hash_out_type, "base58")) {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_PARAM,
                                "Invalid parameter -H, valid values: -H <hex | base58>");
        return ERROR_PARAM;
    }
    int l_err_net_chain = dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &l_arg_index, a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_TX);
    if (l_err_net_chain)
        return l_err_net_chain;

    int l_cmd_num = CMD_NONE;
    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "hold", NULL))
        return s_cli_hold(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "take", NULL))
        return s_cli_take(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, dap_min(a_argc, l_arg_index + 1), "sign", NULL))
        return s_cli_sign(a_argc, a_argv, l_arg_index + 1, a_json_arr_reply, l_net, l_chain, l_hash_out_type);
    else {
        dap_json_rpc_error_add(*a_json_arr_reply, ERROR_SUBCOMMAND, "Subcommand %s not recognized", a_argv[l_arg_index]);
        return ERROR_SUBCOMMAND;
    }
}

int dap_chain_net_srv_bridge_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_EMIT_DELEGATE, s_emit_delegate_verificator, NULL, NULL, NULL, NULL, NULL);
    dap_cli_server_cmd_add("emit_delegate", s_cli_emit_delegate, "Emitting delegation service commands",
                "emit_delegate hold -net <net_name> -w <wallet_name> -token <ticker> -value <value> -fee <value>"
                            "-signs_minimum <value_int> -pkey_hashes <hash1[,hash2,...,hashN]> [-chain <chain_name>] [-H {hex(default) | base58}]\n"
                "emit_delegate take -net <net_name> -w <wallet_name> -tx <transaction_hash> -value <value> -fee <value> [-chain <chain_name>] [-H {hex(default) | base58}]\n"
                "emit_delegate sign -net <net_name> -w <wallet_name> -tx <transaction_hash> [-chain <chain_name>] [-H {hex(default) | base58}]\n\n"
                            "Hint:\n"
                            "\texample value_coins (only natural) 1.0 123.4567\n"
                            "\texample value_datoshi (only integer) 1 20 0.4321e+4\n"
    );

    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_EMIT_DELEGATE_ID };
    dap_ledger_service_add(l_uid, "emit-delegate", s_tag_check);

    return 0;
}


