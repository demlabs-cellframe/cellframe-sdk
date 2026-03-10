/*
 * TX-related CLI commands migrated from ledger module to net/tx
 * to respect the dependency hierarchy (ledger does not depend on net).
 *
 * Commands: tx_create, tx_create_json, mempool_add, tx_verify,
 *           tx_history, tx_cond_create, tx_cond_remove, tx_cond_unspent_find
 *
 * Authors:
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * Cellframe Team
 * Copyright (c) 2019-2026
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_config.h"
#include "dap_enc_base58.h"
#include "dap_enc_base64.h"
#include "dap_json.h"
#include "dap_json_rpc_errors.h"
#include "dap_math_convert.h"
#include "dap_global_db.h"
#include "dap_cert.h"

#include "dap_cli_server.h"
#include "dap_cli_error_codes.h"

#include "dap_chain.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_chain_utxo.h"

#include "dap_chain_ledger.h"
#include "dap_chain_ledger_cli.h"
#include "dap_chain_ledger_cli_compat.h"
#include "dap_chain_ledger_cli_error_codes.h"

#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_net_tx_cli.h"
#include "dap_chain_net_utils.h"

#include "dap_chain_wallet.h"
#include "dap_chain_mempool.h"
#include "dap_chain_srv.h"
#include "dap_chain_datum_tx_create.h"

#define LOG_TAG "chain_net_tx_cli"

#define DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC        (-20)
#define DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_CHECK_SIGN_FUNC  (-21)
#define DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC    (-22)
#define DAP_LEDGER_CLI_ERROR_MEMORY_ALLOC                  (-23)

#define dap_cli_error_get_code(x) (x)
#define dap_cli_error_get_str(x)  #x

static dap_chain_wallet_t *s_wallet_open(const char *a_wallet_name)
{
    const char *l_wallets_path = dap_chain_wallet_get_path(g_config);
    if (!l_wallets_path || !a_wallet_name)
        return NULL;
    return dap_chain_wallet_open(a_wallet_name, l_wallets_path, NULL);
}

static dap_enc_key_t *s_wallet_get_key(const char *a_wallet_name)
{
    dap_chain_wallet_t *l_wallet = s_wallet_open(a_wallet_name);
    if (!l_wallet)
        return NULL;
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);
    return l_key;
}

static dap_chain_addr_t *s_wallet_get_addr(const char *a_wallet_name, dap_chain_net_id_t a_net_id)
{
    dap_chain_wallet_t *l_wallet = s_wallet_open(a_wallet_name);
    if (!l_wallet)
        return NULL;
    dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(l_wallet, a_net_id);
    dap_chain_wallet_close(l_wallet);
    return l_addr;
}

static dap_pkey_t *s_wallet_get_pkey(const char *a_wallet_name)
{
    dap_chain_wallet_t *l_wallet = s_wallet_open(a_wallet_name);
    if (!l_wallet)
        return NULL;
    dap_pkey_t *l_pkey = dap_chain_wallet_get_pkey(l_wallet, 0);
    dap_chain_wallet_close(l_wallet);
    return l_pkey;
}

static char *s_sign_and_mempool_add(dap_chain_datum_tx_t *a_tx, dap_enc_key_t *a_key,
                                    dap_chain_t *a_chain, const char *a_hash_out_type)
{
    if (!a_tx || !a_key || !a_chain)
        return NULL;
    if (dap_chain_datum_tx_add_sign_item(&a_tx, a_key) != 1) {
        log_it(L_ERROR, "Failed to add sign item to TX");
        DAP_DELETE(a_tx);
        return NULL;
    }
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
    DAP_DELETE(a_tx);
    if (!l_datum)
        return NULL;
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, a_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_hash_str;
}

/**
 * @brief Convert ledger UTXO list (dap_chain_tx_used_out_t) to builder format (dap_chain_tx_used_out_item_t)
 */
static dap_list_t *s_convert_utxo_list(dap_list_t *a_ledger_utxos)
{
    dap_list_t *l_result = NULL;
    for (dap_list_t *it = a_ledger_utxos; it; it = it->next) {
        dap_chain_tx_used_out_t *l_src = it->data;
        dap_chain_tx_used_out_item_t *l_dst = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        if (!l_dst) break;
        l_dst->tx_hash_fast = l_src->tx_prev_hash;
        l_dst->num_idx_out  = l_src->tx_out_prev_idx;
        l_dst->value        = l_src->value;
        l_result = dap_list_append(l_result, l_dst);
    }
    return l_result;
}

static char *s_mempool_base_tx_create(dap_chain_t *a_chain, dap_hash_sha3_256_t *a_emission_hash,
                                      dap_chain_id_t a_emission_chain_id,
                                      uint256_t a_value, const char *a_ticker, dap_chain_addr_t *a_addr_to,
                                      dap_enc_key_t *a_priv_key, const char *a_hash_out_type, uint256_t a_value_fee)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_from_emission(
        a_chain->net_id, a_emission_hash, a_emission_chain_id,
        a_value, a_ticker, a_addr_to, a_value_fee);
    if (!l_tx) return NULL;
    return s_sign_and_mempool_add(l_tx, a_priv_key, a_chain, a_hash_out_type);
}

static char *s_mempool_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_priv_key,
                                 const dap_chain_addr_t *a_addr_from,
                                 const dap_chain_addr_t **a_addr_to,
                                 const char *a_token_ticker, uint256_t *a_values,
                                 uint256_t a_value_fee, const char *a_hash_out_type,
                                 size_t a_outputs_count, dap_time_t *a_time_unlock)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net || !l_net->pub.ledger) return NULL;

    uint256_t l_total = uint256_0;
    for (size_t i = 0; i < a_outputs_count; i++)
        SUM_256_256(l_total, a_values[i], &l_total);
    SUM_256_256(l_total, a_value_fee, &l_total);

    uint256_t l_value_found = {};
    dap_list_t *l_utxos_ledger = dap_ledger_get_utxo_for_value(
        l_net->pub.ledger, a_token_ticker, a_addr_from, l_total, &l_value_found);
    if (!l_utxos_ledger) return NULL;

    dap_list_t *l_utxos = s_convert_utxo_list(l_utxos_ledger);
    dap_list_free_full(l_utxos_ledger, NULL);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_multi_transfer(
        a_chain->net_id, a_addr_from, a_addr_to, a_values,
        a_token_ticker, a_value_fee, a_outputs_count, a_time_unlock, l_utxos);
    dap_list_free_full(l_utxos, NULL);

    if (!l_tx) return NULL;
    return s_sign_and_mempool_add(l_tx, a_priv_key, a_chain, a_hash_out_type);
}

static int s_mempool_tx_create_massive(dap_chain_t *a_chain, dap_enc_key_t *a_priv_key,
                                       const dap_chain_addr_t *a_addr_from,
                                       const dap_chain_addr_t *a_addr_to,
                                       const char *a_token_ticker, uint256_t a_value,
                                       uint256_t a_value_fee, size_t a_tx_num)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net || !l_net->pub.ledger) return -1;

    for (size_t i = 0; i < a_tx_num; i++) {
        uint256_t l_total = {};
        SUM_256_256(a_value, a_value_fee, &l_total);

        uint256_t l_value_found = {};
        dap_list_t *l_utxos_ledger = dap_ledger_get_utxo_for_value(
            l_net->pub.ledger, a_token_ticker, a_addr_from, l_total, &l_value_found);
        if (!l_utxos_ledger) return -1;

        dap_list_t *l_utxos = s_convert_utxo_list(l_utxos_ledger);
        dap_list_free_full(l_utxos_ledger, NULL);

        dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_transfer(
            a_chain->net_id, a_addr_from, a_addr_to,
            a_token_ticker, a_value, a_value_fee, l_utxos);
        dap_list_free_full(l_utxos, NULL);

        if (!l_tx) return -1;
        char *l_hash = s_sign_and_mempool_add(l_tx, a_priv_key, a_chain, "hex");
        if (!l_hash) return -1;
        DAP_DELETE(l_hash);
    }
    return 0;
}

static char *s_mempool_tx_create_cond(dap_chain_t *a_chain, dap_enc_key_t *a_priv_key,
                                      dap_hash_sha3_256_t *a_pkey_cond_hash,
                                      const char *a_token_ticker, uint256_t a_value,
                                      uint256_t a_value_per_unit_max,
                                      dap_chain_net_srv_price_unit_uid_t a_unit,
                                      dap_chain_srv_uid_t a_srv_uid,
                                      uint256_t a_value_fee,
                                      const void *a_cond, size_t a_cond_size)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net || !l_net->pub.ledger) return NULL;

    dap_chain_addr_t l_addr_from = {};
    dap_chain_addr_fill_from_key(&l_addr_from, a_priv_key, l_net->pub.id);

    uint256_t l_total = {};
    SUM_256_256(a_value, a_value_fee, &l_total);

    uint256_t l_value_found = {};
    dap_list_t *l_utxos_ledger = dap_ledger_get_utxo_for_value(
        l_net->pub.ledger, a_token_ticker, &l_addr_from, l_total, &l_value_found);
    if (!l_utxos_ledger) return NULL;

    dap_list_t *l_utxos = s_convert_utxo_list(l_utxos_ledger);
    dap_list_free_full(l_utxos_ledger, NULL);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create_cond_output(
        a_chain->net_id, &l_addr_from, a_pkey_cond_hash, a_token_ticker,
        a_value, a_value_per_unit_max, a_unit, a_srv_uid,
        a_value_fee, a_cond, a_cond_size, l_utxos);
    dap_list_free_full(l_utxos, NULL);

    if (!l_tx) return NULL;
    return s_sign_and_mempool_add(l_tx, a_priv_key, a_chain, "hex");
}

/**
 * @brief Create transaction from json file
 * com_tx_create command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 * 
 */
int com_tx_create_json(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int l_arg_index = 1;
    const char *l_net_name = NULL; // optional parameter
    const char *l_chain_name = NULL; // optional parameter
    const char *l_json_file_path = NULL;
    const char *l_json_str = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name); // optional parameter
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-json", &l_json_file_path);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx_obj", &l_json_str);

    if(!l_json_file_path  && !l_json_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_JSON,
                               "Command requires one of parameters '-json <json file path>' or -tx_obj <string>'");
        return DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_JSON;
    }
    // Open json file
    dap_json_t *l_json = NULL;
    if (l_json_file_path){
        l_json = dap_json_from_file(l_json_file_path);
        if(!l_json) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,
                                "Can't open json file");
            return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;
        }
    } else if (l_json_str) {
        l_json = dap_json_parse_string(l_json_str);
        if(!l_json) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE,
                                "Can't parse input JSON-string");
            return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_OPEN_JSON_FILE;
        }
    }
    if(!dap_json_is_object(l_json)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_JSON_FORMAT, "Wrong json format");
        dap_json_object_free(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_WRONG_JSON_FORMAT;
    }


    // Read network from json file
    if(!l_net_name) {
        dap_json_t *l_json_net = NULL;
        dap_json_object_get_ex(l_json, "net", &l_json_net);
        if(l_json_net && dap_json_is_string(l_json_net)) {
            l_net_name = dap_json_get_string(l_json_net);
        }
        if(!l_net_name) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_NET,
                                   "Command requires parameter '-net' or set net in the json file");
            dap_json_object_free(l_json);
            return DAP_CHAIN_NET_TX_CREATE_JSON_REQUIRE_PARAMETER_NET;
        }
    }
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply,
                               DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_BY_NAME,
                               "Not found net by name '%s'", l_net_name);
        dap_json_object_free(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_NET_BY_NAME;
    }
    dap_ledger_t *l_ledger = l_net->pub.ledger;

    // Read chain from json file
    if(!l_chain_name) {
        dap_json_t *l_json_chain = NULL;
        dap_json_object_get_ex(l_json, "chain", &l_json_chain);
        if(l_json_chain && dap_json_is_string(l_json_chain)) {
            l_chain_name = dap_json_get_string(l_json_chain);
        }
    }
    dap_chain_t *l_chain = NULL;
    if (l_chain_name) {
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    }
    if(!l_chain) {
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    }
    if(!l_chain) {
        dap_json_rpc_error_add(a_json_arr_reply,
                               DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_CHAIN_BY_NAME,
                               "Chain name '%s' not found, try use parameter '-chain' or set chain in the json file", l_chain_name);
        dap_json_object_free(l_json);
        return DAP_CHAIN_NET_TX_CREATE_JSON_NOT_FOUNT_CHAIN_BY_NAME;
    }


    // Read items from json file
    dap_json_t *l_jobj_errors = dap_json_array_new();
    size_t l_items_ready = 0, l_items_count = 0;
    dap_chain_datum_tx_t *l_tx = NULL;
    int l_ret = 0;
    if((l_ret = dap_chain_net_tx_create_by_json(l_json, l_net, l_jobj_errors, &l_tx, &l_items_count, &l_items_ready)) != DAP_CHAIN_NET_TX_CREATE_JSON_OK) {
        dap_json_rpc_error_add(a_json_arr_reply, l_ret,
                               "Can't create transaction from json file");
        return l_ret;
    }
    dap_json_t *l_jobj_ret = dap_json_object_new();

    if(l_items_ready < l_items_count) {
        dap_json_t *l_tx_create = dap_json_object_new_bool(false);
        dap_json_t *l_jobj_valid_items = dap_json_object_new_uint64(l_items_ready);
        dap_json_t *l_jobj_total_items = dap_json_object_new_uint64(l_items_count);
        dap_json_object_add_object(l_jobj_ret, "tx_create", l_tx_create);
        dap_json_object_add_object(l_jobj_ret, "valid_items", l_jobj_valid_items);
        dap_json_object_add_object(l_jobj_ret, "total_items", l_jobj_total_items);
        dap_json_object_add_object(l_jobj_ret, "errors", l_jobj_errors);
        dap_json_array_add(a_json_arr_reply, l_jobj_ret);
        DAP_DELETE(l_tx);
        return DAP_CHAIN_NET_TX_CREATE_JSON_INVALID_ITEMS;
    }
    dap_json_object_free(l_jobj_errors);

    // Pack transaction into the datum
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    size_t l_datum_tx_size = dap_chain_datum_size(l_datum_tx);
    DAP_DELETE(l_tx);

    // Add transaction to mempool
    char *l_tx_hash_str = dap_hash_sha3_256_data_to_str(l_datum_tx->data, l_datum_tx->header.data_size).s;
    dap_hash_sha3_256_t l_hf_tx = {0};
    dap_hash_sha3_256_from_str(l_tx_hash_str, &l_hf_tx);
    int rc = -1;
    if ((rc = dap_ledger_tx_add_check(l_net->pub.ledger, (dap_chain_datum_tx_t*)l_datum_tx->data, l_tx_size, &l_hf_tx))) {
        dap_json_t *l_jobj_tx_create = dap_json_object_new_bool(false);
        dap_json_t *l_jobj_hash = dap_json_object_new_string(l_tx_hash_str);
        dap_json_t *l_jobj_total_items = dap_json_object_new_uint64(l_items_count);
        dap_json_t *l_jobj_ledger_ret_code = dap_json_object_new();
        dap_json_object_add_int(l_jobj_ledger_ret_code, "code", rc);
        dap_json_object_add_object(l_jobj_ledger_ret_code, "message",
                               dap_json_object_new_string(dap_chain_net_verify_datum_err_code_to_str(l_datum_tx, rc)));
        dap_json_object_add_object(l_jobj_ret, "tx_create", l_jobj_tx_create);
        dap_json_object_add_object(l_jobj_ret, "hash", l_jobj_hash);
        dap_json_object_add_object(l_jobj_ret, "ledger_code", l_jobj_ledger_ret_code);
        dap_json_object_add_object(l_jobj_ret, "total_items", l_jobj_total_items);
        dap_json_array_add(a_json_arr_reply, l_jobj_ret);
        DAP_DEL_Z(l_datum_tx);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION;
    }

    char *l_gdb_group_mempool_base_tx = dap_chain_mempool_group_new(l_chain);// get group name for mempool
    bool l_placed = !dap_global_db_set(l_gdb_group_mempool_base_tx, l_tx_hash_str, l_datum_tx, l_datum_tx_size, false, NULL, NULL);

    DAP_DEL_Z(l_datum_tx);
    DAP_DELETE(l_gdb_group_mempool_base_tx);
    if(!l_placed) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL,
                               "Can't add transaction to mempool");
        return DAP_CHAIN_NET_TX_CREATE_JSON_CAN_NOT_ADD_TRANSACTION_TO_MEMPOOL;
    }
    // Completed successfully
    dap_json_t *l_jobj_tx_create = dap_json_object_new_bool(true);
    dap_json_t *l_jobj_hash = dap_json_object_new_string(l_tx_hash_str);
    dap_json_t *l_jobj_total_items = dap_json_object_new_uint64(l_items_count);
    dap_json_object_add_object(l_jobj_ret, "tx_create", l_jobj_tx_create);
    dap_json_object_add_object(l_jobj_ret, "hash", l_jobj_hash);
    dap_json_object_add_object(l_jobj_ret, "total_items", l_jobj_total_items);
    dap_json_array_add(a_json_arr_reply, l_jobj_ret);
    return DAP_CHAIN_NET_TX_CREATE_JSON_OK;
}

/**
 * @brief Create transaction
 * com_tx_create command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 * 
 */
int com_tx_create(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int arg_index = 1;
//    int cmd_num = 1;
//    const char *value_str = NULL;
    const char *addr_base58_to = NULL;
    const char * l_fee_str = NULL;
    const char * l_value_str = NULL;
    const char * l_from_wallet_name = NULL;
    const char * l_wallet_fee_name = NULL;
    const char * l_token_ticker = NULL;
    const char * l_net_name = NULL;
    const char * l_chain_name = NULL;
    const char * l_emission_chain_name = NULL;
    const char * l_tx_num_str = NULL;
    const char *l_emission_hash_str = NULL;
    const char *l_cert_str = NULL;
    const char *l_time_str = NULL;
    dap_cert_t *l_cert = NULL;
    dap_enc_key_t *l_priv_key = NULL;
    dap_hash_sha3_256_t l_emission_hash = {};
    size_t l_tx_num = 0;
    dap_chain_wallet_t * l_wallet_fee = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_HASH_INVALID, "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_HASH_INVALID;
    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NET_NOT_FOUND, "not found net by name '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NET_NOT_FOUND;
    }
    dap_ledger_t *l_ledger = l_net->pub.ledger;

    uint256_t *l_value = NULL;
    uint256_t l_value_fee = {};
    dap_chain_addr_t **l_addr_to = NULL;
    size_t l_addr_el_count = 0;
    size_t l_value_el_count = 0;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_wallet", &l_from_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-wallet_fee", &l_wallet_fee_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_emission", &l_emission_hash_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain_emission", &l_emission_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx_num", &l_tx_num_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-lock_before", &l_time_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_ticker);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_addr", &addr_base58_to);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_str);

    if(l_tx_num_str)
        l_tx_num = strtoul(l_tx_num_str, NULL, 10);

    // Validator's fee
    if (dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_str)) {
        if (!l_fee_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE, "tx_create requires parameter '-fee'");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE;
        }
        l_value_fee = dap_chain_balance_scan(l_fee_str);
    }
    if (IS_ZERO_256(l_value_fee) && (!l_emission_hash_str || (l_fee_str && strcmp(l_fee_str, "0")))) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE_IS_UINT256, "tx_create requires parameter '-fee' to be valid uint256");
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_FEE_IS_UINT256;
    }

    if((!l_from_wallet_name && !l_emission_hash_str)||(l_from_wallet_name && l_emission_hash_str)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_WALLET_OR_FROM_EMISSION, "tx_create requires one of parameters '-from_wallet' or '-from_emission'");
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_WALLET_OR_FROM_EMISSION;
    }

    dap_chain_t *l_chain = NULL;
    if (l_chain_name) {
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
    } else {
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_TX);
    }

    if(!l_chain) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NOT_FOUND_CHAIN,
                               "not found chain name '%s', try use parameter '-chain' or set default datum type in chain configuration file",
                l_chain_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NOT_FOUND_CHAIN;
    }

    dap_chain_t *l_emission_chain = NULL;
    if (l_emission_hash_str) {
        if (dap_hash_sha3_256_from_str(l_emission_hash_str, &l_emission_hash)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_EMISSION,
                                   "tx_create requires parameter '-from_emission' "
                                   "to be valid string containing hash in hex or base58 format");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_EMISSION;
        }
        if (l_emission_chain_name) {
            l_emission_chain = dap_chain_net_get_chain_by_name(l_net, l_emission_chain_name);
        } else {
            l_emission_chain = dap_chain_net_get_default_chain_by_chain_type(l_net,CHAIN_TYPE_EMISSION);
        }
        if (!l_emission_chain) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_CHAIN_EMISSION,
                                   "tx_create requires parameter '-chain_emission' "
                                   "to be a valid chain name or set default datum type in chain configuration file");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_FROM_CHAIN_EMISSION;
        }

        if (l_wallet_fee_name){
            // Use wallet get_key callback
            if (!dap_chain_wallet_get_path(g_config)) {
                dap_json_rpc_error_add(a_json_arr_reply, -20,
                    "Wallet signing function not available (wallet module not loaded)");
                return -20;
            }
            l_priv_key = s_wallet_get_key(l_wallet_fee_name);
            if (!l_priv_key) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_WALLET_FEE,
                                       "Can't get key from wallet %s", l_wallet_fee_name);
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_WALLET_FEE;
            }
        } else if (l_cert_str) {
            l_cert = dap_cert_find_by_name(l_cert_str);
            if (!l_cert) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CERT_IS_INVALID, "Certificate %s is invalid", l_cert_str);
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CERT_IS_INVALID;
            }
            l_priv_key = l_cert->enc_key;
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_CERT_OR_WALLET_FEE,
                                              "tx_create requires parameter '-cert' or '-wallet_fee' for create base tx for emission");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_CERT_OR_WALLET_FEE;
        }
    } else {
        size_t l_time_el_count = 0;
        if (!l_token_ticker) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_TOKEN, "tx_create requires parameter '-token'");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_TOKEN;
        }
        if (!dap_ledger_token_ticker_check(l_net->pub.ledger, l_token_ticker)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_TOKEN_NOT_DECLARATED_IN_NET,
                                   "Ticker '%s' is not declared on network '%s'.", l_token_ticker, l_net_name);
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_TOKEN_NOT_DECLARATED_IN_NET;
        }
        if (!addr_base58_to) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_TO_ADDR, "tx_create requires parameter '-to_addr'");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_TO_ADDR;
        }
        if (!l_value_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE, "tx_create requires parameter '-value' to be valid uint256 value");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE;
        }
        l_addr_el_count = dap_str_symbol_count(addr_base58_to, ',') + 1;
        l_value_el_count = dap_str_symbol_count(l_value_str, ',') + 1;
        if (l_time_str)
            l_time_el_count = dap_str_symbol_count(l_time_str, ',') + 1;

        if ((l_addr_el_count != l_value_el_count) || (l_time_str && l_time_el_count != l_value_el_count)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE, "num of '-to_addr', '-value' and '-lock_before' should be equal");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE;
        }

        l_value = DAP_NEW_Z_COUNT(uint256_t, l_value_el_count);
        if (!l_value) {
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_MEMORY_ERR"), c_error_memory_alloc);
            return dap_cli_error_code_get("LEDGER_MEMORY_ERR");
        }
        char **l_value_array = dap_strsplit(l_value_str, ",", l_value_el_count);
        if (!l_value_array) {
            DAP_DELETE(l_value);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR, "Can't read '-to_addr' arg");
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }
        for (size_t i = 0; i < l_value_el_count; ++i) {
            l_value[i] = dap_chain_balance_scan(l_value_array[i]);
            if(IS_ZERO_256(l_value[i])) {
                DAP_DEL_MULTY(l_value_array, l_value);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE, "tx_create requires parameter '-value' to be valid uint256 value");
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_REQUIRE_PARAMETER_VALUE_OR_INVALID_FORMAT_VALUE;
            }
        }
        dap_strfreev(l_value_array);
    
        l_addr_to = DAP_NEW_Z_COUNT(dap_chain_addr_t *, l_addr_el_count);
        if (!l_addr_to) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_value);
            dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_code_get("LEDGER_MEMORY_ERR"), c_error_memory_alloc);
            return dap_cli_error_code_get("LEDGER_MEMORY_ERR");
        }
        char **l_addr_base58_to_array = dap_strsplit(addr_base58_to, ",", l_addr_el_count);
        if (!l_addr_base58_to_array) {
            DAP_DEL_MULTY(l_addr_to, l_value);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR, "Can't read '-to_addr' arg");
            return DAP_CHAIN_NODE_CLI_COM_GLOBAL_DB_PARAM_ERR;
        }
        for (size_t i = 0; i < l_addr_el_count; ++i) {
            l_addr_to[i] = dap_chain_addr_from_str(l_addr_base58_to_array[i]);
            if(!l_addr_to[i]) {
                DAP_DEL_ARRAY(l_addr_to, i);
                DAP_DEL_MULTY(l_addr_to, l_value);
                dap_strfreev(l_addr_base58_to_array);  
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_ADDRESS_INVALID, "destination address is invalid");
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_ADDRESS_INVALID;
            }
            if(!dap_chain_net_is_bridged(l_net, l_addr_to[i]->net_id)) {
                DAP_DEL_ARRAY(l_addr_to, i);
                DAP_DEL_MULTY(l_addr_to, l_value);
                dap_strfreev(l_addr_base58_to_array);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_ADDRESS_INVALID, "destination source network is not bridget with recepient network");
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_ADDRESS_INVALID;
            }
        }
        dap_strfreev(l_addr_base58_to_array);
    }

    int l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_OK;
    if (l_emission_hash_str) {
        char *l_tx_hash_str = NULL;
        if (!l_priv_key) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NO_PRIVATE_KEY_DEFINED, "No private key defined for creating the underlying "
                                                   "transaction no '-wallet_fee' or '-cert' parameter specified.");
            l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_NO_PRIVATE_KEY_DEFINED;
        }
        if (!l_token_ticker) {
            dap_chain_datum_token_emission_t *l_emi = dap_ledger_token_emission_find(l_ledger, &l_emission_hash);
            if (l_emi)
                l_token_ticker = l_emi->hdr.ticker;
        }
        uint256_t l_emi_value = uint256_0;
        if (l_value_str)
            l_emi_value = dap_chain_balance_scan(l_value_str);
        dap_chain_addr_t *l_emi_addr_to = NULL;
        if (addr_base58_to)
            l_emi_addr_to = dap_chain_addr_from_str(addr_base58_to);
        l_tx_hash_str = s_mempool_base_tx_create(l_chain, &l_emission_hash, l_emission_chain->id,
                                                 l_emi_value, l_token_ticker, l_emi_addr_to,
                                                 l_priv_key, l_hash_out_type, l_value_fee);
        DAP_DELETE(l_emi_addr_to);
        dap_json_t *l_jobj_emission = dap_json_object_new();
        dap_json_t *l_jobj_emi_status = NULL;
        dap_json_t *l_jobj_emi_hash = NULL;
        if (l_tx_hash_str) {
            l_jobj_emi_status = dap_json_object_new_string("Ok");
            l_jobj_emi_hash = dap_json_object_new_string(l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
            dap_json_object_add_object(l_jobj_emission, "emission", l_jobj_emi_status);
            dap_json_object_add_object(l_jobj_emission, "hash", l_jobj_emi_hash);
        } else {
            l_jobj_emi_status = dap_json_object_new_string("False");
            dap_json_object_add_object(l_jobj_emission, "emission", l_jobj_emi_status);
            dap_json_t *l_jobj_msg = dap_json_object_new_string("Can't place TX datum in mempool, examine log files\n");
            dap_json_object_add_object(l_jobj_emission, "message", l_jobj_msg);
            l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_ADD_DATUM_IN_MEMPOOL;
        }
        dap_json_array_add(a_json_arr_reply, l_jobj_emission);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        // Wallet callback - no need to close wallet
        if (l_priv_key && l_wallet_fee_name) {
            dap_enc_key_delete(l_priv_key);
        }
        return l_ret;        
    }

    // Check wallet using callback
    if (!dap_chain_wallet_get_path(g_config)) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_CHECK_SIGN_FUNC),
            "%s", dap_cli_error_get_str(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_CHECK_SIGN_FUNC));
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_CHECK_SIGN_FUNC);
    }
    const char *l_wallet_check_str = (s_wallet_open(l_from_wallet_name) ? "ok" : NULL);
    if (!l_wallet_check_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WALLET_DOES_NOT_EXIST,
                               "wallet %s does not exist", l_from_wallet_name);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WALLET_DOES_NOT_EXIST;
    }
    
    dap_json_t *l_jobj_result = dap_json_object_new();
    if (dap_strcmp(l_wallet_check_str, "") != 0) {
        dap_json_t *l_obj_wgn_str = dap_json_object_new_string(l_wallet_check_str);
        dap_json_object_add_object(l_jobj_result, "warning", l_obj_wgn_str);
    }
    
    // Get addr from wallet using callback
    if (!dap_chain_wallet_get_path(g_config)) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC),
            "%s", dap_cli_error_get_str(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC));
        dap_json_object_free(l_jobj_result);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_GET_ADDR_FUNC);
    }
    dap_chain_addr_t *l_addr_from = s_wallet_get_addr(l_from_wallet_name, l_ledger->net_id);

    if(!l_addr_from) {
        // Wallet callback - no need to close wallet
        if (l_priv_key && l_wallet_fee_name) {
            dap_enc_key_delete(l_priv_key);
        }
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_SOURCE_ADDRESS_INVALID, "source address is invalid");
        dap_json_object_free(l_jobj_result);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_SOURCE_ADDRESS_INVALID;
    }

    for (size_t i = 0; i < l_addr_el_count; ++i) {
        if (dap_chain_addr_compare(l_addr_to[i], l_addr_from)) {
            // Wallet callback - no need to close wallet
            if (l_priv_key && l_wallet_fee_name) {
                dap_enc_key_delete(l_priv_key);
            }
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_EQ_SOURCE_DESTINATION_ADDRESS, "The transaction cannot be directed to the same address as the source.");
            dap_json_object_free(l_jobj_result);
            DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
            DAP_DEL_MULTY(l_addr_to, l_value);
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_EQ_SOURCE_DESTINATION_ADDRESS;
        }
    }

    for (size_t i = 0; i < l_addr_el_count; ++i) {
        if (l_addr_to[i]->net_id.uint64 != l_net->pub.id.uint64 && !dap_chain_addr_is_blank(l_addr_to[i])) {
            bool l_found = false;
            for (size_t j = 0; j < l_net->pub.bridged_networks_count; ++j) {
                if (l_net->pub.bridged_networks[j].uint64 == l_addr_to[i]->net_id.uint64) {
                    l_found = true;
                    break;
                }
            }
            if (!l_found) {
                dap_string_t *l_allowed_list = dap_string_new("");
                dap_string_append_printf(l_allowed_list, "0x%016"DAP_UINT64_FORMAT_X, l_net->pub.id.uint64);
                for (size_t j = 0; j < l_net->pub.bridged_networks_count; ++j)
                    dap_string_append_printf(l_allowed_list, ", 0x%016"DAP_UINT64_FORMAT_X, l_net->pub.bridged_networks[j].uint64);
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_NETWORK_IS_UNREACHEBLE,
                                    "Destination network ID=0x%"DAP_UINT64_FORMAT_x
                                    " is unreachable. List of available network IDs:\n%s"
                                    " Please, change network name or wallet address",
                                    l_addr_to[i]->net_id.uint64, l_allowed_list->str);
                dap_string_free(l_allowed_list, true);
                dap_json_object_free(l_jobj_result);

                DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
                DAP_DEL_MULTY(l_addr_to, l_value);
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_DESTINATION_NETWORK_IS_UNREACHEBLE;
            }
        }
    }
    dap_time_t *l_time_unlock = NULL;
    if (l_time_str) {
        l_time_unlock = DAP_NEW_Z_COUNT(dap_time_t, l_value_el_count);
        if (!l_time_unlock) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_MEMORY_ERR, "Can't allocate memory");
            DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
            DAP_DEL_MULTY(l_addr_to, l_value);
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_MEMORY_ERR;
        }
        char **l_time_unlock_array = dap_strsplit(l_time_str, ",", l_value_el_count);
        if (!l_time_unlock_array) {
            DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
            DAP_DEL_MULTY(l_addr_to, l_value, l_time_unlock);
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WRONG_TIME_FORMAT, "Can't read '-lock_before' arg");
            return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WRONG_TIME_FORMAT;
        }
        for (size_t i = 0; i < l_value_el_count; ++i) {
            if (l_time_unlock_array[i] && !dap_strcmp(l_time_unlock_array[i], "0")) {
                l_time_unlock[i] = 0;
                continue;
            }
            if (!(l_time_unlock[i] = dap_time_from_str_simplified(l_time_unlock_array[i])) && !(l_time_unlock[i] = dap_time_from_str_rfc822(l_time_unlock_array[i]))) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WRONG_TIME_FORMAT, "Wrong time format. Parameter -lock_before must be in format \"Day Month Year HH:MM:SS Timezone\" e.g. \"19 August 2024 22:00:00 +0300\"");
                DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
                DAP_DEL_MULTY(l_addr_to, l_value, l_time_unlock);       
                dap_strfreev(l_time_unlock_array);
                return DAP_CHAIN_NODE_CLI_COM_TX_CREATE_WRONG_TIME_FORMAT;
            }
        }
        dap_strfreev(l_time_unlock_array);
    }

    dap_json_t *l_jobj_transfer_status = NULL;
    dap_json_t *l_jobj_tx_hash = NULL;

    // Get key from wallet using callback
    if (!dap_chain_wallet_get_path(g_config)) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC),
            "%s", dap_cli_error_get_str(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC));
        dap_json_object_free(l_jobj_result);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC);
    }
    l_priv_key = s_wallet_get_key(l_from_wallet_name);
    if (!l_priv_key) {
        dap_json_rpc_error_add(a_json_arr_reply, dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_MEMORY_ALLOC),
            "Can't get key from wallet %s", l_from_wallet_name);
        dap_json_object_free(l_jobj_result);
        DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
        DAP_DEL_MULTY(l_addr_to, l_value);
        return dap_cli_error_get_code(DAP_LEDGER_CLI_ERROR_MEMORY_ALLOC);
    }
    if(l_tx_num){
        l_ret = s_mempool_tx_create_massive(l_chain, l_priv_key, l_addr_from,
                                            l_addr_to[0], l_token_ticker, l_value[0], l_value_fee, l_tx_num);
        l_jobj_transfer_status = dap_json_object_new_string((l_ret == 0) ? "Ok" : (l_ret == -2) ? "False, not enough funds for transfer" : "False");
        dap_json_object_add_object(l_jobj_result, "transfer", l_jobj_transfer_status);
    } else {
        char *l_tx_hash_str = s_mempool_tx_create(l_chain, l_priv_key, l_addr_from, (const dap_chain_addr_t **)l_addr_to,
                                                  l_token_ticker, l_value, l_value_fee, l_hash_out_type, l_addr_el_count, l_time_unlock);
        if (l_tx_hash_str) {
            l_jobj_transfer_status = dap_json_object_new_string("Ok");
            l_jobj_tx_hash = dap_json_object_new_string(l_tx_hash_str);
            dap_json_object_add_object(l_jobj_result, "transfer", l_jobj_transfer_status);
            dap_json_object_add_object(l_jobj_result, "hash", l_jobj_tx_hash);
            DAP_DELETE(l_tx_hash_str);
        } else {
            l_jobj_transfer_status = dap_json_object_new_string("False");
            dap_json_object_add_object(l_jobj_result, "transfer", l_jobj_transfer_status);
            l_ret = DAP_CHAIN_NODE_CLI_COM_TX_CREATE_CAN_NOT_CREATE_TRANSACTION;
        }
    }
    dap_json_array_add(a_json_arr_reply, l_jobj_result);

    DAP_DEL_ARRAY(l_addr_to, l_addr_el_count);
    DAP_DEL_MULTY(l_addr_from, l_addr_to, l_value);
    // Wallet callback - no need to close wallet
    dap_enc_key_delete(l_priv_key);
    return l_ret;
}


/* com_mempool_add removed - it already exists in dap_chain_mempool_cli.c */



/**
 * @brief com_tx_verify
 * Verifing transaction
 * tx_verify command
 * @param argc
 * @param argv
 * @param arg_func
 * @param str_reply
 * @return int
 */
int com_tx_verify(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    const char * l_tx_hash_str = NULL;
    dap_chain_net_t * l_net = NULL;
    dap_chain_t * l_chain = NULL;
    int l_arg_index = 1;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-tx", &l_tx_hash_str);
    if(!l_tx_hash_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_REQUIRE_PARAMETER_TX, "tx_verify requires parameter '-tx'");
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_REQUIRE_PARAMETER_TX;
    }
    dap_chain_node_cli_cmd_values_parse_net_chain_for_json(a_json_arr_reply, &l_arg_index, a_argc, a_argv, &l_chain, &l_net,
                                                           CHAIN_TYPE_TX);
    if (!l_net || !l_chain) {
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_NET_CHAIN_UNDEFINED;
    }
    dap_hash_sha3_256_t l_tx_hash;
    char *l_hex_str_from58 = NULL;
    if (dap_hash_sha3_256_from_hex_str(l_tx_hash_str, &l_tx_hash)) {
        l_hex_str_from58 = dap_enc_base58_to_hex_str_from_str(l_tx_hash_str);
        if (dap_hash_sha3_256_from_hex_str(l_hex_str_from58, &l_tx_hash)) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_INVALID_TX_HASH, "Invalid tx hash format, need hex or base58");
            return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_INVALID_TX_HASH;
        }
    }
    size_t l_datum_size = 0;
    char *l_gdb_group = dap_chain_mempool_group_new(l_chain);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t*)dap_global_db_get_sync(l_gdb_group, l_hex_str_from58 ? l_hex_str_from58 : l_tx_hash_str, &l_datum_size, NULL, NULL);
    DAP_DEL_Z(l_hex_str_from58);
    if (!l_datum) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_SPECIFIED_TX_NOT_FOUND, "Specified tx not found");
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_SPECIFIED_TX_NOT_FOUND;
    }
    if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX){
        char *l_str_err = dap_strdup_printf("Based on the specified hash, the type %s was found and not a transaction.",
                                            dap_chain_datum_type_id_to_str(l_datum->header.type_id));
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_HASH_IS_NOT_TX_HASH, l_str_err);
        DAP_DELETE(l_str_err);
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_HASH_IS_NOT_TX_HASH;
    }
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*)l_datum->data;
    int l_ret = dap_ledger_tx_add_check(l_net->pub.ledger, l_tx, l_datum->header.data_size, &l_tx_hash);
    dap_json_t *l_obj_ret = dap_json_object_new();
    dap_json_t *l_obj_hash = dap_json_object_new_string(l_tx_hash_str);
    dap_json_object_add_object(l_obj_ret, "hash", l_obj_hash);
    dap_json_t *l_jobj_verfiy = NULL;
    dap_json_t *l_jobj_error = NULL;
    if (l_ret) {
        l_jobj_verfiy = dap_json_object_new_bool(false);
        l_jobj_error = dap_json_object_new();
        dap_json_t *l_jobj_err_str = dap_json_object_new_string(dap_ledger_check_error_str(l_ret));
        dap_json_t *l_jobj_err_code = dap_json_object_new_int64(l_ret);
        dap_json_object_add_object(l_jobj_error, "code", l_jobj_err_code);
        dap_json_object_add_object(l_jobj_error, "message", l_jobj_err_str);
        dap_json_object_add_object(l_obj_ret, "verify", l_jobj_verfiy);
        dap_json_object_add_object(l_obj_ret, "error", l_jobj_error);
        dap_json_array_add(a_json_arr_reply, l_obj_ret);
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_TX_NOT_VERIFY;
    } else {
        l_jobj_verfiy = dap_json_object_new_bool(true);
        l_jobj_error = dap_json_object_new();
        dap_json_object_add_object(l_obj_ret, "verify", l_jobj_verfiy);
        dap_json_object_add_object(l_obj_ret, "error", l_jobj_error);
        dap_json_array_add(a_json_arr_reply, l_obj_ret);
        return DAP_CHAIN_NODE_CLI_COM_TX_VERIFY_OK;
    }
}


/**
 * @brief com_tx_history
 * tx_history command
 * Transaction history for an address
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return int
 */
int com_tx_history(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int arg_index = 1;
    const char *l_addr_base58 = NULL;
    const char *l_wallet_name = NULL;
    const char *l_net_str = NULL;
    const char *l_chain_str = NULL;
    const char *l_tx_hash_str = NULL;
    const char *l_tx_srv_str = NULL;
    const char *l_tx_act_str = NULL;
    const char *l_limit_str = NULL;
    const char *l_offset_str = NULL;
    const char *l_head_str = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_net_t * l_net = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;

    }

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_base58);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_name);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-chain", &l_chain_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-tx", &l_tx_hash_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv", &l_tx_srv_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-act", &l_tx_act_str);

    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
    bool l_head = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-head", &l_head_str) ? true : false;
    size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 1000;
    size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;

    //default is ALL/ANY
    dap_chain_tx_tag_action_type_t l_action = l_tx_act_str ? dap_ledger_tx_action_str_to_action_t(l_tx_act_str):
                                     DAP_CHAIN_TX_TAG_ACTION_ALL;

    bool l_brief = (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "-brief") != -1) ? true : false;

    bool l_is_tx_all = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-all", NULL);
    bool l_is_tx_count = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-count", NULL);

    if (!l_addr_base58 && !l_wallet_name && !l_tx_hash_str && !l_is_tx_all && !l_is_tx_count) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx_history requires parameter '-addr' or '-w' or '-tx'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    if (!l_net_str && !l_addr_base58&& !l_is_tx_all) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR,
                                "tx_history requires parameter '-net' or '-addr'");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_PARAM_ERR;
    }

    dap_hash_sha3_256_t l_tx_hash;
    if (l_tx_hash_str && dap_hash_sha3_256_from_str(l_tx_hash_str, &l_tx_hash) != 0) {

        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR, "tx hash not recognized");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_HASH_REC_ERR;
    }

    // Select chain network
    if (!l_addr_base58 && l_net_str) {
        l_net = dap_chain_net_by_name(l_net_str);
        if (!l_net) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR,
                                    "tx_history requires parameter '-net' to be valid chain network name");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR;
        }
    }
    // Get chain address
    dap_chain_addr_t *l_addr = NULL;
    if (l_addr_base58) {
        if (l_tx_hash_str) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR,
                                                        "Incompatible params '-addr' & '-tx'");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_INCOMPATIBLE_PARAMS_ERR;
        }
        l_addr = dap_chain_addr_from_str(l_addr_base58);
        if (!l_addr) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR,
                                                        "Wallet address not recognized");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ADDR_ERR;
        }
        if (l_net) {
            if (l_net->pub.id.uint64 != l_addr->net_id.uint64) {
                dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR,
                                        "Network ID with '-net' param and network ID with '-addr' param are different");
                DAP_DELETE(l_addr);
                return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ID_NET_ADDR_DIF_ERR;
            }
        } else
            l_net = dap_chain_net_by_id(l_addr->net_id);
    }
    if (l_wallet_name) {
        if (!l_net) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR,
                "Network must be specified with '-net' when using '-w'");
            if (l_addr) DAP_DELETE(l_addr);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_PARAM_ERR;
        }
        dap_chain_addr_t *l_addr_tmp = s_wallet_get_addr(l_wallet_name, l_net->pub.id);
        if (l_addr_tmp) {
            if (l_addr) {
                if (!dap_chain_addr_compare(l_addr, l_addr_tmp)) {
                    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR,
                                            "Address with '-addr' param and address with '-w' param are different");
                    DAP_DELETE(l_addr);
                    DAP_DELETE(l_addr_tmp);
                    return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_ADDR_WALLET_DIF_ERR;
                }
                DAP_DELETE(l_addr_tmp);
            } else {
                l_addr = l_addr_tmp;
            }
        } else {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR,
                                    "The wallet %s is not activated or it doesn't exist", l_wallet_name);
            if (l_addr) DAP_DELETE(l_addr);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_WALLET_ERR;
        }
    }
    // Select chain, if any
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR, "Could not determine the network from which to "
                                                       "extract data for the tx_history command to work.");
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_NET_ERR;
    }
    if (l_chain_str)
        l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_str);
    else
        l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);

    if(!l_chain) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR,
                                "tx_history requires parameter '-chain' to be valid chain name in chain net %s."
                                " You can set default datum type in chain configuration file", l_net_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_CHAIN_PARAM_ERR;
    }
    // response
    dap_json_t *json_obj_out = NULL;
    if (l_tx_hash_str) {
         // history tx hash
        json_obj_out = dap_db_history_tx(a_json_arr_reply, &l_tx_hash, l_chain, l_hash_out_type, l_net->pub.ledger, a_version);
        if (!json_obj_out) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR,
                                    "something went wrong in tx_history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_TX_ERR;
        }
    } else if (l_addr) {
        // history addr and wallet
        dap_json_t *json_obj_summary = dap_json_object_new();
        if (!json_obj_summary) {
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR;
        }
        json_obj_out = dap_db_history_addr(a_json_arr_reply, l_addr, l_chain, l_net->pub.ledger, l_hash_out_type, dap_chain_addr_to_str_static(l_addr), json_obj_summary, l_limit, l_offset, l_brief, l_tx_srv_str, l_action, l_head, a_version);
        if (!json_obj_out) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR,
                                    "something went wrong in tx_history");
            dap_json_object_free(json_obj_summary);
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ADDR_ERR;
        }
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        dap_json_array_add(a_json_arr_reply, json_obj_summary);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    } else if (l_is_tx_all) {
        // history all
        dap_json_t * json_obj_summary = dap_json_object_new();
        if (!json_obj_summary) {
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_MEMORY_ERR;
        }

        dap_json_t *json_arr_history_all = dap_db_history_tx_all(a_json_arr_reply, l_chain, l_net, l_hash_out_type, json_obj_summary,
                                                                l_limit, l_offset, l_brief, l_tx_srv_str, l_action, l_head, a_version);
        if (!json_arr_history_all) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR,
                                    "something went wrong in tx_history");
            return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_DAP_DB_HISTORY_ALL_ERR;
        }
        dap_json_array_add(a_json_arr_reply, json_arr_history_all);
        dap_json_array_add(a_json_arr_reply, json_obj_summary);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    } else if (l_is_tx_count) {
        dap_json_t * json_count_obj= dap_json_object_new();
        dap_json_object_add_uint64(json_count_obj, "number_of_transaction", l_chain->callback_count_tx(l_chain));
        dap_json_array_add(a_json_arr_reply, json_count_obj);
        return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
    }

    if (json_obj_out) {
        const char *json_string_sdfasf = dap_json_to_string(a_json_arr_reply);
        char *result_string_sadfasf = strdup(json_string_sdfasf);
        dap_json_array_add(a_json_arr_reply, json_obj_out);
        const char *json_string = dap_json_to_string(a_json_arr_reply);
        char* result_string = strdup(json_string);
    } else {
        dap_json_array_add(a_json_arr_reply, dap_json_object_new_string("empty"));
    }

    return DAP_CHAIN_NODE_CLI_COM_TX_HISTORY_OK;
}

/**
 * @brief com_tx_cond_create
 * Create transaction
 * com_tx_cond_create command
 * @param a_argc
 * @param a_argv
 * @param a_str_reply
 * @return int
 */
int com_tx_cond_create(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int arg_index = 1;
    const char * l_token_ticker = NULL;
    const char * l_wallet_str = NULL;
    const char * l_cert_str = NULL;
    const char * l_value_str = NULL;
    const char * l_value_fee_str = NULL;
    const char * l_net_name = NULL;
    const char * l_unit_str = NULL;
    const char * l_srv_uid_str = NULL;
    const char * l_pkey_str = NULL;
    uint256_t l_value_datoshi = {};
    uint256_t l_value_fee = {};
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_INVALID_PARAMETER_HEX,
                               "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_INVALID_PARAMETER_HEX;
    }

    // Token ticker
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-token", &l_token_ticker);
    // Wallet name - from
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    // Public certifiacte of condition owner
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_str);
    // value datoshi
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_str);
    // fee
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_value_fee_str);
    // net
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // unit
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unit", &l_unit_str);
    // service
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);
    // pkey_hash
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-pkey", &l_pkey_str);

    if(!l_token_ticker) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_TOKEN, "tx_cond_create requires parameter '-token'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_TOKEN;
    }
    if (!l_wallet_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_W, "tx_cond_create requires parameter '-w'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_W;
    }
    if (!l_cert_str && !l_pkey_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_CERT, "tx_cond_create requires parameter '-cert' or '-pkey'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_CERT;
    }
    if (!l_value_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_VALUE, "tx_cond_create requires parameter '-value'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_VALUE;
    }
    if(!l_value_fee_str){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_FEE, "tx_cond_create requires parameter '-fee'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_FEE;
    }
    if(!l_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_NET, "tx_cond_create requires parameter '-net'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_NET;
    }
    if(!l_unit_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_UNIT, "tx_cond_create requires parameter '-unit'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_UNIT;
    }

    if(!l_srv_uid_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_SRV_UID, "tx_cond_create requires parameter '-srv_uid'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_REQUIRES_PARAMETER_SRV_UID;
    }
    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_SERVICE_UID, "Can't find service UID %s ", l_srv_uid_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_SERVICE_UID;
    }

    dap_chain_net_srv_price_unit_uid_t l_price_unit = { .enm = dap_chain_srv_str_to_unit_enum((char*)l_unit_str)};

    if(l_price_unit.enm == SERV_UNIT_UNDEFINED) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_UNIT,
                               "Can't recognize unit '%s'. Unit must look like { B | SEC }", l_unit_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_UNIT;
    }

    l_value_datoshi = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value_datoshi)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE,
                               "Can't recognize value '%s' as a number", l_value_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE;
    }

    l_value_fee = dap_chain_balance_scan(l_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE_FEE,
                               "Can't recognize value '%s' as a number", l_value_fee_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_RECOGNIZE_VALUE_FEE;
    }

    dap_ledger_t *l_ledger = l_net_name ? dap_ledger_find_by_name(l_net_name) : NULL;
    dap_chain_net_t *l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_NET, "Can't find net '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_FIND_NET;
    }

    dap_hash_sha3_256_t l_pkey_cond_hash = {};
    if (l_cert_str) {
        dap_cert_t *l_cert_cond = dap_cert_find_by_name(l_cert_str);
        if(!l_cert_cond) {
            dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_FIND_CERT, "Can't find cert '%s'", l_cert_str);
            return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_FIND_CERT;
        }
        dap_cert_get_pkey_hash(l_cert_cond, DAP_HASH_TYPE_SHA3_256, l_pkey_cond_hash.raw, sizeof(dap_hash_sha3_256_t));
    } else {
        dap_hash_sha3_256_from_str(l_pkey_str, &l_pkey_cond_hash);
    }
    if (dap_hash_sha3_256_is_blank(&l_pkey_cond_hash)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_FIND_CERT, "Can't calc pkey hash");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_FIND_CERT;
    }

    if (!l_ledger || !dap_chain_wallet_get_path(g_config)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC,
            "Wallet signing function not available");
        return DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC;
    }
    dap_enc_key_t *l_key_from = s_wallet_get_key(l_wallet_str);
    if (!l_key_from) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_OPEN_WALLET, 
            "Can't get key from wallet '%s'", l_wallet_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_OPEN_WALLET;
    }

    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_CONDITIONAL_TX_CREATE,
            "No TX chain found in network");
        dap_enc_key_delete(l_key_from);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_CONDITIONAL_TX_CREATE;
    }
    uint256_t l_value_per_unit_max = {};
    char *l_hash_str = s_mempool_tx_create_cond(l_chain, l_key_from, &l_pkey_cond_hash, l_token_ticker,
                                                l_value_datoshi, l_value_per_unit_max, l_price_unit,
                                                l_srv_uid, l_value_fee, NULL, 0);
    dap_enc_key_delete(l_key_from);

    if (l_hash_str) {
        dap_json_t *l_jobj_ret = dap_json_object_new();
        dap_json_t *l_jobj_tx_cond_transfer = dap_json_object_new_bool(true);
        dap_json_t *l_jobj_hash = dap_json_object_new_string(l_hash_str);
        dap_json_object_add_object(l_jobj_ret, "create_tx_cond", l_jobj_tx_cond_transfer);
        dap_json_object_add_object(l_jobj_ret, "hash", l_jobj_hash);
        dap_json_array_add(a_json_arr_reply, l_jobj_ret);
        DAP_DELETE(l_hash_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_OK;
    }
    dap_json_t *l_jobj_ret = dap_json_object_new();
    dap_json_t *l_jobj_tx_cond_transfer = dap_json_object_new_bool(false);
    dap_json_object_add_object(l_jobj_ret, "create_tx_cond", l_jobj_tx_cond_transfer);
    dap_json_array_add(a_json_arr_reply, l_jobj_ret);
    return DAP_CHAIN_NODE_CLI_COM_TX_COND_CREATE_CAN_NOT_CONDITIONAL_TX_CREATE;
}

static dap_list_t* s_hashes_parse_str_list(const char *a_hashes_str)
{
    dap_list_t *l_ret_list = NULL;
    char *l_hash_str_dup = strdup(a_hashes_str), *l_hash_str, *l_hashes_tmp_ptrs = NULL;
    if (!l_hash_str_dup)
        return log_it(L_CRITICAL, "%s", c_error_memory_alloc), NULL;
    dap_hash_sha3_256_t l_hash = { };
    while (( l_hash_str = strtok_r(l_hash_str_dup, ",", &l_hashes_tmp_ptrs) )) {
        l_hash_str = dap_strstrip(l_hash_str);
        if (dap_hash_sha3_256_from_str(l_hash_str, &l_hash)){
            log_it(L_ERROR, "Can't get hash of string \"%s\". Continue.", l_hash_str);
            continue;
        }
        l_ret_list = dap_list_append(l_ret_list, DAP_DUP(&l_hash));
    }
    DAP_DELETE(l_hash_str_dup);
    return l_ret_list;
}

int com_tx_cond_remove(int a_argc, char ** a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void) a_argc;
    int arg_index = 1;
    const char * l_wallet_str = NULL;
    const char * l_value_fee_str = NULL;
    const char * l_net_name = NULL;
    const char * l_hashes_str = NULL;
    const char * l_srv_uid_str = NULL;
    uint256_t l_value_datoshi = {};
    uint256_t l_value_fee = {};
    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_INVALID_PARAMETER_HEX,
                               "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_INVALID_PARAMETER_HEX;
    }

    // Wallet name
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    // fee
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_value_fee_str);
    // net
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // tx cond hahses
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hashes", &l_hashes_str);
    // srv_uid
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);

    if (!l_wallet_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_W, "com_txs_cond_remove requires parameter '-w'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_W;
    }
    if(!l_value_fee_str){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_FEE, "com_txs_cond_remove requires parameter '-fee'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_FEE;
    }
    if(!l_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_NET, "com_txs_cond_remove requires parameter '-net'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_NET;
    }
    if(!l_hashes_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_HASHES, "com_txs_cond_remove requires parameter '-hashes'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_HASHES;
    }
    if(!l_srv_uid_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_SRV_UID, "com_txs_cond_remove requires parameter '-srv_uid'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUIRES_PARAMETER_SRV_UID;
    }

    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_SERVICE_UID, "Can't find service UID %s ", l_srv_uid_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_SERVICE_UID;
    }

    dap_ledger_t *l_ledger = l_net_name ? dap_ledger_find_by_name(l_net_name) : NULL;
    dap_chain_net_t *l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NET, "Can't find net '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NET;
    }
    
    if (!l_ledger || !dap_chain_wallet_get_path(g_config)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC,
            "Wallet signing function not available");
        return DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC;
    }
    dap_enc_key_t *l_key_from = s_wallet_get_key(l_wallet_str);
    if (!l_key_from) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_OPEN_WALLET, 
            "Can't get key from wallet '%s'", l_wallet_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_OPEN_WALLET;
    }

    dap_pkey_t *l_wallet_pkey = dap_pkey_from_enc_key(l_key_from);

    l_value_fee = dap_chain_balance_scan(l_value_fee_str);
    if(IS_ZERO_256(l_value_fee)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_RECOGNIZE_VALUE_FEE, "Can't recognize value '%s' as a number", l_value_fee_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_RECOGNIZE_VALUE_FEE;
    }

    const char *l_native_ticker = l_net->pub.native_ticker;
    if (!l_native_ticker){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NATIVE_TICKER_IN_NET, "Can't find native ticker for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_NATIVE_TICKER_IN_NET;
    }
    if (!l_ledger)
        l_ledger = dap_ledger_find_by_name(l_net->pub.name);
    if (!l_ledger){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_LEDGER_FOR_NET, "Can't find ledger for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_FIND_LEDGER_FOR_NET;
    }
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_ledger){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_CREATE_NEW_TX, "Can't create new tx");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_CREATE_NEW_TX;
    }

    dap_list_t *l_hashes_list = s_hashes_parse_str_list(l_hashes_str);
    if (!l_hashes_list){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUESTED_COND_TX_WITH_HASH_NOT_FOUND, "Requested conditional transaction with hash not found");
        dap_chain_datum_tx_delete(l_tx);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_REQUESTED_COND_TX_WITH_HASH_NOT_FOUND;
    }

    uint256_t l_cond_value_sum = {};
    size_t l_num_of_hashes = dap_list_length(l_hashes_list);
    log_it(L_INFO, "Found %zu hashes. Start returning funds from transactions.", l_num_of_hashes);
    for (dap_list_t * l_tmp = l_hashes_list; l_tmp; l_tmp=l_tmp->next){
        dap_hash_sha3_256_t *l_hash = (dap_hash_sha3_256_t*)l_tmp->data;
        // get tx by hash
        dap_chain_datum_tx_t *l_cond_tx = dap_ledger_tx_find_by_hash(l_ledger, l_hash);
        if (!l_cond_tx) {
            char l_hash_str[DAP_HASH_SHA3_256_STR_SIZE];
            dap_hash_sha3_256_to_str(l_hash, l_hash_str, DAP_HASH_SHA3_256_STR_SIZE);
            log_it(L_WARNING, "Requested conditional transaction with hash %s not found. Continue.", l_hash_str);
            continue;
        }

        const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, l_hash);
        if (!l_tx_ticker) {
            log_it(L_WARNING, "Can't get tx ticker");
            continue;
        }
        if (strcmp(l_native_ticker, l_tx_ticker)) {
            log_it(L_WARNING, "Tx must be in native ticker");
            continue;
        }

        // Get out_cond from l_cond_tx
        int l_prev_cond_idx = 0;
        dap_chain_tx_out_cond_t *l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_cond_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
                                                                             &l_prev_cond_idx);
        if (!l_tx_out_cond) {
            log_it(L_WARNING, "Requested conditional transaction has no contitional output with srv_uid %"DAP_UINT64_FORMAT_U, l_srv_uid.uint64);
            continue;
        }
        if (l_tx_out_cond->header.srv_uid.uint64 != l_srv_uid.uint64)
            continue;

        if (dap_ledger_tx_hash_is_used_out_item(l_ledger, l_hash, l_prev_cond_idx, NULL)) {
            log_it(L_WARNING, "Requested conditional transaction is already used out");
            continue;
        }
        // Get owner tx
        dap_hash_sha3_256_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, l_hash);
        dap_chain_datum_tx_t *l_owner_tx = dap_hash_sha3_256_is_blank(&l_owner_tx_hash)
            ? l_cond_tx:
            dap_ledger_tx_find_by_hash(l_ledger, &l_owner_tx_hash);
        if (!l_owner_tx)
            continue;
        dap_chain_tx_sig_t *l_owner_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_owner_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_owner_tx_sig);

        if (!l_owner_sign) {
            log_it(L_WARNING, "Can't get sign.");
            continue;
        }

        if (!dap_pkey_compare_with_sign(l_wallet_pkey, l_owner_sign)) {
            log_it(L_WARNING, "Only owner can return funds from tx cond");
            continue;
        }

        // get final tx
        dap_hash_sha3_256_t l_final_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, l_hash, true);
        dap_chain_datum_tx_t *l_final_tx = dap_ledger_tx_find_by_hash(l_ledger, &l_final_hash);
        if (!l_final_tx) {
            log_it(L_WARNING, "Only get final tx hash or tx is already used out.");
            continue;
        }

        // get and check tx_cond_out
        int l_final_cond_idx = 0;
        dap_chain_tx_out_cond_t *l_final_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_final_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
                                                                             &l_final_cond_idx);
        if (!l_final_tx_out_cond || IS_ZERO_256(l_final_tx_out_cond->header.value))
            continue;


        // add in_cond to new tx
        // add 'in' item to buy from conditional transaction
        dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_final_hash, l_final_cond_idx, 0);
        SUM_256_256(l_cond_value_sum, l_final_tx_out_cond->header.value, &l_cond_value_sum);
    }
    dap_list_free_full(l_hashes_list, NULL);

    if (IS_ZERO_256(l_cond_value_sum)){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_UNSPENT_COND_TX_IN_HASH_LIST_FOR_WALLET,
                               "No unspent conditional transactions in hashes list for wallet %s. Check input parameters.", l_wallet_str);
        dap_chain_datum_tx_delete(l_tx);
        // Wallet callback - no need to close wallet
        DAP_DEL_Z(l_wallet_pkey);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_UNSPENT_COND_TX_IN_HASH_LIST_FOR_WALLET;
    }

    uint256_t l_net_fee = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_net->pub.id, &l_net_fee, &l_addr_fee);
    uint256_t l_total_fee = l_value_fee;
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    if (compare256(l_total_fee, l_cond_value_sum) >= 0 ){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_SUM_COND_OUTPUTS_MUST_GREATER_THAN_FEES_SUM,
                               "Sum of conditional outputs must be greater than fees sum.");
        dap_chain_datum_tx_delete(l_tx);
        // Wallet callback - no need to close wallet
        DAP_DEL_Z(l_wallet_pkey);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_SUM_COND_OUTPUTS_MUST_GREATER_THAN_FEES_SUM;
    }

    uint256_t l_coin_back = {};
    SUBTRACT_256_256(l_cond_value_sum, l_total_fee, &l_coin_back);
    dap_chain_addr_t *l_wallet_addr = s_wallet_get_addr(l_wallet_str, l_net->pub.id);
    // return coins to owner
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, l_wallet_addr, l_coin_back, l_native_ticker) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_RETURNING_COINS_OUTPUT,
                               "Can't create new TX. Something went wrong.\n");
        log_it(L_ERROR, "Can't add returning coins output");
        DAP_DELETE(l_wallet_addr);
        // Wallet callback - no need to close wallet
        DAP_DEL_Z(l_wallet_pkey);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_RETURNING_COINS_OUTPUT-22;
    }
     DAP_DELETE(l_wallet_addr);
    // Network fee
    if (l_net_fee_used &&
            dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_native_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        // Wallet callback - no need to close wallet
        DAP_DEL_Z(l_wallet_pkey);
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_NETWORK_FEE_OUTPUT, "Can't create new TX. Something went wrong.\n");
        log_it(L_ERROR, "Cant add network fee output");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_NETWORK_FEE_OUTPUT;
    }
    // Validator's fee
    if (dap_chain_datum_tx_add_fee_item(&l_tx, l_value_fee) == -1) {
        dap_chain_datum_tx_delete(l_tx);
        // Wallet callback - no need to close wallet
        DAP_DEL_Z(l_wallet_pkey);
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_VALIDATORS_FEE_OUTPUT, "Can't create new TX. Something went wrong.\n");
        log_it(L_ERROR, "Cant add validator's fee output");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_VALIDATORS_FEE_OUTPUT;
    }

    // add 'sign' items
    // l_key_from already obtained via callback above
    if(dap_chain_datum_tx_add_sign_item(&l_tx, l_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_key_from);
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_SIGN_OUTPUT, "Can't create new TX. Something went wrong.\n");
        log_it( L_ERROR, "Can't add sign output");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_NOT_ADD_SIGN_OUTPUT;
    }

    // Wallet callback - no need to close wallet
    DAP_DEL_Z(l_wallet_pkey);

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_tx);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
    if (!l_chain) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_FIND_DEFAULT_CHAIN_WITH_TX_FOR_NET,
                               "Can't create new TX. Something went wrong.\n");
        DAP_DELETE(l_datum);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_CAN_FIND_DEFAULT_CHAIN_WITH_TX_FOR_NET;
    }
    // Processing will be made according to autoprocess policy
    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);

    if (l_hash_str) {
        dap_json_t *l_jobj_ret = dap_json_object_new();
        dap_json_t *l_jobj_tx_status = dap_json_object_new_bool(true);
        dap_json_t *l_jobj_tx_hash = dap_json_object_new_string(l_hash_str);
        dap_json_object_add_object(l_jobj_ret, "tx_create", l_jobj_tx_status);
        dap_json_object_add_object(l_jobj_ret, "hash", l_jobj_tx_hash);
        DAP_DELETE(l_hash_str);
        dap_json_array_add(a_json_arr_reply, l_jobj_ret);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OK;
    }
    dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OTHER_ERROR, "Can't create new TX. Something went wrong.");
    return DAP_CHAIN_NODE_CLI_COM_TX_COND_REMOVE_OTHER_ERROR;
}

typedef struct tx_check_args {
    dap_chain_datum_tx_t *tx;
    dap_hash_sha3_256_t tx_hash;
} tx_check_args_t;

void s_tx_is_srv_pay_check (dap_chain_net_t* a_net, dap_chain_datum_tx_t *a_tx, dap_hash_sha3_256_t *a_tx_hash, void *a_arg)
{
    UNUSED(a_net);
    dap_list_t **l_tx_list_ptr = a_arg;
    if (dap_chain_datum_tx_out_cond_get(a_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY , NULL)){
        tx_check_args_t *l_arg = DAP_NEW_Z(tx_check_args_t);
        l_arg->tx = a_tx;
        l_arg->tx_hash = *a_tx_hash;
        *l_tx_list_ptr = dap_list_append(*l_tx_list_ptr, l_arg);
    }

}

int com_tx_cond_unspent_find(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    (void) a_argc;
    int arg_index = 1;
    const char * l_wallet_str = NULL;
    const char * l_net_name = NULL;
    const char * l_srv_uid_str = NULL;

    const char * l_hash_out_type = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
    if(!l_hash_out_type)
        l_hash_out_type = "hex";
    if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_HEX,
                               "Invalid parameter -H, valid values: -H <hex | base58>");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_HEX;
    }

    // Public certifiacte of condition owner
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-w", &l_wallet_str);
    // net
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-net", &l_net_name);
    // srv_uid
    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-srv_uid", &l_srv_uid_str);

    if (!l_wallet_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_W,
                               "com_txs_cond_remove requires parameter '-w'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_W;
    }
    if(!l_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_NET,
                               "com_txs_cond_remove requires parameter '-net'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_NET;
    }
    if(!l_srv_uid_str) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_SRV_UID,
                               "com_txs_cond_remove requires parameter '-srv_uid'");
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_INVALID_PARAMETER_SRV_UID;
    }

    dap_chain_srv_uid_t l_srv_uid = {};
    l_srv_uid.uint64 = strtoll(l_srv_uid_str, NULL, 10);
    if (!l_srv_uid.uint64) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_SERVICE_UID,
                               "Can't find service UID %s ", l_srv_uid_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_SERVICE_UID;
    }

    dap_ledger_t *l_ledger = l_net_name ? dap_ledger_find_by_name(l_net_name) : NULL;
    dap_chain_net_t *l_net = l_net_name ? dap_chain_net_by_name(l_net_name) : NULL;
    if (!l_net) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NET,
                               "Can't find net '%s'", l_net_name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NET;
    }

    if (!l_ledger || !dap_chain_wallet_get_path(g_config)) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC,
            "Wallet signing function not available");
        return DAP_LEDGER_CLI_ERROR_TX_NO_WALLET_SIGN_FUNC;
    }
    dap_enc_key_t *l_key_from = s_wallet_get_key(l_wallet_str);
    if (!l_key_from) {
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_OPEN_WALLET,
            "Can't get key from wallet '%s'", l_wallet_str);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_OPEN_WALLET;
    }

    dap_pkey_t *l_wallet_pkey = dap_pkey_from_enc_key(l_key_from);

    const char *l_native_ticker = l_net->pub.native_ticker;
    if (!l_native_ticker){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NATIVE_TICKER_IN_NET,
                               "Can't find native ticker for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_NATIVE_TICKER_IN_NET;
    }
    if (!l_ledger)
        l_ledger = dap_ledger_find_by_name(l_net->pub.name);
    if (!l_ledger){
        dap_json_rpc_error_add(a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_LEDGER_FOR_NET, "Can't find ledger for net %s", l_net->pub.name);
        return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_CAN_NOT_FIND_LEDGER_FOR_NET;
    }

//    dap_string_t *l_reply_str = dap_string_new("");
    dap_json_t *l_jobj_tx_list_cond_outs = dap_json_array_new();
    dap_list_t *l_tx_list = NULL;

    dap_chain_net_get_tx_all(l_net, TX_SEARCH_TYPE_NET, s_tx_is_srv_pay_check, &l_tx_list);
    size_t l_tx_count = 0;
    uint256_t l_total_value = {};
    for (dap_list_t *it = l_tx_list; it; it = it->next) {
        tx_check_args_t *l_data_tx = (tx_check_args_t*)it->data;
        dap_chain_datum_tx_t *l_tx = l_data_tx->tx;
        int l_prev_cond_idx = 0;
        dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY , &l_prev_cond_idx);
        if (!l_out_cond || l_out_cond->header.srv_uid.uint64 != l_srv_uid.uint64 || IS_ZERO_256(l_out_cond->header.value))
            continue;

        if (dap_ledger_tx_hash_is_used_out_item(l_ledger, &l_data_tx->tx_hash, l_prev_cond_idx, NULL)) {
            continue;
        }

        const char *l_tx_ticker = dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_data_tx->tx_hash);
        if (!l_tx_ticker) {
            continue;
        }
        if (strcmp(l_native_ticker, l_tx_ticker)) {
            continue;
        }

        // Check sign
        dap_hash_sha3_256_t l_owner_tx_hash = dap_ledger_get_first_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, &l_data_tx->tx_hash);
        dap_chain_datum_tx_t *l_owner_tx = dap_hash_sha3_256_is_blank(&l_owner_tx_hash)
            ? l_tx
            : dap_ledger_tx_find_by_hash(l_ledger, &l_owner_tx_hash);

        if (!l_owner_tx)
            continue;
        dap_chain_tx_sig_t *l_owner_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(l_owner_tx, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_owner_sign = dap_chain_datum_tx_item_sig_get_sign((dap_chain_tx_sig_t *)l_owner_tx_sig);


        if (!dap_pkey_compare_with_sign(l_wallet_pkey, l_owner_sign)) {
            continue;
        }

        char *l_remain_datoshi_str = NULL;
        char *l_remain_coins_str = NULL;
        char l_hash_str[DAP_HASH_SHA3_256_STR_SIZE];
        dap_hash_sha3_256_to_str(&l_data_tx->tx_hash, l_hash_str, DAP_HASH_SHA3_256_STR_SIZE);
        l_remain_coins_str = dap_chain_balance_coins_print(l_out_cond->header.value);
        l_remain_datoshi_str = dap_chain_balance_datoshi_print(l_out_cond->header.value);
        dap_json_t *l_jobj_hash = dap_json_object_new_string(l_hash_str);
        dap_json_t *l_jobj_remain = dap_json_object_new();
        dap_json_t *l_jobj_remain_coins = dap_json_object_new_string(l_remain_coins_str);
        dap_json_t *l_jobj_remain_datoshi = dap_json_object_new_string(l_remain_datoshi_str);
        dap_json_object_add_object(l_jobj_remain, "coins", l_jobj_remain_coins);
        dap_json_object_add_object(l_jobj_remain, "datoshi", l_jobj_remain_datoshi);
        dap_json_t *l_jobj_native_ticker = dap_json_object_new_string(l_native_ticker);
        dap_json_t *l_jobj_tx = dap_json_object_new();
        dap_json_object_add_object(l_jobj_tx, "hash", l_jobj_hash);
        dap_json_object_add_object(l_jobj_tx, "remain", l_jobj_remain);
        dap_json_object_add_object(l_jobj_tx, "ticker", l_jobj_native_ticker);
        dap_json_array_add(l_jobj_tx_list_cond_outs, l_jobj_tx);
        l_tx_count++;
        SUM_256_256(l_total_value, l_out_cond->header.value, &l_total_value);
    }
    char *l_total_datoshi_str = dap_chain_balance_coins_print(l_total_value);
    char *l_total_coins_str = dap_chain_balance_datoshi_print(l_total_value);
    dap_json_t *l_jobj_total = dap_json_object_new();
    dap_json_t *l_jobj_total_datoshi = dap_json_object_new_string(l_total_datoshi_str);
    dap_json_t *l_jobj_total_coins = dap_json_object_new_string(l_total_coins_str);
    dap_json_t *l_jobj_native_ticker = dap_json_object_new_string(l_native_ticker);
    dap_json_object_add_object(l_jobj_total, "datoshi", l_jobj_total_datoshi);
    dap_json_object_add_object(l_jobj_total, "coins", l_jobj_total_coins);
    dap_json_object_add_object(l_jobj_total, "ticker", l_jobj_native_ticker);
    dap_json_object_add_uint64(l_jobj_total, "tx_count", l_tx_count);
    dap_json_t *l_jobj_ret = dap_json_object_new();
    dap_json_object_add_object(l_jobj_ret, "transactions_out_cond", l_jobj_tx_list_cond_outs);
    dap_json_object_add_object(l_jobj_ret, "total", l_jobj_total);
    dap_list_free_full(l_tx_list, NULL);
    dap_json_array_add(a_json_arr_reply, l_jobj_ret);
    DAP_DEL_Z(l_wallet_pkey);
    // Wallet callback - no need to close wallet
    return DAP_CHAIN_NODE_CLI_COM_TX_COND_UNSPEND_FIND_OK;
}


int dap_chain_net_tx_cli_init(void)
{
    dap_cli_server_cmd_add("tx_create", com_tx_create, NULL,
                           "Create transaction",
                           -1,
                           "tx_create -net <net_name> -chain <chain_name> -from_wallet <wallet_name> -to_addr <addr> -token <token_ticker> -value <value> -fee <value>\n"
                           "tx_create -net <net_name> -chain <chain_name> -from_emission <emission_hash> -chain_emission <chain_name> -to_addr <addr> -value <value> -fee <fee_value> -cert <cert_name>\n");
    dap_cli_server_cmd_add("tx_create_json", com_tx_create_json, NULL,
                           "Create transaction from JSON",
                           -1,
                           "tx_create_json -net <net_name> -chain <chain_name> -json <json_file_path>\n");
    /* mempool_add already registered by dap_chain_mempool_cli */
    dap_cli_server_cmd_add("tx_verify", com_tx_verify, NULL,
                           "Verify transaction in mempool",
                           -1,
                           "tx_verify -tx <tx_hash> -net <net_name> [-chain <chain_name>]\n");
    dap_cli_server_cmd_add("tx_history", com_tx_history, NULL,
                           "Transaction history",
                           -1,
                           "tx_history {-all | -addr <addr> | -w <wallet_name> | -tx <tx_hash>} -net <net_name> [-chain <chain_name>]\n");
    dap_cli_server_cmd_add("tx_cond_create", com_tx_cond_create, NULL,
                           "Create conditional transaction",
                           -1,
                           "tx_cond_create -net <net_name> -token <token_ticker> -w <wallet_name> -cert <cert_name> -value <value> -unit <unit> -srv_uid <uid> -fee <value>\n");
    dap_cli_server_cmd_add("tx_cond_remove", com_tx_cond_remove, NULL,
                           "Remove conditional transaction",
                           -1,
                           "tx_cond_remove -net <net_name> -hashes <hash1[,hash2,...]> -w <wallet_name> -srv_uid <uid> -fee <value>\n");
    dap_cli_server_cmd_add("tx_cond_unspent_find", com_tx_cond_unspent_find, NULL,
                           "Find unspent conditional transactions",
                           -1,
                           "tx_cond_unspent_find -net <net_name> -srv_uid <uid> -w <wallet_name>\n");
    log_it(L_NOTICE, "Net TX CLI commands registered");
    return 0;
}

void dap_chain_net_tx_cli_deinit(void)
{
    log_it(L_INFO, "Net TX CLI commands unregistered");
}
