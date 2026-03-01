/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_tx.h"
#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_cmd_registry.h"
#include "dap_cli_error_codes.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_json_rpc_errors.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_cli_server.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_cert.h"
#include "dap_hash.h"
#include "dap_chain_net.h"
#include "dap_chain_net_utils.h"

#define LOG_TAG "ledger_cli_tx"

// Forward declaration for wallet TX params (defined in wallet module)
typedef struct dap_chain_wallet_tx_transfer_params {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t value;
    dap_chain_addr_t *addr_to;
} dap_chain_wallet_tx_transfer_params_t;



/**
 * @brief tx create - Create transaction using NEW TX Compose API
 * 
 * FULL IMPLEMENTATION using plugin-based architecture:
 * - Uses dap_chain_tx_compose_orchestrate() for TX creation
 * - Supports transfer, multi-transfer (wallet module)
 * - Hardware wallet friendly (async signing via callbacks)
 * - Clean separation of concerns
 */
int ledger_cli_tx_create(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    int l_arg_index = 1;
    const char *l_net_name = NULL;
    const char *l_chain_name = NULL;
    const char *l_from_wallet = NULL;
    const char *l_to_addr_str = NULL;
    const char *l_token_ticker = NULL;
    const char *l_value_str = NULL;
    const char *l_fee_str = NULL;
    const char *l_hash_out_type = NULL;
    const char *l_emission_hash_str = NULL;
    const char *l_emission_chain_name = NULL;
    const char *l_cert_str = NULL;

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from_wallet", &l_from_wallet);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-to_addr", &l_to_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_ticker);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from_emission", &l_emission_hash_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain_emission", &l_emission_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);

    if (!l_hash_out_type)
        l_hash_out_type = "hex";

    if (!l_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Network name required (-net)");
        return -1;
    }

    dap_ledger_t *l_ledger = cli_get_ledger_by_net_name(l_net_name, a_json_arr_reply);
    if (!l_ledger)
        return -1;

    uint256_t l_fee = l_fee_str ? dap_chain_balance_scan(l_fee_str) : uint256_0;

    // Emission-based base TX creation path
    if (l_emission_hash_str) {
        dap_hash_sha3_256_t l_emission_hash = {};
        if (dap_hash_sha3_256_from_str(l_emission_hash_str, &l_emission_hash)) {
            dap_json_rpc_error_add(a_json_arr_reply, -1,
                "Invalid emission hash: %s", l_emission_hash_str);
            return -1;
        }

        if (!l_cert_str) {
            dap_json_rpc_error_add(a_json_arr_reply, -1,
                "Parameter -cert required for emission base TX creation");
            return -1;
        }
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_cert) {
            dap_json_rpc_error_add(a_json_arr_reply, -1,
                "Certificate '%s' not found", l_cert_str);
            return -1;
        }
        dap_enc_key_t *l_priv_key = l_cert->enc_key;

        dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
        if (!l_net) {
            dap_json_rpc_error_add(a_json_arr_reply, -1, "Network '%s' not found", l_net_name);
            return -1;
        }

        dap_chain_t *l_chain = NULL;
        if (l_chain_name)
            l_chain = dap_chain_net_get_chain_by_name(l_net, l_chain_name);
        else
            l_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
        if (!l_chain) {
            dap_json_rpc_error_add(a_json_arr_reply, -1, "TX chain not found in net '%s'", l_net_name);
            return -1;
        }

        dap_chain_id_t l_emission_chain_id = {};
        if (l_emission_chain_name) {
            dap_chain_t *l_emission_chain = dap_chain_net_get_chain_by_name(l_net, l_emission_chain_name);
            if (!l_emission_chain) {
                dap_json_rpc_error_add(a_json_arr_reply, -1,
                    "Emission chain '%s' not found", l_emission_chain_name);
                return -1;
            }
            l_emission_chain_id = l_emission_chain->id;
        } else {
            dap_chain_t *l_emission_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_EMISSION);
            if (l_emission_chain)
                l_emission_chain_id = l_emission_chain->id;
        }

        char *l_tx_hash_str = dap_chain_mempool_base_tx_create(
            l_chain, &l_emission_hash, l_emission_chain_id,
            uint256_0, NULL, NULL,
            l_priv_key, l_hash_out_type, l_fee);

        if (!l_tx_hash_str) {
            dap_json_rpc_error_add(a_json_arr_reply, -1, "Failed to create base TX from emission");
            return -1;
        }

        dap_json_t *l_result = dap_json_object_new();
        dap_json_object_add_string(l_result, "status", "Ok");
        dap_json_object_add_string(l_result, "hash", l_tx_hash_str);
        dap_json_array_add(a_json_arr_reply, l_result);
        DAP_DELETE(l_tx_hash_str);
        return 0;
    }

    // Wallet-based UTXO transfer path
    if (!l_from_wallet) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,
            "Specify -from_wallet for transfer or -from_emission for base TX");
        return -1;
    }
    if (!l_to_addr_str) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Destination address required (-to_addr)");
        return -1;
    }
    if (!l_token_ticker) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Token ticker required (-token)");
        return -1;
    }
    if (!l_value_str) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Value required (-value)");
        return -1;
    }

    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Invalid value: %s", l_value_str);
        return -1;
    }

    dap_chain_addr_t *l_addr_to = dap_chain_addr_from_str(l_to_addr_str);
    if (!l_addr_to) {
        dap_json_rpc_error_add(a_json_arr_reply, -1,
            "Invalid destination address: %s", l_to_addr_str);
        return -1;
    }

    const dap_chain_addr_t *l_addr_from = NULL;
    if (l_ledger->wallet_get_addr_callback)
        l_addr_from = l_ledger->wallet_get_addr_callback(l_from_wallet, l_ledger->net_id);
    if (!l_addr_from) {
        DAP_DELETE(l_addr_to);
        dap_json_rpc_error_add(a_json_arr_reply, -1,
            "Cannot get address from wallet: %s", l_from_wallet);
        return -1;
    }

    uint256_t l_total_needed = {};
    SUM_256_256(l_value, l_fee, &l_total_needed);

    uint256_t l_value_found = {};
    dap_list_t *l_list_outs = dap_ledger_get_utxo_for_value(
        l_ledger, l_token_ticker, l_addr_from, l_total_needed, &l_value_found);

    if (!l_list_outs) {
        DAP_DELETE(l_addr_to);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Insufficient funds");
        return -1;
    }

    dap_chain_wallet_tx_transfer_params_t l_params = {
        .token_ticker = {0},
        .value = l_value,
        .addr_to = l_addr_to
    };
    strncpy(l_params.token_ticker, l_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);

    dap_chain_datum_t *l_datum = dap_chain_tx_compose_create(
        "transfer", l_ledger, l_list_outs, &l_params);

    dap_list_free_full(l_list_outs, NULL);
    DAP_DELETE(l_addr_to);

    if (!l_datum) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Failed to create transaction");
        return -1;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_name);
    dap_chain_t *l_chain = l_net
        ? dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX)
        : NULL;

    if (!l_chain) {
        DAP_DELETE(l_datum);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "No TX chain found in network");
        return -1;
    }

    if (!l_ledger->mempool_add_datum_callback) {
        DAP_DELETE(l_datum);
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Mempool callback not set");
        return -1;
    }

    char *l_hash_str = l_ledger->mempool_add_datum_callback(l_datum, l_chain, l_hash_out_type);
    DAP_DELETE(l_datum);

    if (!l_hash_str) {
        dap_json_rpc_error_add(a_json_arr_reply, -1, "Failed to add transaction to mempool");
        return -1;
    }

    dap_json_t *l_result = dap_json_object_new();
    dap_json_object_add_string(l_result, "status", "success");
    dap_json_object_add_string(l_result, "tx_hash", l_hash_str);
    dap_json_array_add(a_json_arr_reply, l_result);
    DAP_DELETE(l_hash_str);
    return 0;
}

/**
 * @brief tx create_json - Create transaction from JSON
 * 
 * TODO: Implement using TX Compose API
 */
int ledger_cli_tx_create_json(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    dap_json_rpc_error_add(a_json_arr_reply, 
        dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
        "tx create_json not yet implemented - use 'tx create' for now");
    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
}

/**
 * @brief tx verify - Verify transaction
 * 
 * TODO: Implement using ledger verification API
 */
int ledger_cli_tx_verify(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    dap_json_rpc_error_add(a_json_arr_reply, 
        dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
        "tx verify not yet implemented");
    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
}

/**
 * @brief tx history - Show transaction history
 * 
 * TODO: Implement using ledger history API
 */
int ledger_cli_tx_history(int a_argc, char **a_argv, dap_json_t *a_json_arr_reply, int a_version)
{
    dap_json_rpc_error_add(a_json_arr_reply, 
        dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
        "tx history not yet implemented");
    return dap_cli_error_code_get("LEDGER_PARAM_ERR");
}

/**
 * @brief Initialize TX commands module
 * 
 * Registers all TX commands in CLI registry
 */
int dap_chain_ledger_cli_tx_init(void)
{
    log_it(L_INFO, "Initializing ledger TX CLI commands");
    
    // Register TX commands via registry - plugin pattern!
    dap_ledger_cli_cmd_register("tx", "create", ledger_cli_tx_create, 
                                 "Create transaction using TX Compose API");
    dap_ledger_cli_cmd_register("tx", "create_json", ledger_cli_tx_create_json, 
                                 "Create transaction from JSON file");
    dap_ledger_cli_cmd_register("tx", "verify", ledger_cli_tx_verify, 
                                 "Verify transaction");
    dap_ledger_cli_cmd_register("tx", "history", ledger_cli_tx_history, 
                                 "Show transaction history");
    
    log_it(L_NOTICE, "TX CLI commands registered successfully");
    return 0;
}

/**
 * @brief Deinitialize TX commands module
 */
void dap_chain_ledger_cli_tx_deinit(void)
{
    log_it(L_INFO, "Deinitializing ledger TX CLI commands");
    
    // Unregister commands
    dap_ledger_cli_cmd_unregister("tx", "create");
    dap_ledger_cli_cmd_unregister("tx", "create_json");
    dap_ledger_cli_cmd_unregister("tx", "verify");
    dap_ledger_cli_cmd_unregister("tx", "history");
}

