/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.
 */

#include "dap_chain_ledger_cli_tx.h"
#include "dap_chain_ledger_cli_internal.h"
#include "dap_chain_ledger_cli_cmd_registry.h"  // For command registration
#include "dap_cli_error_codes.h"
#include "dap_chain_ledger_cli_error_codes.h"
#include "dap_json_rpc_errors.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_cli_server.h"  // For dap_cli_server_cmd_find_option_val
#include "dap_chain_common.h" // For CHAIN_TYPE_TX
#include "dap_chain_ledger_type.h"

/* Must match anon_transfer_compose_params_t in dap_chain_tx_anon_compose.c */
typedef struct {
    const char *wallet_name;
    const char *chain_name;
    const char *token_ticker;
    uint256_t value;
    dap_chain_addr_t addr_to;
    size_t anon_set;
    uint256_t fee;
    const char *hash_out_type;
} anon_transfer_compose_params_t;

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
    
    // Parse parameters
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from_wallet", &l_from_wallet);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-to_addr", &l_to_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_ticker);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    
    // Anonymous TX parameters (auto-detected from ledger type)
    const char *l_anon_set_str = NULL;
    size_t l_anon_set = 10;
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-anon_set", &l_anon_set_str);
    if (l_anon_set_str) {
        l_anon_set = (size_t)strtoul(l_anon_set_str, NULL, 10);
        if (l_anon_set < 8 || l_anon_set > 64) {
            dap_json_rpc_error_add(a_json_arr_reply,
                dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID"),
                "Parameter '-anon_set' must be between 8 and 64");
            return dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID");
        }
    }
    bool l_anonymous = false;
    
    if (!l_hash_out_type) {
        l_hash_out_type = "hex";
    }
    
    // Validate required parameters
    if (!l_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), 
            "Network name required (-net)");
        return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
    }
    
    if (!l_from_wallet) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_WALLET_PARAM_ERR"), 
            "Source wallet required (-from_wallet)");
        return dap_cli_error_code_get("LEDGER_WALLET_PARAM_ERR");
    }
    
    if (!l_to_addr_str) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_TO_ADDR_REQUIRED"), 
            "Destination address required (-to_addr)");
        return dap_cli_error_code_get("LEDGER_TX_CREATE_TO_ADDR_REQUIRED");
    }
    
    if (!l_token_ticker) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_TOKEN_REQUIRED"), 
            "Token ticker required (-token)");
        return dap_cli_error_code_get("LEDGER_TX_CREATE_TOKEN_REQUIRED");
    }
    
    if (!l_value_str) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID"), 
            "Value required (-value)");
        return dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID");
    }
    
    // Get ledger
    dap_ledger_t *l_ledger = cli_get_ledger_by_net_name(l_net_name, a_json_arr_reply);
    if (!l_ledger) {
        return dap_cli_error_code_get("LEDGER_NET_FIND_ERR");
    }
    
    // Parse value
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID"), 
            "Invalid value: %s", l_value_str);
        return dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID");
    }
    
    // Parse fee
    uint256_t l_fee = l_fee_str ? dap_chain_balance_scan(l_fee_str) : uint256_0;
    
    // Parse destination address
    dap_chain_addr_t *l_addr_to = dap_chain_addr_from_str(l_to_addr_str);
    if (!l_addr_to) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_DEST_ADDR_INVALID"), 
            "Invalid destination address: %s", l_to_addr_str);
        return dap_cli_error_code_get("LEDGER_TX_CREATE_DEST_ADDR_INVALID");
    }
    
    // Auto-detect anonymous mode from ledger type
    l_anonymous = (dap_ledger_get_type(l_ledger) == DAP_LEDGER_TYPE_ANON);
    
    /* ===== Anonymous TX branch ===== */
    if (l_anonymous) {
        // Resolve chain name (default to "main" for anonymous TX)
        const char *l_anon_chain_name = l_chain_name ? l_chain_name : "main";
        
        // Prepare anonymous transfer compose parameters
        anon_transfer_compose_params_t l_anon_params = {
            .wallet_name = l_from_wallet,
            .chain_name = l_anon_chain_name,
            .token_ticker = l_token_ticker,
            .value = l_value,
            .addr_to = *l_addr_to,
            .anon_set = l_anon_set,
            .fee = l_fee,
            .hash_out_type = l_hash_out_type
        };
        
        log_it(L_INFO, "Creating anonymous transfer TX: wallet=%s, chain=%s, token=%s, anon_set=%zu",
               l_from_wallet, l_anon_chain_name, l_token_ticker, l_anon_set);
        
        dap_chain_datum_t *l_datum = dap_chain_tx_compose_create(
            "anon_transfer",
            l_ledger,
            NULL,  // Anonymous TX does its own UTXO search internally
            &l_anon_params
        );
        
        DAP_DELETE(l_addr_to);
        
        if (!l_datum) {
            dap_json_rpc_error_add(a_json_arr_reply,
                dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED"),
                "Failed to create anonymous transaction. Check logs for details "
                "(wallet key type must be sig_chipmunk_ring or sig_chipmunk_lrs, "
                "insufficient balance, or STARK error)");
            return dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED");
        }
        
        // Get default TX chain from ledger registry
        dap_chain_t *l_chain = NULL;
        dap_chain_info_t *l_chain_info = NULL, *l_tmp = NULL;
        dap_ht_foreach(l_ledger->chains_registry, l_chain_info, l_tmp) {
            if (l_chain_info->chain_type == CHAIN_TYPE_TX) {
                l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                break;
            }
        }
        
        if (!l_chain) {
            DAP_DELETE(l_datum);
            dap_json_rpc_error_add(a_json_arr_reply,
                dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND"),
                "No TX chain found in network");
            return dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND");
        }
        
        // Add to mempool via ledger callback
        if (!l_ledger->mempool_add_datum_callback) {
            DAP_DELETE(l_datum);
            dap_json_rpc_error_add(a_json_arr_reply,
                dap_cli_error_code_get("LEDGER_MEMPOOL_FAILED"),
                "Mempool callback not set");
            return dap_cli_error_code_get("LEDGER_MEMPOOL_FAILED");
        }
        
        char *l_hash_str = l_ledger->mempool_add_datum_callback(l_datum, l_chain, l_hash_out_type);
        DAP_DELETE(l_datum);
        
        if (!l_hash_str) {
            dap_json_rpc_error_add(a_json_arr_reply,
                dap_cli_error_code_get("LEDGER_TX_CREATE_MEMPOOL_ADD_FAILED"),
                "Failed to add anonymous transaction to mempool");
            return dap_cli_error_code_get("LEDGER_TX_CREATE_MEMPOOL_ADD_FAILED");
        }
        
        dap_json_t *l_result = dap_json_object_new();
        dap_json_object_add_string(l_result, "status", "success");
        dap_json_object_add_string(l_result, "tx_hash", l_hash_str);
        dap_json_object_add_string(l_result, "anonymous", "true");
        dap_json_array_add(a_json_arr_reply, l_result);
        
        DAP_DELETE(l_hash_str);
        
        log_it(L_NOTICE, "Anonymous transaction created successfully");
        return 0;
    }
    /* ===== End anonymous TX branch ===== */
    
    // Get source address from wallet using ledger callback
    const dap_chain_addr_t *l_addr_from = NULL;
    if (l_ledger->wallet_get_addr_callback) {
        l_addr_from = l_ledger->wallet_get_addr_callback(l_from_wallet, l_ledger->net_id);
    }
    
    if (!l_addr_from) {
        DAP_DELETE(l_addr_to);
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_WALLET_ERR"), 
            "Cannot get address from wallet: %s", l_from_wallet);
        return dap_cli_error_code_get("LEDGER_WALLET_ERR");
    }
    
    // Get UTXO for the transaction
    uint256_t l_total_needed = {};
    SUM_256_256(l_value, l_fee, &l_total_needed);
    
    uint256_t l_value_found = {};
    dap_list_t *l_list_outs = dap_ledger_get_utxo_for_value(
        l_ledger,
        l_token_ticker,    // Token ticker
        l_addr_from,       // Source address
        l_total_needed,    // Value needed
        &l_value_found     // Value found (out)
    );
    
    if (!l_list_outs) {
        DAP_DELETE(l_addr_to);
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED"), 
            "Insufficient funds");
        return dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED");
    }
    
    // Create transfer parameters (for wallet module)
    dap_chain_wallet_tx_transfer_params_t l_params = {
        .token_ticker = {0},
        .value = l_value,
        .addr_to = l_addr_to
    };
    strncpy(l_params.token_ticker, l_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    
    // Call TX Compose API - uses registered "transfer" builder from wallet module
    log_it(L_INFO, "Creating transfer TX using TX Compose API");
    dap_chain_datum_t *l_datum = dap_chain_tx_compose_create(
        "transfer",        // TX type registered by wallet module
        l_ledger,          // Ledger for network context
        l_list_outs,       // UTXO list
        &l_params          // Transfer-specific parameters
    );
    
    // Cleanup UTXO list
    dap_list_free_full(l_list_outs, NULL);
    
    DAP_DELETE(l_addr_to);
    
    if (!l_datum) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED"), 
            "Failed to create transaction");
        return dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED");
    }
    
    // Get default TX chain from ledger registry
    dap_chain_t *l_chain = NULL;
    dap_chain_info_t *l_chain_info = NULL, *l_tmp = NULL;
    dap_ht_foreach(l_ledger->chains_registry, l_chain_info, l_tmp) {
        if (l_chain_info->chain_type == CHAIN_TYPE_TX) {
            l_chain = (dap_chain_t *)l_chain_info->chain_ptr;
            break;
        }
    }
    
    if (!l_chain) {
        DAP_DELETE(l_datum);
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND"), 
            "No TX chain found in network");
        return dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND");
    }
    
    // Add to mempool via ledger callback
    if (!l_ledger->mempool_add_datum_callback) {
        DAP_DELETE(l_datum);
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_MEMPOOL_FAILED"), 
            "Mempool callback not set");
        return dap_cli_error_code_get("LEDGER_MEMPOOL_FAILED");
    }
    
    char *l_hash_str = l_ledger->mempool_add_datum_callback(l_datum, l_chain, l_hash_out_type);
    DAP_DELETE(l_datum);
    
    if (!l_hash_str) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_MEMPOOL_ADD_FAILED"), 
            "Failed to add transaction to mempool");
        return dap_cli_error_code_get("LEDGER_TX_CREATE_MEMPOOL_ADD_FAILED");
    }
    
    // Success!
    dap_json_t *l_result = dap_json_object_new();
    dap_json_object_add_string(l_result, "status", "success");
    dap_json_object_add_string(l_result, "tx_hash", l_hash_str);
    dap_json_array_add(a_json_arr_reply, l_result);
    
    DAP_DELETE(l_hash_str);
    
    log_it(L_NOTICE, "Transaction created successfully using TX Compose API");
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

