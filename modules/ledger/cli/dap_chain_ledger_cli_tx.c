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
#include "dap_cert.h"        // For certificate handling in emission-based TX
#include "dap_chain_mempool.h" // For dap_chain_mempool_base_tx_create
#include "dap_chain_net.h"    // For dap_chain_net_get_default_chain_by_chain_type
#include "dap_chain_type_dag_event.h" // For dap_chain_type_dag_event_get_datum
#include "dap_chain_datum.h"  // For dap_chain_datum_calc_hash

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
    const char *l_from_emission_str = NULL;
    const char *l_chain_emission_name = NULL;
    const char *l_cert_str = NULL;
    
    // Parse parameters
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-net", &l_net_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain", &l_chain_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from_wallet", &l_from_wallet);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-to_addr", &l_to_addr_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-token", &l_token_ticker);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-value", &l_value_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-fee", &l_fee_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-H", &l_hash_out_type);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-from_emission", &l_from_emission_str);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-chain_emission", &l_chain_emission_name);
    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
    
    if (!l_hash_out_type) {
        l_hash_out_type = "hex";
    }
    
    // Debug: show parsed parameters
    log_it(L_INFO, "tx create PARAMS: net=%s from_emission=%s from_wallet=%s chain_emission=%s cert=%s",
           l_net_name ? l_net_name : "NULL",
           l_from_emission_str ? l_from_emission_str : "NULL",
           l_from_wallet ? l_from_wallet : "NULL",
           l_chain_emission_name ? l_chain_emission_name : "NULL",
           l_cert_str ? l_cert_str : "NULL");
    
    // Validate required parameters
    if (!l_net_name) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_NET_PARAM_ERR"), 
            "Network name required (-net)");
        return dap_cli_error_code_get("LEDGER_NET_PARAM_ERR");
    }
    
    // Get ledger early - needed for both emission and wallet flows
    dap_ledger_t *l_ledger = cli_get_ledger_by_net_name(l_net_name, a_json_arr_reply);
    if (!l_ledger) {
        return dap_cli_error_code_get("LEDGER_NET_FIND_ERR");
    }
    
    // Parse fee
    uint256_t l_fee = l_fee_str ? dap_chain_balance_scan(l_fee_str) : uint256_0;
    
    // ==========================================================================
    // EMISSION-BASED TRANSACTION PATH
    // ==========================================================================
    log_it(L_INFO, "tx create: checking emission path, l_from_emission_str=%p", (void*)l_from_emission_str);
    if (l_from_emission_str) {
        log_it(L_INFO, "tx create: ENTERING EMISSION PATH with hash %s", l_from_emission_str);
        // Parse emission hash
        dap_chain_hash_fast_t l_emission_hash = {};
        if (dap_chain_hash_fast_from_str(l_from_emission_str, &l_emission_hash)) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                "Invalid emission hash: %s", l_from_emission_str);
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        // Get emission chain
        if (!l_chain_emission_name) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                "Emission chain required (-chain_emission) when using -from_emission");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        // Need certificate for signing emission TX
        if (!l_cert_str) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                "Certificate required (-cert) for emission-based transaction");
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_cert) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_PARAM_ERR"), 
                "Certificate not found: %s", l_cert_str);
            return dap_cli_error_code_get("LEDGER_PARAM_ERR");
        }
        
        // Get emission chain by name from ledger registry
        dap_chain_t *l_emission_chain = NULL;
        dap_chain_info_t *l_chain_info = NULL, *l_tmp = NULL;
        HASH_ITER(hh, l_ledger->chains_registry, l_chain_info, l_tmp) {
            if (l_chain_info->chain_name[0] && strcmp(l_chain_info->chain_name, l_chain_emission_name) == 0) {
                l_emission_chain = (dap_chain_t *)l_chain_info->chain_ptr;
                break;
            }
        }
        
        if (!l_emission_chain) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND"), 
                "Emission chain not found: %s", l_chain_emission_name);
            return dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND");
        }
        
        // Get TX chain from network
        dap_chain_net_t *l_net = dap_chain_net_by_id(l_ledger->net_id);
        dap_chain_t *l_tx_chain = dap_chain_net_get_default_chain_by_chain_type(l_net, CHAIN_TYPE_TX);
        if (!l_tx_chain) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND"), 
                "TX chain not found in network");
            return dap_cli_error_code_get("LEDGER_CHAIN_NOT_FOUND");
        }
        
        // The -from_emission parameter can be either:
        // 1. The event hash (DAG event containing the emission datum)
        // 2. The datum hash directly
        // We need to try both approaches to find the emission
        
        dap_chain_hash_fast_t l_datum_hash = l_emission_hash;  // Start with the provided hash
        
        // First, check if this is a DAG event hash by trying to get the event
        size_t l_event_size = 0;
        dap_chain_atom_ptr_t l_event = dap_chain_get_atom_by_hash(l_emission_chain, &l_emission_hash, &l_event_size);
        
        if (l_event && l_event_size > 0) {
            // It's a DAG event - extract the datum and compute its hash
            log_it(L_INFO, "Found DAG event, extracting datum hash");
            dap_chain_datum_t *l_datum = dap_chain_type_dag_event_get_datum(
                (dap_chain_type_dag_event_t *)l_event, l_event_size);
            if (l_datum) {
                dap_chain_datum_calc_hash(l_datum, &l_datum_hash);
                log_it(L_INFO, "Computed datum hash: %s", dap_chain_hash_fast_to_str_static(&l_datum_hash));
            } else {
                log_it(L_WARNING, "Failed to extract datum from DAG event");
            }
        } else {
            log_it(L_INFO, "No DAG event found with hash, assuming it's a direct datum hash");
        }
        
        // Create base TX from emission using the datum hash
        log_it(L_INFO, "Creating base TX from emission hash: %s on chain %s", 
               dap_chain_hash_fast_to_str_static(&l_datum_hash), l_tx_chain->name);
        char *l_tx_hash_str = dap_chain_mempool_base_tx_create(
            l_tx_chain, 
            &l_datum_hash, 
            l_emission_chain->id,
            uint256_0, NULL, NULL,  // Get value/token/addr from emission itself
            l_cert->enc_key, 
            l_hash_out_type, 
            l_fee
        );
        
        if (!l_tx_hash_str) {
            dap_json_rpc_error_add(a_json_arr_reply, 
                dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED"), 
                "Failed to create base TX from emission");
            return dap_cli_error_code_get("LEDGER_TX_CREATE_FAILED");
        }
        
        // Success - return hash
        dap_json_t *l_result = dap_json_object_new();
        dap_json_object_add_string(l_result, "status", "success");
        dap_json_object_add_string(l_result, "emission", "Ok");
        dap_json_object_add_string(l_result, "hash", l_tx_hash_str);
        dap_json_array_add(a_json_arr_reply, l_result);
        
        DAP_DELETE(l_tx_hash_str);
        log_it(L_NOTICE, "Base TX from emission created successfully");
        return 0;
    }
    
    // ==========================================================================
    // WALLET-BASED TRANSACTION PATH (original flow)
    // ==========================================================================
    if (!l_from_wallet) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_WALLET_PARAM_ERR"), 
            "Source wallet required (-from_wallet) or emission (-from_emission)");
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
    
    // Parse value
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID"), 
            "Invalid value: %s", l_value_str);
        return dap_cli_error_code_get("LEDGER_TX_CREATE_VALUE_INVALID");
    }
    
    // Parse destination address
    dap_chain_addr_t *l_addr_to = dap_chain_addr_from_str(l_to_addr_str);
    if (!l_addr_to) {
        dap_json_rpc_error_add(a_json_arr_reply, 
            dap_cli_error_code_get("LEDGER_TX_CREATE_DEST_ADDR_INVALID"), 
            "Invalid destination address: %s", l_to_addr_str);
        return dap_cli_error_code_get("LEDGER_TX_CREATE_DEST_ADDR_INVALID");
    }
    
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
    HASH_ITER(hh, l_ledger->chains_registry, l_chain_info, l_tmp) {
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

