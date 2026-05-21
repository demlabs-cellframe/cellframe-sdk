/**
 * @file utxo_blocking_test_helpers.c
 * @brief Helper functions implementation for UTXO blocking integration tests
 * @date 2025-01-16
 */

#include "utxo_blocking_test_helpers.h"
#include "dap_tsd.h"
#include "dap_sign.h"
#include "dap_test.h"
#include "dap_strfuncs.h"
#include "dap_string.h"

#define LOG_TAG "utxo_blocking_test_helpers"

/**
 * @brief Helper: Create token_update datum with TSD section for UTXO blocking
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_utxo_block_tsd(
    const char *a_ticker,
    dap_chain_hash_fast_t *a_tx_hash,
    uint32_t a_out_idx,
    dap_cert_t *a_cert,
    dap_time_t a_becomes_effective,
    size_t *a_datum_size)
{
    // Create TSD section for UTXO_BLOCKED_ADD
    size_t l_tsd_data_size = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
    if (a_becomes_effective > 0) {
        l_tsd_data_size += sizeof(dap_time_t);
    }
    
    byte_t *l_tsd_data = DAP_NEW_Z_SIZE(byte_t, l_tsd_data_size);
    memcpy(l_tsd_data, a_tx_hash, sizeof(dap_chain_hash_fast_t));
    memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t), &a_out_idx, sizeof(uint32_t));
    if (a_becomes_effective > 0) {
        memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t),
               &a_becomes_effective, sizeof(dap_time_t));
    }
    
    dap_tsd_t *l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD,
                                      l_tsd_data, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    
    // Create token_update datum
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_token->signs_valid = 0;
    l_token->total_supply = uint256_0;
    l_token->signs_total = 0;
    // For UPDATE type, use header_native_update (not header_native_decl)
    l_token->header_native_update.padding = 0;  // padding field for UPDATE (replaces flags in DECL)
    l_token->header_native_update.decimals = 0;
    
    size_t l_tsd_size = dap_tsd_size(l_tsd);
    l_token->header_native_update.tsd_total_size = l_tsd_size;
    
    // Realloc to fit TSD
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_token) {
        DAP_DELETE(l_tsd);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs, l_tsd, l_tsd_size);
    DAP_DELETE(l_tsd);
    
    // Sign token_update
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_sign) {
        DAP_DELETE(l_token);
        return NULL;
    }
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size);
    if (!l_token) {
        DAP_DELETE(l_sign);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs + l_tsd_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    
    l_token->signs_total = 1;
    *a_datum_size = sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size;
    
    return l_token;
}

/**
 * @brief Helper: Create token_update datum with address blocking TSD
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_address_block(
    const char *a_ticker,
    dap_chain_addr_t *a_addr,
    bool a_is_sender_block,
    dap_cert_t *a_cert,
    size_t *a_datum_size)
{
    // Create TSD section for ADDRESS_BLOCKED_ADD
    size_t l_tsd_data_size = sizeof(dap_chain_addr_t);
    
    byte_t *l_tsd_data = DAP_NEW_Z_SIZE(byte_t, l_tsd_data_size);
    memcpy(l_tsd_data, a_addr, sizeof(dap_chain_addr_t));
    
    uint8_t l_tsd_type = a_is_sender_block ? 
        DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD :
        DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD;
    
    dap_tsd_t *l_tsd = dap_tsd_create(l_tsd_type, l_tsd_data, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    
    // Create token_update datum
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_token->signs_valid = 0;
    l_token->total_supply = uint256_0;
    l_token->signs_total = 0;
    l_token->header_native_update.padding = 0;
    l_token->header_native_update.decimals = 0;
    
    size_t l_tsd_size = dap_tsd_size(l_tsd);
    l_token->header_native_update.tsd_total_size = l_tsd_size;
    
    // Realloc to fit TSD
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_token) {
        DAP_DELETE(l_tsd);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs, l_tsd, l_tsd_size);
    DAP_DELETE(l_tsd);
    
    // Sign token_update
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_sign) {
        DAP_DELETE(l_token);
        return NULL;
    }
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size);
    if (!l_token) {
        DAP_DELETE(l_sign);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs + l_tsd_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    
    l_token->signs_total = 1;
    *a_datum_size = sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size;
    
    return l_token;
}

/**
 * @brief Helper: Create token_update datum with UTXO_FLAGS TSD section
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_utxo_flags(
    const char *a_ticker,
    uint32_t a_utxo_flags,
    dap_cert_t *a_cert,
    size_t *a_datum_size)
{
    // Create TSD section for UTXO_FLAGS
    size_t l_tsd_data_size = sizeof(uint32_t);
    
    byte_t *l_tsd_data = DAP_NEW_Z_SIZE(byte_t, l_tsd_data_size);
    memcpy(l_tsd_data, &a_utxo_flags, sizeof(uint32_t));
    
    dap_tsd_t *l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_FLAGS,
                                      l_tsd_data, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    
    // Create token_update datum
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_token->signs_valid = 0;
    l_token->total_supply = uint256_0;
    l_token->signs_total = 0;
    l_token->header_native_update.padding = 0;
    l_token->header_native_update.decimals = 0;
    
    size_t l_tsd_size = dap_tsd_size(l_tsd);
    l_token->header_native_update.tsd_total_size = l_tsd_size;
    
    // Realloc to fit TSD
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_token) {
        DAP_DELETE(l_tsd);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs, l_tsd, l_tsd_size);
    DAP_DELETE(l_tsd);
    
    // Sign token_update
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_sign) {
        DAP_DELETE(l_token);
        return NULL;
    }
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size);
    if (!l_token) {
        DAP_DELETE(l_sign);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs + l_tsd_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    
    l_token->signs_total = 1;
    *a_datum_size = sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size;
    
    return l_token;
}

/**
 * @brief Helper: Create token_update datum with generic TSD list
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_tsd_list(
    const char *a_ticker,
    dap_list_t *a_tsd_list,
    dap_cert_t *a_cert,
    size_t *a_datum_size)
{
    // Calculate total TSD size
    size_t l_tsd_total_size = 0;
    dap_list_t *l_item;
    for (l_item = a_tsd_list; l_item; l_item = l_item->next) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)l_item->data;
        if (l_tsd) {
            l_tsd_total_size += dap_tsd_size(l_tsd);
        }
    }
    
    // Create token_update datum
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_token->signs_valid = 0;
    l_token->total_supply = uint256_0;
    l_token->signs_total = 0;
    l_token->header_native_update.padding = 0;
    l_token->header_native_update.decimals = 0;
    l_token->header_native_update.tsd_total_size = l_tsd_total_size;
    
    // Realloc to fit TSD sections
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_total_size);
    if (!l_token) {
        return NULL;
    }
    
    // Copy TSD sections
    byte_t *l_tsd_ptr = l_token->tsd_n_signs;
    for (l_item = a_tsd_list; l_item; l_item = l_item->next) {
        dap_tsd_t *l_tsd = (dap_tsd_t *)l_item->data;
        if (l_tsd) {
            size_t l_tsd_size = dap_tsd_size(l_tsd);
            memcpy(l_tsd_ptr, l_tsd, l_tsd_size);
            l_tsd_ptr += l_tsd_size;
        }
    }
    
    // Sign token_update
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token, sizeof(dap_chain_datum_token_t) + l_tsd_total_size);
    if (!l_sign) {
        DAP_DELETE(l_token);
        return NULL;
    }
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_total_size + l_sign_size);
    if (!l_token) {
        DAP_DELETE(l_sign);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs + l_tsd_total_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    
    l_token->signs_total = 1;
    *a_datum_size = sizeof(dap_chain_datum_token_t) + l_tsd_total_size + l_sign_size;
    
    return l_token;
}

/**
 * @brief Helper: Create token_update datum with TSD section for UTXO unblocking
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_utxo_unblock_tsd(
    const char *a_ticker,
    dap_chain_hash_fast_t *a_tx_hash,
    uint32_t a_out_idx,
    dap_cert_t *a_cert,
    dap_time_t a_becomes_unblocked,
    size_t *a_datum_size)
{
    // Create TSD section for UTXO_BLOCKED_REMOVE
    size_t l_tsd_data_size = sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t);
    if (a_becomes_unblocked > 0) {
        l_tsd_data_size += sizeof(dap_time_t);
    }
    
    byte_t *l_tsd_data = DAP_NEW_Z_SIZE(byte_t, l_tsd_data_size);
    memcpy(l_tsd_data, a_tx_hash, sizeof(dap_chain_hash_fast_t));
    memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t), &a_out_idx, sizeof(uint32_t));
    if (a_becomes_unblocked > 0) {
        memcpy(l_tsd_data + sizeof(dap_chain_hash_fast_t) + sizeof(uint32_t),
               &a_becomes_unblocked, sizeof(dap_time_t));
    }
    
    dap_tsd_t *l_tsd = dap_tsd_create(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE,
                                      l_tsd_data, l_tsd_data_size);
    DAP_DELETE(l_tsd_data);
    
    // Create token_update datum
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_token->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_token->ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1] = '\0';
    l_token->signs_valid = 0;
    l_token->total_supply = uint256_0;
    l_token->signs_total = 0;
    l_token->header_native_update.padding = 0;
    l_token->header_native_update.decimals = 0;
    
    size_t l_tsd_size = dap_tsd_size(l_tsd);
    l_token->header_native_update.tsd_total_size = l_tsd_size;
    
    // Realloc to fit TSD
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_token) {
        DAP_DELETE(l_tsd);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs, l_tsd, l_tsd_size);
    DAP_DELETE(l_tsd);
    
    // Sign token_update
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size);
    if (!l_sign) {
        DAP_DELETE(l_token);
        return NULL;
    }
    
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size);
    if (!l_token) {
        DAP_DELETE(l_sign);
        return NULL;
    }
    memcpy(l_token->tsd_n_signs + l_tsd_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    
    l_token->signs_total = 1;
    *a_datum_size = sizeof(dap_chain_datum_token_t) + l_tsd_size + l_sign_size;
    
    return l_token;
}

/**
 * @brief Helper: Split CLI command string into arguments and create JSON-RPC request
 */
char *utxo_blocking_test_cli_cmd_to_json_rpc(const char *a_cmd_str, const char *a_method,
                                              char *a_json_buf, size_t a_json_buf_size,
                                              int a_request_id)
{
    if (!a_cmd_str || !a_method || !a_json_buf || a_json_buf_size == 0) {
        return NULL;
    }
    
    // Split command string by spaces
    char **l_argv = dap_strsplit(a_cmd_str, " ", -1);
    if (!l_argv) {
        return NULL;
    }
    
    // Count arguments
    size_t l_argc = dap_str_countv(l_argv);
    if (l_argc == 0) {
        dap_strfreev(l_argv);
        return NULL;
    }
    
    // Join arguments with ';' separator (as expected by CLI server)
    dap_string_t *l_cmd_joined = dap_string_new("");
    for (size_t i = 0; i < l_argc; i++) {
        if (i > 0) {
            dap_string_append(l_cmd_joined, ";");
        }
        // Escape JSON special characters in argument
        const char *l_arg = l_argv[i];
        if (l_arg) {
            // Simple JSON string escaping (for basic cases)
            for (const char *p = l_arg; *p; p++) {
                if (*p == '"' || *p == '\\') {
                    dap_string_append_c(l_cmd_joined, '\\');
                }
                dap_string_append_c(l_cmd_joined, *p);
            }
        }
    }
    
    // Build JSON-RPC request
    int l_ret = snprintf(a_json_buf, a_json_buf_size,
                        "{\"method\":\"%s\",\"params\":[\"%s\"],\"id\":%d,\"jsonrpc\":\"2.0\"}",
                        a_method, l_cmd_joined->str, a_request_id);
    
    char *l_cmd_joined_str = dap_string_free(l_cmd_joined, false);
    dap_strfreev(l_argv);
    
    if (l_ret < 0 || (size_t)l_ret >= a_json_buf_size) {
        return NULL;
    }
    
    return a_json_buf;
}
