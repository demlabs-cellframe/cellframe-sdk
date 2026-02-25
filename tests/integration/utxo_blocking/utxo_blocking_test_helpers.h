/**
 * @file utxo_blocking_test_helpers.h
 * @brief Helper functions and shared context for UTXO blocking integration tests
 * @date 2025-01-16
 */

#pragma once

#include "dap_common.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_common.h"
#include "dap_cert.h"
#include "test_ledger_fixtures.h"

#ifdef __cplusplus
extern "C" {
#endif

// Global test context (defined in main test file)
extern test_net_fixture_t *s_net_fixture;

/**
 * @brief Helper: Create token_update datum with TSD section for UTXO blocking
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_utxo_block_tsd(
    const char *a_ticker,
    dap_chain_hash_fast_t *a_tx_hash,
    uint32_t a_out_idx,
    dap_cert_t *a_cert,
    dap_time_t a_becomes_effective,
    size_t *a_datum_size);

/**
 * @brief Helper: Create token_update datum with address blocking TSD
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_address_block(
    const char *a_ticker,
    dap_chain_addr_t *a_addr,
    bool a_is_sender_block,
    dap_cert_t *a_cert,
    size_t *a_datum_size);

/**
 * @brief Helper: Create token_update datum with UTXO_FLAGS TSD section
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_utxo_flags(
    const char *a_ticker,
    uint32_t a_utxo_flags,
    dap_cert_t *a_cert,
    size_t *a_datum_size);

/**
 * @brief Helper: Create token_update datum with generic TSD list
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_tsd_list(
    const char *a_ticker,
    dap_list_t *a_tsd_list,
    dap_cert_t *a_cert,
    size_t *a_datum_size);

/**
 * @brief Helper: Create token_update datum with TSD section for UTXO unblocking
 */
dap_chain_datum_token_t *utxo_blocking_test_create_token_update_with_utxo_unblock_tsd(
    const char *a_ticker,
    dap_chain_hash_fast_t *a_tx_hash,
    uint32_t a_out_idx,
    dap_cert_t *a_cert,
    dap_time_t a_becomes_unblocked,
    size_t *a_datum_size);

/**
 * @brief Helper: Split CLI command string into arguments and create JSON-RPC request
 * @details Splits command string by spaces and joins arguments with ';' separator
 *          as expected by CLI server (dap_cli_server.c splits by ';')
 * @param a_cmd_str Command string with spaces (e.g., "token_update -net Snet -token TEST")
 * @param a_method JSON-RPC method name (e.g., "token_update")
 * @param a_json_buf Buffer for JSON-RPC request string
 * @param a_json_buf_size Size of JSON buffer
 * @param a_request_id JSON-RPC request ID
 * @return Pointer to JSON-RPC request string on success, NULL on failure
 */
char *utxo_blocking_test_cli_cmd_to_json_rpc(const char *a_cmd_str, const char *a_method,
                                              char *a_json_buf, size_t a_json_buf_size,
                                              int a_request_id);

#ifdef __cplusplus
}
#endif

