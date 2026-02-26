/**
 * @file dap_chain_ledger_cli_ledger_wrap.h
 * @brief Wrapper functions for ledger CLI commands (for mocking in tests)
 * 
 * This file declares wrapper functions that can be mocked using the DAP Mock Framework.
 * The wrappers are used to intercept calls to underlying ledger/network functions
 * during unit testing, allowing controlled test behavior.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#pragma once

#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wrapper for dap_ledger_find_by_name
 * @param a_name Ledger/network name to look up
 * @return Pointer to ledger structure or NULL if not found
 */
dap_ledger_t* dap_ledger_find_by_name_w(const char *a_name);

/**
 * @brief Wrapper for dap_chain_net_by_name
 * @param a_name Network name to look up
 * @return Pointer to network structure or NULL if not found
 */
dap_chain_net_t* dap_chain_net_by_name_w(const char *a_name);

/**
 * @brief Wrapper for dap_ledger_tx_find_by_hash
 * @param a_ledger Ledger to search in
 * @param a_tx_hash Transaction hash
 * @return Pointer to transaction datum or NULL if not found
 */
dap_chain_datum_tx_t* dap_ledger_tx_find_by_hash_w(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash);

/**
 * @brief Wrapper for dap_ledger_token_ticker_check
 * @param a_ledger Ledger to check in
 * @param a_token_ticker Token ticker to check
 * @return true if token exists, false otherwise
 */
bool dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker);

/**
 * @brief Wrapper for dap_ledger_token_info_by_name
 * @param a_ledger Ledger to get token info from
 * @param a_token_ticker Token ticker
 * @param a_version JSON version
 * @return JSON object with token info or NULL
 */
dap_json_t* dap_ledger_token_info_by_name_w(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version);

#ifdef __cplusplus
}
#endif
