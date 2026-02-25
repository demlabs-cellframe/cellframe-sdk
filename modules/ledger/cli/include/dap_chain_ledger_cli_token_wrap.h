/**
 * @file dap_chain_ledger_cli_token_wrap.h
 * @brief Wrapper functions for token CLI operations
 * 
 * This file declares wrapper functions for token operations that can be
 * mocked during unit testing. The wrappers provide an indirection layer
 * between CLI commands and actual token/ledger logic.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#pragma once

#include "dap_chain_ledger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wrapper for finding ledger by network name
 * @param a_net_name Network name
 * @return Ledger pointer or NULL if not found
 */
dap_ledger_t *dap_ledger_find_by_name_w(const char *a_net_name);

/**
 * @brief Wrapper for getting token info by name
 * @param a_ledger Ledger pointer
 * @param a_token_ticker Token ticker
 * @param a_version API version
 * @return JSON object with token info or NULL
 */
dap_json_t *dap_ledger_token_info_by_name_w(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version);

/**
 * @brief Wrapper for checking if token exists in ledger
 * @param a_ledger Ledger pointer
 * @param a_token_ticker Token ticker
 * @return true if token exists, false otherwise
 */
bool dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker);

#ifdef __cplusplus
}
#endif

