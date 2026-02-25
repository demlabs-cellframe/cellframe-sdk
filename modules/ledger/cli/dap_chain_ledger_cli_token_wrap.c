/**
 * @file dap_chain_ledger_cli_token_wrap.c
 * @brief Wrapper functions for token CLI operations
 * 
 * This file implements wrapper functions for token operations that can be
 * mocked during unit testing using the DAP Mock Framework with --wrap linker flag.
 * 
 * Each wrapper function simply delegates to the real implementation,
 * but can be intercepted by mock wrappers during testing.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include "dap_chain_ledger.h"
#include "dap_chain_ledger_cli_token_wrap.h"

/**
 * @brief Wrapper for finding ledger by network name
 */
dap_ledger_t *dap_ledger_find_by_name_w(const char *a_net_name)
{
    return dap_ledger_find_by_name(a_net_name);
}

/**
 * @brief Wrapper for getting token info by name
 */
dap_json_t *dap_ledger_token_info_by_name_w(dap_ledger_t *a_ledger, const char *a_token_ticker, int a_version)
{
    return dap_ledger_token_info_by_name(a_ledger, a_token_ticker, a_version);
}

/**
 * @brief Wrapper for checking if token exists in ledger
 */
bool dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    return dap_ledger_token_ticker_check(a_ledger, a_token_ticker);
}

