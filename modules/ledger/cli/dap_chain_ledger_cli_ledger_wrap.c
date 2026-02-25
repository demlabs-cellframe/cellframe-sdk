/**
 * @file dap_chain_ledger_cli_ledger_wrap.c
 * @brief Wrapper function implementations for ledger CLI commands
 * 
 * These wrapper functions delegate to the real implementations and can be
 * intercepted by the DAP Mock Framework during unit testing.
 * 
 * @author Cellframe Team
 * @copyright DeM Labs Inc. 2025
 * @license GPL-3.0
 */

#include "dap_chain_ledger_cli_ledger_wrap.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"

/**
 * @brief Wrapper for dap_ledger_find_by_name
 */
dap_ledger_t* dap_ledger_find_by_name_w(const char *a_name)
{
    return dap_ledger_find_by_name(a_name);
}

/**
 * @brief Wrapper for dap_chain_net_by_name
 */
dap_chain_net_t* dap_chain_net_by_name_w(const char *a_name)
{
    return dap_chain_net_by_name(a_name);
}

/**
 * @brief Wrapper for dap_ledger_tx_find_by_hash
 */
dap_chain_datum_tx_t* dap_ledger_tx_find_by_hash_w(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash)
{
    return dap_ledger_tx_find_by_hash(a_ledger, a_tx_hash);
}

/**
 * @brief Wrapper for dap_ledger_get_txs
 */
dap_hash_fast_t* dap_ledger_get_txs_w(dap_ledger_t *a_ledger, size_t *a_count,
                                       const char *a_token, dap_chain_addr_t *a_addr,
                                       size_t a_limit, size_t a_offset)
{
    return dap_ledger_get_txs(a_ledger, a_count, a_token, a_addr, a_limit, a_offset);
}

/**
 * @brief Wrapper for dap_ledger_token_ticker_check
 */
bool dap_ledger_token_ticker_check_w(dap_ledger_t *a_ledger, const char *a_token_ticker)
{
    return dap_ledger_token_ticker_check(a_ledger, a_token_ticker);
}

