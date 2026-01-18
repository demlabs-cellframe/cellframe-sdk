/*
 * Authors:
 * AI Refactoring 2026
 * 
 * Copyright: Demlabs
 * License: All rights reserved
 *
 * dap_wallet_ledger_ops_impl.c - Implementation of ledger callbacks for wallet
 * 
 * This file implements Dependency Inversion Principle (DIP):
 * - wallet depends on interface (dap_wallet_ledger_ops.h)
 * - ledger provides implementation (this file)  
 * - wallet-shared registers the implementation at init
 */

#include "dap_wallet_ledger_ops.h"
#include "dap_chain_ledger.h"

// Wrapper functions that call real ledger functions

static uint256_t s_ledger_calc_balance_wrapper(
    dap_ledger_t *a_ledger,
    const dap_chain_addr_t *a_addr,
    const char *a_token_ticker)
{
    return dap_ledger_calc_balance(a_ledger, a_addr, a_token_ticker);
}

static dap_chain_datum_tx_t* s_ledger_tx_find_by_addr_wrapper(
    dap_ledger_t *a_ledger,
    const char *a_token_ticker,
    const dap_chain_addr_t *a_addr_from,
    dap_chain_hash_fast_t *a_hash_from)
{
    return dap_ledger_tx_find_by_addr(a_ledger, a_token_ticker, a_addr_from, a_hash_from);
}

static const char* s_ledger_tx_get_token_ticker_wrapper(
    dap_ledger_t *a_ledger,
    const dap_chain_hash_fast_t *a_tx_hash)
{
    return dap_ledger_tx_get_token_ticker_by_hash(a_ledger, a_tx_hash);
}

static bool s_ledger_tx_hash_is_used_out_wrapper(
    dap_ledger_t *a_ledger,
    const dap_chain_hash_fast_t *a_tx_hash,
    int a_out_idx,
    int *a_out_cond_idx)
{
    return dap_ledger_tx_hash_is_used_out_item(a_ledger, a_tx_hash, a_out_idx, a_out_cond_idx);
}

static void s_ledger_addr_get_token_ticker_all_wrapper(
    dap_ledger_t *a_ledger,
    dap_chain_addr_t *a_addr,
    char ***a_tickers,
    size_t *a_tickers_size)
{
    dap_ledger_addr_get_token_ticker_all(a_ledger, a_addr, a_tickers, a_tickers_size);
}

static const char* s_ledger_get_description_wrapper(
    dap_ledger_t *a_ledger,
    const char *a_token_ticker)
{
    return dap_ledger_get_description_by_ticker(a_ledger, a_token_ticker);
}

// Global ops structure
static const dap_wallet_ledger_ops_t s_ledger_ops = {
    .calc_balance = s_ledger_calc_balance_wrapper,
    .tx_find_by_addr = s_ledger_tx_find_by_addr_wrapper,
    .tx_get_token_ticker = s_ledger_tx_get_token_ticker_wrapper,
    .tx_hash_is_used_out = s_ledger_tx_hash_is_used_out_wrapper,
    .addr_get_token_ticker_all = s_ledger_addr_get_token_ticker_all_wrapper,
    .get_description = s_ledger_get_description_wrapper
};

/**
 * @brief Registers ledger operations for wallet
 * 
 * This function should be called from wallet-shared module initialization
 * to connect wallet with ledger through the DIP interface.
 */
void dap_wallet_ledger_ops_impl_register(void)
{
    dap_wallet_ledger_ops_register(&s_ledger_ops);
}
