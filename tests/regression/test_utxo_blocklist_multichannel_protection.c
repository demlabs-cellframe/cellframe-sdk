/**
 * @file test_utxo_blocklist_multichannel_protection.c
 * @brief Regression tests for behavior that currently WORKS and must not regress
 *        (all checks are expected to PASS on master)
 *
 * Covers:
 * 1. Multichannel parent, blocklist entry in the parent MAIN ticker only:
 *    - central validation rejects a handcrafted spend (main ticker is what central
 *      validation consults today);
 *    - wallet enumeration still RETURNS the output (wallet consults the actual
 *      token's blocklist) - documents why blocking a multichannel output requires
 *      TWO entries: one in the actual token (wallet side) and one in the parent
 *      main ticker (central validation side).
 * 2. Same parent after adding the second entry (in the actual token's blocklist),
 *    i.e. the documented dual-entry workaround:
 *    - wallet enumeration hides the output;
 *    - central validation rejects handcrafted 'in' and 'in_cond' spends.
 * 3. Single-token parent (actual token == parent main ticker), entry in its token:
 *    - wallet enumeration hides the output;
 *    - handcrafted 'in' spend rejected with DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED;
 *    - handcrafted 'in_cond' spend rejected the same way.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_test.h"
#include "test_utxo_blocklist_mc_common.h"

#define LOG_TAG "utxo_mc_protection"

static void test_multichannel_protection_flow(void)
{
    dap_print_module_name("Protection: multichannel blocklist entries (single scenario, two phases)");

    utxo_mc_ctx_t l_ctx;
    dap_assert_PIF(utxo_mc_ctx_multichannel_init(&l_ctx) == 0, "multichannel scenario initialized");

    const uint32_t l_out_idx = 0;

    // Phase 1: entry ONLY in the parent main ticker's blocklist (SECND), none in the actual (MCHN)
    dap_assert_PIF(utxo_mc_block(l_ctx.parent_main_ticker, l_ctx.tok_second,
                                 &l_ctx.parent_hash, l_out_idx) == 0,
                   "token_update blocked parent:0 in parent-main-ticker blocklist");

    // Central validation consults the parent main ticker: must reject
    int l_res = utxo_mc_check_spend(&l_ctx.parent_hash, l_out_idx, UTXO_MC_TOK_NATIVE,
                                    l_ctx.spender_key, &l_ctx.dst_addr, UTXO_MC_FUND_VALUE, false);
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
               "central validation rejects spend when parent-main-ticker entry present");

    // Wallet consults the actual token's blocklist: output is still visible/selectable
    dap_assert(utxo_mc_wallet_lists(UTXO_MC_TOK_NATIVE, &l_ctx.spender_addr,
                                    &l_ctx.parent_hash, l_out_idx),
               "wallet enumeration still lists output with main-ticker-only entry "
               "(dual entry required)");

    // Phase 2: add the second entry in the actual token's blocklist (dual-entry workaround)
    dap_assert_PIF(utxo_mc_block(UTXO_MC_TOK_NATIVE, l_ctx.tok_native,
                                 &l_ctx.parent_hash, l_out_idx) == 0,
                   "token_update blocked parent:0 in actual-token blocklist");

    dap_assert(!utxo_mc_wallet_lists(UTXO_MC_TOK_NATIVE, &l_ctx.spender_addr,
                                     &l_ctx.parent_hash, l_out_idx),
              "wallet enumeration hides output with dual entry");

    l_res = utxo_mc_check_spend(&l_ctx.parent_hash, l_out_idx, UTXO_MC_TOK_NATIVE,
                                l_ctx.spender_key, &l_ctx.dst_addr, "999.5", false);
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
               "central validation rejects 'in' spend with dual entry");

    l_res = utxo_mc_check_spend(&l_ctx.parent_hash, l_out_idx, UTXO_MC_TOK_NATIVE,
                                l_ctx.spender_key, &l_ctx.dst_addr, "999.5", true);
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
               "central validation rejects 'in_cond' spend with dual entry");

    utxo_mc_ctx_free(&l_ctx);
    dap_pass_msg("multichannel protection flow locked");
}

static void test_single_token_blocking(void)
{
    dap_print_module_name("Protection: single-token output blocking (no multichannel)");

    utxo_mc_ctx_t l_ctx;
    dap_assert_PIF(utxo_mc_ctx_single_init(&l_ctx) == 0, "single-token scenario initialized");

    const uint32_t l_out_idx = 0;

    dap_assert_PIF(utxo_mc_block(UTXO_MC_TOK_SINGLE, l_ctx.tok_single,
                                 &l_ctx.single_parent_hash, l_out_idx) == 0,
                   "token_update blocked parent:0 in token blocklist");

    dap_assert(!utxo_mc_wallet_lists(UTXO_MC_TOK_SINGLE, &l_ctx.spender_addr,
                                     &l_ctx.single_parent_hash, l_out_idx),
              "wallet enumeration hides blocked single-token output");

    int l_res = utxo_mc_check_spend(&l_ctx.single_parent_hash, l_out_idx, UTXO_MC_TOK_SINGLE,
                                    l_ctx.spender_key, &l_ctx.dst_addr, UTXO_MC_FUND_VALUE, false);
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
               "central validation rejects 'in' spend of blocked single-token output");

    l_res = utxo_mc_check_spend(&l_ctx.single_parent_hash, l_out_idx, UTXO_MC_TOK_SINGLE,
                                l_ctx.spender_key, &l_ctx.dst_addr, "999.5", true);
    dap_assert(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
               "central validation rejects 'in_cond' spend of blocked single-token output");

    utxo_mc_ctx_free(&l_ctx);
    dap_pass_msg("single-token blocking behavior locked");
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    dap_print_module_name("UTXO blocklist multichannel protection regression tests");
    if (utxo_mc_setup_env() != 0) {
        log_it(L_ERROR, "Test environment setup failed");
        return 2;
    }
    test_multichannel_protection_flow();
    test_single_token_blocking();
    utxo_mc_teardown_env();
    log_it(L_NOTICE, "=== UTXO blocklist protection tests complete ===");
    return 0;
}
