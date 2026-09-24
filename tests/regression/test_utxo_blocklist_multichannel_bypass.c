/**
 * @file test_utxo_blocklist_multichannel_bypass.c
 * @brief Regression test for the UTXO blocklist multichannel bypass (EXPECTED TO FAIL
 *        while the bug is present; CMake marks it WILL_FAIL for that reason)
 *
 * Bug:
 * For a multichannel parent transaction (secondary OUT_EXT/OUT_STD output in a token
 * different from the parent's cached main ticker) central validation resolves the UTXO
 * blocklist by the parent's MAIN ticker (dap_chain_ledger.c: l_token =
 * l_item_out->cache_data.token_ticker) instead of the actual token of the spent 'out'
 * item. A blocklist entry recorded on the ACTUAL token of the output (the natural
 * action of that token's owner) is therefore not consulted, and a correctly signed
 * handcrafted transaction can spend the "frozen" output.
 *
 * Expected (desired) behavior asserted here:
 * 1. Wallet enumeration by the actual token hides the blocked output (works today).
 * 2. A handcrafted 'in' spend of the blocked output MUST be rejected with
 *    DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED (fails while the bug is present).
 * 3. A handcrafted 'in_cond' spend of the blocked output MUST be rejected with
 *    DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED (same check, fails while bug is present).
 *
 * Exit code is non-zero while any of the desired checks fails (i.e. while the bug
 * reproduces). Once the fix lands, this test goes green: remove WILL_FAIL from
 * tests/regression/CMakeLists.txt.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_test.h"
#include "test_utxo_blocklist_mc_common.h"

#define LOG_TAG "utxo_mc_bypass"

static int s_failures = 0;

static void s_expect(bool a_cond, const char *a_msg)
{
    if (a_cond) {
        printf("\t%s%s PASS.%s\n", TEXT_COLOR_GRN, a_msg, TEXT_COLOR_RESET);
        fflush(stdout);
    } else {
        printf("\t%s%s FAILED!%s\n", TEXT_COLOR_RED, a_msg, TEXT_COLOR_RESET);
        fflush(stdout);
        s_failures++;
    }
}

static void test_multichannel_bypass(void)
{
    dap_print_module_name("Regression: multichannel UTXO blocklist bypass (expected fail while bug present)");

    utxo_mc_ctx_t l_ctx;
    int l_init = utxo_mc_ctx_multichannel_init(&l_ctx);
    if (l_init != 0) {
        printf("\t%sScenario setup FAILED!%s\n", TEXT_COLOR_RED, TEXT_COLOR_RESET);
        fflush(stdout);
        s_failures++;
        return;
    }

    // Blocked target: parent out #0, actual token MCHN, parent main ticker SECND
    const uint32_t l_out_idx = 0;

    // Block the output in the ACTUAL token's blocklist - what the token owner would do
    int l_res = utxo_mc_block(UTXO_MC_TOK_NATIVE, l_ctx.tok_native, &l_ctx.parent_hash, l_out_idx);
    s_expect(l_res == 0, "token_update blocked parent:0 in actual-token (MCHN) blocklist");

    // 1. Wallet side is protected (enumeration by actual token)
    s_expect(!utxo_mc_wallet_lists(UTXO_MC_TOK_NATIVE, &l_ctx.spender_addr, &l_ctx.parent_hash, l_out_idx),
             "wallet enumeration hides blocked multichannel output");

    // 2. Central validation must reject a handcrafted 'in' spend of the blocked output
    l_res = utxo_mc_check_spend(&l_ctx.parent_hash, l_out_idx, UTXO_MC_TOK_NATIVE,
                                l_ctx.spender_key, &l_ctx.dst_addr, UTXO_MC_FUND_VALUE, false);
    if (l_res == 0)
        log_it(L_ERROR, "BUG PRESENT: blocked-in-%s output %s:%u passed central validation "
                        "(blocklist looked up by parent main ticker '%s')",
               UTXO_MC_TOK_NATIVE, dap_chain_hash_fast_to_str_static(&l_ctx.parent_hash),
               l_out_idx, l_ctx.parent_main_ticker);
    s_expect(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
             "central validation rejects handcrafted 'in' spend of blocked output");

    // 3. Same for an 'in_cond' spend (blocklist check is common for in/in_cond)
    l_res = utxo_mc_check_spend(&l_ctx.parent_hash, l_out_idx, UTXO_MC_TOK_NATIVE,
                                l_ctx.spender_key, &l_ctx.dst_addr, "999.5", true);
    if (l_res == 0)
        log_it(L_ERROR, "BUG PRESENT: blocked-in-%s output %s:%u passed central validation via in_cond",
               UTXO_MC_TOK_NATIVE, dap_chain_hash_fast_to_str_static(&l_ctx.parent_hash), l_out_idx);
    s_expect(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
             "central validation rejects handcrafted 'in_cond' spend of blocked output");

    utxo_mc_ctx_free(&l_ctx);
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (utxo_mc_setup_env() != 0) {
        log_it(L_ERROR, "Test environment setup failed");
        return 2;
    }
    test_multichannel_bypass();
    utxo_mc_teardown_env();

    if (s_failures) {
        log_it(L_ERROR, "=== %d desired-behavior check(s) FAILED - bypass reproduces in this build ===",
               s_failures);
        return 1;
    }
    log_it(L_NOTICE, "=== All desired-behavior checks passed - remove WILL_FAIL for this test ===");
    return 0;
}
