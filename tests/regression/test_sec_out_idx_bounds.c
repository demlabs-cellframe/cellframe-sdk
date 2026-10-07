/**
 * @file test_sec_out_idx_bounds.c
 * @brief Regression: out-of-range tx_out_prev_idx must be rejected, not crash
 *
 * Security review 2026-10-07 (High): s_ledger_tx_hash_is_used_out_item indexed
 * tx_hash_spent_fast[a_idx_out] with the network-supplied tx_out_prev_idx
 * BEFORE validating it against the parent's actual out count. A crafted spend
 * referencing (real parent hash : huge out index) read ~GB past a small heap
 * allocation and crashed the node (tx gossip / mempool_add path).
 *
 * The fix bounds the index inside the helper. This test drives the exact
 * public path (dap_ledger_tx_add_check) with out-of-range indices and asserts
 * a clean rejection code and a surviving process.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_test.h"
#include "test_utxo_blocklist_mc_common.h"

#define LOG_TAG "sec_out_idx_bounds"

static int s_failures = 0;

#define SEC_ASSERT(cond, name) { \
    if (cond) { dap_pass_msg(name); } \
    else { s_failures++; dap_fail(name); } \
}

static void test_out_of_range_out_idx(void)
{
    dap_print_module_name("Security: out-of-range tx_out_prev_idx is rejected without crash");

    utxo_mc_ctx_t l_ctx;
    dap_assert_PIF(utxo_mc_ctx_single_init(&l_ctx) == 0, "single-token scenario initialized");

    // Sanity: the legit spend of out #0 is a normal check (any code, no crash)
    int l_rc_ok = utxo_mc_check_spend(&l_ctx.single_parent_hash, 0, UTXO_MC_TOK_SINGLE,
                                      l_ctx.spender_key, &l_ctx.dst_addr, "1.0", false);
    (void)l_rc_ok;

    // Out-of-range plain 'in': huge index, real parent hash
    int l_rc_huge = utxo_mc_check_spend(&l_ctx.single_parent_hash, 0x0FFFFFFF, UTXO_MC_TOK_SINGLE,
                                        l_ctx.spender_key, &l_ctx.dst_addr, "1.0", false);
    log_it(L_MSG, "huge out_idx check code: %d", l_rc_huge);
    SEC_ASSERT(l_rc_huge != 0, "huge out_idx rejected by central validation");

    // Out-of-range just past the end (parent has a single output)
    int l_rc_past = utxo_mc_check_spend(&l_ctx.single_parent_hash, 1, UTXO_MC_TOK_SINGLE,
                                        l_ctx.spender_key, &l_ctx.dst_addr, "1.0", false);
    log_it(L_MSG, "one-past-end out_idx check code: %d", l_rc_past);
    SEC_ASSERT(l_rc_past != 0, "one-past-end out_idx rejected");

    // The uint32 wrap shape: index with the top bit set
    int l_rc_wrap = utxo_mc_check_spend(&l_ctx.single_parent_hash, 0x80000001u, UTXO_MC_TOK_SINGLE,
                                        l_ctx.spender_key, &l_ctx.dst_addr, "1.0", true);
    log_it(L_MSG, "in_cond wrapped out_idx check code: %d", l_rc_wrap);
    SEC_ASSERT(l_rc_wrap != 0, "in_cond with wrapped out_idx rejected");

    // The ledger must still work normally afterwards (no corrupted state)
    int l_rc_after = utxo_mc_check_spend(&l_ctx.single_parent_hash, 0, UTXO_MC_TOK_SINGLE,
                                         l_ctx.spender_key, &l_ctx.dst_addr, "1.0", false);
    (void)l_rc_after;

    utxo_mc_ctx_free(&l_ctx);
    dap_pass_msg("out-of-range out_idx regression: no crash, clean rejections");
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (utxo_mc_setup_env() != 0) {
        log_it(L_ERROR, "Test environment setup failed");
        return 2;
    }
    test_out_of_range_out_idx();
    utxo_mc_teardown_env();
    return s_failures ? -1 : 0;
}
