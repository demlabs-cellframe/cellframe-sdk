/*
 * Regression test for the consensus-era decision.
 *
 * Every rule that differs between the legacy 5.7 behaviour and the new one asks
 * the same question: does the new era bind for this block? The answer decides
 * whether a reward claim is capped, whether a vote may use the reserved slot past
 * the last answer, whether a HAL/HRL entry is scoped to its chain and whether the
 * ESBOCS strict-era checks run. A wrong answer in either direction splits the
 * network: too strict rejects history the legacy nodes accepted, too lenient
 * accepts what the upgraded ones reject.
 *
 * The decision is a pure function of the decree's bounds and the block being
 * judged, so all of its branches are pinned here:
 *
 *   - no version decree                 -> legacy era everywhere;
 *   - a block-height boundary           -> new era exactly from that block, and it
 *                                          wins over the timestamp (the creation
 *                                          time of the decree is not a chain
 *                                          position);
 *   - a legacy-mode network             -> the timestamp boundary is ignored until
 *                                          a height arrives (that is what the mode
 *                                          is for: waiting for a coordinated
 *                                          switch);
 *   - a network without legacy mode     -> the timestamp boundary of an older
 *                                          decree still applies;
 *   - no block context (height 0)       -> still decided by the timestamp.
 */

#include <stdio.h>

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_test.h"

#define LOG_TAG "esbocs_era_test"

#define V_NO_DECREE   0
#define V_STRICT      2
#define H_ACTIVATE    1000
#define TS_BOUNDARY   1700000000

static void s_expect(bool a_got, bool a_expected, const char *a_what)
{
    if (a_got != a_expected) {
        dap_assert_PIF(false, a_what);
        return;
    }
    dap_pass_msg(a_what);
}

int main(void)
{
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("ESBOCS consensus era");

    // No decree: the legacy era everywhere, whatever the bounds say.
    s_expect(dap_chain_esbocs_era_decision(V_NO_DECREE, 0, 0, false, 500, 0), false,
             "no decree -> legacy");
    s_expect(dap_chain_esbocs_era_decision(V_NO_DECREE, H_ACTIVATE, 0, false, 5000, 1800000000), false,
             "no decree with a height left over -> legacy");

    // A height boundary binds exactly from that block, and ignores the timestamp:
    // a block older than the decree's creation but above the height is new-era.
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, H_ACTIVATE, 0, false, H_ACTIVATE - 1, 1900000000), false,
             "block before the height -> legacy");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, H_ACTIVATE, 0, false, H_ACTIVATE, 1), true,
             "the activation block itself -> new era");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, H_ACTIVATE, 0, false, H_ACTIVATE + 1, 1), true,
             "block after the height -> new era");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, H_ACTIVATE, TS_BOUNDARY, false, H_ACTIVATE - 1, TS_BOUNDARY + 100), false,
             "height wins over a timestamp already passed");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, H_ACTIVATE, TS_BOUNDARY, true, H_ACTIVATE, 0), true,
             "legacy mode does not silence a height boundary");

    // Legacy-mode network, no height: waiting, so the old timestamp boundary is
    // ignored in both directions.
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, 0, TS_BOUNDARY, true, 5000, TS_BOUNDARY + 100), false,
             "legacy mode ignores a passed timestamp boundary");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, 0, 0, true, 5000, 1900000000), false,
             "legacy mode without any boundary -> legacy");

    // A network that did not declare itself legacy: an older decree keeps its
    // timestamp boundary, and a missing boundary means "whole chain".
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, 0, TS_BOUNDARY, false, 5000, TS_BOUNDARY - 1), false,
             "timestamp boundary not reached -> legacy");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, 0, TS_BOUNDARY, false, 5000, TS_BOUNDARY), true,
             "timestamp boundary reached -> new era");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, 0, 0, false, 1, 0), true,
             "decree without any boundary -> whole chain is new era");

    // No block context (mempool, zerochain event): the caller passes the current
    // chain position; the decision must still be the boundary one.
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, H_ACTIVATE, 0, false, 0, 1900000000), false,
             "no block context below the height -> legacy");
    s_expect(dap_chain_esbocs_era_decision(V_STRICT, 0, TS_BOUNDARY, false, 0, TS_BOUNDARY + 1), true,
             "no block context past the timestamp -> new era");

    printf("All consensus era tests passed (14 checks)\n");
    return 0;
}
