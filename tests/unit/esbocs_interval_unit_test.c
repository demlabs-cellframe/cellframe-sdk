/*
 * Regression test for the activation-interval parser.
 *
 * A consensus-version decree binds at a block height, and the operator gives the
 * command a time interval ("switch in a week"). The interval is turned into a
 * height through the chain's measured block cadence, so a wrong parse silently
 * schedules the switch at the wrong chain position - which is the one thing a
 * consensus change cannot afford.
 *
 * The cases pinned here are the accepted spellings, the implied unit, and the
 * rejection of everything ambiguous: an empty string, a bare unit, a zero value
 * and an unknown suffix must all come back as 0 so the command refuses to build
 * the decree instead of guessing.
 */

#include <stdio.h>

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_decree.h"
#include "dap_test.h"

#define LOG_TAG "esbocs_interval_test"

static void s_check(const char *a_str, uint64_t a_expected)
{
    uint64_t l_got = dap_chain_datum_decree_parse_interval_sec(a_str);
    if (l_got != a_expected) {
        dap_assert_PIF(false, a_str ? a_str : "(null)");
        return;
    }
    dap_pass_msg(a_str);
}

int main(void)
{
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("ESBOCS activation interval");

    // Accepted spellings and the unit each suffix implies.
    s_check("90", 90);
    s_check("90s", 90);
    s_check("30m", 30 * 60);
    s_check("36h", 36 * 3600);
    s_check("7d", 7 * 86400);
    s_check("2w", 2 * 604800);
    s_check("90S", 90);
    s_check("30M", 1800);
    s_check("36H", 129600);
    s_check("7D", 604800);

    // Ambiguous or malformed input must be refused, never defaulted.
    s_check("", 0);
    s_check("m", 0);
    s_check("0", 0);
    s_check("0d", 0);
    s_check("7x", 0);
    s_check("-7d", 0);
    s_check("7 d", 0);

    printf("All activation interval tests passed (17 checks)\n");
    return 0;
}
