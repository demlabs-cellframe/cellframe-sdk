/*
 * Regression test for the esbocs_state payload layout.
 *
 * The snapshot section that carries the consensus parameters has grown twice
 * (v1 -> v2 added the era history, v2 -> v3 the activation height), so a payload
 * on disk must be addressed by the size of the version that wrote it.
 *
 * This is not academic: with the v1 payload read as if it started with the v2
 * header, the record pointer shifts by four bytes, the bounds check on the
 * emergency-address count fails and the section is rejected. A rejected section
 * withdraws the snapshot's complete-state claim, so the node silently replays
 * the whole chain on every start - the exact cost the snapshot exists to avoid.
 *
 * The numbers pinned here are the two real payloads from the live nodes:
 *
 *   KelVPN, v1, 526 bytes: 64-byte header + 6 emergency records of 77 bytes;
 *   Scorpion, v3, 511 bytes: 76-byte header + 5 emergency records + 5 eras.
 *
 * Both must fit exactly, and the v1 one must NOT fit under a 68-byte header -
 * that is the bug this test keeps from coming back.
 */

#include <stdio.h>

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_test.h"

#define LOG_TAG "esbocs_state_test"

// The on-disk record shapes: an emergency record holds one signing address, an
// era record is { uint64 ts_effective; uint16 value; } packed. The era struct is
// private to the module, so its size is pinned here as the format contract.
#define EM_REC_SIZE   sizeof(dap_chain_addr_t)
#define ERA_REC_SIZE  10u

static void s_check_size(uint32_t a_format, size_t a_expected, const char *a_what)
{
    size_t l_got = dap_chain_esbocs_state_hdr_size(a_format);
    if (l_got != a_expected) {
        dap_assert_PIF(false, a_what);
        return;
    }
    dap_pass_msg(a_what);
}

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
    dap_print_module_name("ESBOCS state payload");

    // Header size per format version, and the refusal to guess an unknown one.
    s_check_size(DAP_CHAIN_ESBOCS_STATE_FORMAT_V1, 64, "v1 header is 64 bytes");
    s_check_size(DAP_CHAIN_ESBOCS_STATE_FORMAT_V2, 68, "v2 header is 68 bytes");
    s_check_size(DAP_CHAIN_ESBOCS_STATE_FORMAT_V3, 76, "v3 header is 76 bytes");
    s_check_size(0, 0, "no format version -> unknown");
    s_check_size(4, 0, "a future format version -> unknown");

    // The address record size is part of the same on-disk contract: a change here
    // makes every payload already written unreadable, so it is asserted too.
    s_expect(EM_REC_SIZE == 77, true, "an emergency record (one address) is 77 bytes");
    s_expect(ERA_REC_SIZE == 10, true, "an era record is 10 bytes");

    // The live KelVPN payload: v1, 6 emergency addresses, no era history.
    const size_t l_kelvpn_size = 526;
    s_expect(l_kelvpn_size - dap_chain_esbocs_state_hdr_size(DAP_CHAIN_ESBOCS_STATE_FORMAT_V1)
                    == 6 * EM_REC_SIZE, true, "KelVPN v1 payload fits after a 64-byte header");
    s_expect(l_kelvpn_size - 68 >= 6 * EM_REC_SIZE, false,
             "the same payload does not fit after a 68-byte header (the regression)");

    // The live Scorpion payload: v3, 5 emergency addresses, 5 era records.
    const size_t l_scorpion_size = 511;
    s_expect(l_scorpion_size - dap_chain_esbocs_state_hdr_size(DAP_CHAIN_ESBOCS_STATE_FORMAT_V3)
                    == 5 * EM_REC_SIZE + 5 * ERA_REC_SIZE, true,
             "Scorpion v3 payload fits after a 76-byte header");

    printf("All esbocs state payload tests passed (10 checks)\n");
    return 0;
}
