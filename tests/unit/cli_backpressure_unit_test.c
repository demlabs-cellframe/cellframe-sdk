/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2026
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file cli_backpressure_unit_test.c
 * @brief Unit tests for the CLI/RPC backpressure gate added to fight the
 *        RPC-overload described in cellframe_node_rpc_overload_research_2026_09.
 * @details Exercises the two mechanisms that are reachable without a live
 *          socket or a running dap_cli_server_init()'d server:
 *           - dap_cli_server_backpressure_acquire()/_release() inflight
 *             caps, for both the regular and HEAVY counters, shared by the
 *             CLI-port path (s_cli_cmd_schedule) and the signed HTTP
 *             /exec_cmd path (dap_json_rpc_request_handler.c).
 *           - DAP_CLI_CMD_FLAG_HEAVY classification via
 *             dap_cli_server_cmd_flags_set(), i.e. that a command a service
 *             marked HEAVY is actually routed through the heavy counter and
 *             an unmarked command through the regular one.
 *          The per-/16 rate limiter (s_cli_rate_limit_check) and the
 *          dead-client registry (s_cli_live_client_check) are both static
 *          to dap_cli_server.c and only reachable through a live esocket,
 *          so they are covered by an integration test instead (see
 *          cellframe-sdk/tests/integration/cli_backpressure/), not here.
 * @date 2026-09-24
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_cli_server.h"
#include "dap_test.h"

#define LOG_TAG "cli_backpressure_unit_test"

// Config defaults from dap_cli_server.c: s_cli_max_inflight = 32,
// s_cli_max_inflight_heavy = 4. dap_cli_server_init() is never called in
// this test file (no config/socket needed for the gate itself), so these
// are the values in effect.
#define DEFAULT_MAX_INFLIGHT        32
#define DEFAULT_MAX_INFLIGHT_HEAVY  4

static const char c_light_req[]  = "{\"method\":\"cli_backpressure_test_light_cmd\",\"params\":[[]],\"id\":\"1\",\"version\":1}";
static const char c_heavy_req[]  = "{\"method\":\"cli_backpressure_test_heavy_cmd\",\"params\":[[]],\"id\":\"1\",\"version\":1}";

static int s_stub_cmd_func(int argc, char **argv, void **a_str_reply, int a_version)
{
    (void)argc; (void)argv; (void)a_str_reply; (void)a_version;
    return 0;
}

/**
 * @brief Unit Test 1: acquire/release round-trip never leaks a slot
 * @details A single acquire followed by its matching release must return
 *          the inflight counter to a state where DEFAULT_MAX_INFLIGHT more
 *          acquires succeed - i.e. release actually decrements, not just
 *          "doesn't crash".
 */
static void s_test_acquire_release_round_trip(void)
{
    dap_print_module_name("Unit Test 1: backpressure acquire/release round-trip");

    bool l_is_heavy = true; // poison value, must be flipped to false below
    bool l_ok = dap_cli_server_backpressure_acquire(c_light_req, &l_is_heavy);
    dap_assert(l_ok, "Regular-command acquire succeeds under the limit");
    dap_assert(!l_is_heavy, "Regular command is not classified as heavy");
    dap_cli_server_backpressure_release(l_is_heavy);

    // If release actually freed the slot, we can now acquire+release the
    // full regular limit again without ever hitting the cap.
    for (int i = 0; i < DEFAULT_MAX_INFLIGHT; ++i) {
        bool l_heavy_flag = true;
        dap_assert_PIF(dap_cli_server_backpressure_acquire(c_light_req, &l_heavy_flag),
                       "Repeated acquire/release cycles never accumulate leaked slots");
        dap_cli_server_backpressure_release(l_heavy_flag);
    }

    dap_pass_msg("Acquire/release round-trip test passed");
}

/**
 * @brief Unit Test 2: regular-command inflight cap is enforced and independent of HEAVY
 * @details Saturate the regular counter to its default limit without
 *          releasing; the next acquire must be refused (429 in production),
 *          and the HEAVY counter must be entirely unaffected by it.
 */
static void s_test_regular_inflight_cap(void)
{
    dap_print_module_name("Unit Test 2: regular inflight cap enforcement");

    bool l_heavy_flags[DEFAULT_MAX_INFLIGHT];
    int l_acquired = 0;
    for (; l_acquired < DEFAULT_MAX_INFLIGHT; ++l_acquired) {
        bool l_is_heavy = true;
        bool l_ok = dap_cli_server_backpressure_acquire(c_light_req, &l_is_heavy);
        if (!l_ok)
            break;
        l_heavy_flags[l_acquired] = l_is_heavy;
    }
    dap_assert(l_acquired == DEFAULT_MAX_INFLIGHT,
              "Exactly max_inflight regular acquires succeed before saturation");

    bool l_is_heavy_extra = true;
    bool l_extra_ok = dap_cli_server_backpressure_acquire(c_light_req, &l_is_heavy_extra);
    dap_assert(!l_extra_ok, "Acquire beyond max_inflight is refused (would be a 429 in production)");

    // HEAVY counter must still have its own full budget - the two caps are
    // independent, so a light-command flood must never starve heavy
    // commands (or vice versa).
    bool l_heavy_ok = true;
    bool l_is_heavy_check = false;
    l_heavy_ok = dap_cli_server_backpressure_acquire(c_heavy_req, &l_is_heavy_check);
    dap_assert(l_heavy_ok && l_is_heavy_check,
              "Heavy counter is untouched by regular-counter saturation");
    dap_cli_server_backpressure_release(l_is_heavy_check);

    // Cleanup: release every slot we acquired above so later tests in this
    // binary see a clean counter.
    for (int i = 0; i < l_acquired; ++i)
        dap_cli_server_backpressure_release(l_heavy_flags[i]);

    dap_pass_msg("Regular inflight cap test passed");
}

/**
 * @brief Registers the throwaway HEAVY command used by c_heavy_req.
 * @details Flags it DAP_CLI_CMD_FLAG_HEAVY via dap_cli_server_cmd_flags_set()
 *          exactly the way a service (DEX, xchange, stake, ...) would in its
 *          own init function. Called once from main() before any test that
 *          sends c_heavy_req - an unregistered command name is never
 *          classified as heavy (s_cmd_is_heavy() only consults commands
 *          dap_cli_server_cmd_find() can locate), so every test relying on
 *          c_heavy_req routing through the heavy counter needs this to have
 *          already run.
 */
static void s_register_heavy_test_command(void)
{
    dap_cli_cmd_t *l_cmd = dap_cli_server_cmd_add("cli_backpressure_test_heavy_cmd", s_stub_cmd_func, NULL,
                                                   "test heavy command", "test heavy command (extended)");
    dap_assert_PIF(l_cmd != NULL, "Test heavy command registers");
    dap_assert_PIF(!(l_cmd->flags & DAP_CLI_CMD_FLAG_HEAVY), "Command is not heavy before flags_set() is called");

    dap_cli_server_cmd_flags_set("cli_backpressure_test_heavy_cmd", DAP_CLI_CMD_FLAG_HEAVY);
    dap_cli_cmd_t *l_cmd_after = dap_cli_server_cmd_find("cli_backpressure_test_heavy_cmd");
    dap_assert_PIF(l_cmd_after != NULL, "Test heavy command is still findable after flags_set()");
    dap_assert_PIF(l_cmd_after->flags & DAP_CLI_CMD_FLAG_HEAVY,
                  "dap_cli_server_cmd_flags_set() actually sets DAP_CLI_CMD_FLAG_HEAVY");
}

/**
 * @brief Unit Test 3: HEAVY-flagged command is capped separately from regular commands
 * @details Assumes s_register_heavy_test_command() already ran (see main()).
 *          Verifies dap_cli_server_backpressure_acquire() routes a
 *          HEAVY-flagged command through the (much smaller) heavy counter,
 *          saturating at DEFAULT_MAX_INFLIGHT_HEAVY instead of
 *          DEFAULT_MAX_INFLIGHT.
 */
static void s_test_heavy_command_classification(void)
{
    dap_print_module_name("Unit Test 3: HEAVY command classification and cap");

    bool l_heavy_flags[DEFAULT_MAX_INFLIGHT_HEAVY];
    int l_acquired = 0;
    for (; l_acquired < DEFAULT_MAX_INFLIGHT_HEAVY; ++l_acquired) {
        bool l_is_heavy = false;
        bool l_ok = dap_cli_server_backpressure_acquire(c_heavy_req, &l_is_heavy);
        if (!l_ok)
            break;
        dap_assert_PIF(l_is_heavy, "Flagged command is classified as heavy on every acquire");
        l_heavy_flags[l_acquired] = l_is_heavy;
    }
    dap_assert(l_acquired == DEFAULT_MAX_INFLIGHT_HEAVY,
              "Exactly max_inflight_heavy acquires succeed for a HEAVY command "
              "(much smaller than the regular cap - this is the whole point of "
              "the HEAVY class: a DEX/xchange/stake crawler can't exhaust the "
              "budget light commands like wallet info/tx_create need)");

    bool l_is_heavy_extra = false;
    bool l_extra_ok = dap_cli_server_backpressure_acquire(c_heavy_req, &l_is_heavy_extra);
    dap_assert(!l_extra_ok, "Acquire beyond max_inflight_heavy is refused");

    for (int i = 0; i < l_acquired; ++i)
        dap_cli_server_backpressure_release(l_heavy_flags[i]);

    dap_pass_msg("HEAVY command classification test passed");
}

/**
 * @brief Unit Test 4: unrecognized / malformed request never crashes or is misclassified
 * @details A request that doesn't parse as JSON, or parses but has no
 *          "method" field, or names a command that was never registered,
 *          must all be treated as non-heavy and still subject to (and
 *          released from) the regular counter - never crash, never leak.
 */
static void s_test_malformed_request_is_safe(void)
{
    dap_print_module_name("Unit Test 4: malformed/unknown request handling");

    static const char *c_bad_requests[] = {
        "not json at all",
        "{}",
        "{\"no_method_field\":true}",
        "{\"method\":\"cli_backpressure_test_command_that_was_never_registered\"}",
    };
    for (size_t i = 0; i < sizeof(c_bad_requests) / sizeof(c_bad_requests[0]); ++i) {
        bool l_is_heavy = true;
        bool l_ok = dap_cli_server_backpressure_acquire(c_bad_requests[i], &l_is_heavy);
        dap_assert_PIF(l_ok, "Malformed/unknown request still gets an acquire slot (fail-open, not fail-closed)");
        dap_assert_PIF(!l_is_heavy, "Malformed/unknown request is never misclassified as heavy");
        dap_cli_server_backpressure_release(l_is_heavy);
    }

    // NULL request string: also must not crash, and must be treated as non-heavy.
    bool l_is_heavy_null = true;
    bool l_ok_null = dap_cli_server_backpressure_acquire(NULL, &l_is_heavy_null);
    dap_assert(l_ok_null, "NULL request string still gets an acquire slot");
    dap_assert(!l_is_heavy_null, "NULL request string is never misclassified as heavy");
    dap_cli_server_backpressure_release(l_is_heavy_null);

    dap_pass_msg("Malformed request handling test passed");
}

int main(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);

    printf("CLI Backpressure Unit Tests starting...\n"); fflush(stdout);
    dap_print_module_name("CLI Backpressure Unit Tests");

    // Must run before any test that sends c_heavy_req - see the function's
    // own doc comment for why.
    s_register_heavy_test_command();

    s_test_acquire_release_round_trip();
    s_test_regular_inflight_cap();
    s_test_heavy_command_classification();
    s_test_malformed_request_is_safe();

    printf("All CLI backpressure unit tests passed (4 tests)!\n"); fflush(stdout);

    return 0;
}
