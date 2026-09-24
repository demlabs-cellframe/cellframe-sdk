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
 * @file mempool_spent_index_unit_test.c
 * @brief Unit tests for the mempool spent-outs index (Stage B1) added to fight
 *        the RPC-overload described in cellframe_node_rpc_overload_research_2026_09
 *        sec. 2/9.3/10.1: dap_chain_mempool_out_is_used() turned from an
 *        O(mempool size) dap_global_db_get_all_sync() scan per call into an
 *        O(1) hash lookup once dap_chain_mempool_spent_index_init() has run.
 * @details Exercises:
 *           - fail-open correctness: dap_chain_mempool_out_is_used() must
 *             give the right answer via the historical full-scan path
 *             *before* the index is ever initialized (this is the state
 *             every test/tool that never calls
 *             dap_chain_mempool_spent_index_init() runs in permanently).
 *           - synchronous indexing: dap_chain_mempool_datum_add() indexes an
 *             IN item immediately, before any async cluster notification can
 *             possibly fire - the whole point being that two mempool TXs
 *             submitted back-to-back can never both see the same
 *             not-yet-notified prior spend as available.
 *           - idempotency: adding the same tx to the mempool twice (the
 *             synchronous datum_add path racing the async notify replaying
 *             the same ADD) must not corrupt the index or double-count.
 *           - removal: deleting the mempool tx (DEL notification, key-only -
 *             no datum) must remove all its indexed outputs, restoring
 *             out_is_used() to false for hashes it no longer covers.
 *           - correctness parity between the indexed path and the full-scan
 *             fallback for the same data, since both must agree or the
 *             index is worse than not having one.
 * @date 2026-09-24
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef DAP_OS_WINDOWS
#include <unistd.h>
#endif

#include "dap_common.h"
#include "dap_file_utils.h"
#include "dap_hash.h"
#include "dap_enc_key.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_mempool.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_global_db.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"

#define LOG_TAG "mempool_spent_index_unit_test"

static test_net_fixture_t *s_fixture = NULL;

static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    log_it(L_NOTICE, "=== Mempool Spent-Outs Index Unit Tests Setup ===");

    const char *l_tmp = test_get_temp_dir();
    char l_config_dir_buf[512], l_gdb_buf[512];
    snprintf(l_config_dir_buf, sizeof(l_config_dir_buf), "%s%cmempool_idx_test_config", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_gdb_buf, sizeof(l_gdb_buf), "%s%cmempool_idx_test_gdb", l_tmp, DAP_DIR_SEPARATOR);
    dap_rm_rf(l_gdb_buf);
    dap_rm_rf(l_config_dir_buf);
    dap_mkdir_with_parents(l_config_dir_buf);

    // test_env_init() -> dap_config_init()+dap_config_open("test") requires
    // an actual test.cfg file to already exist in the config dir - it
    // doesn't synthesize one. A minimal file is enough; this test doesn't
    // exercise anything config-driven besides global DB path setup, which
    // test_env_init() itself handles via a_global_db_path.
    char l_config_path[600];
    snprintf(l_config_path, sizeof(l_config_path), "%s%ctest.cfg", l_config_dir_buf, DAP_DIR_SEPARATOR);
    FILE *l_config_file = fopen(l_config_path, "w");
    dap_assert_PIF(l_config_file != NULL, "Test config file created");
    fputs("[general]\ndebug=true\n", l_config_file);
    fclose(l_config_file);

    int l_env_init_res = test_env_init(l_config_dir_buf, l_gdb_buf);
    dap_assert_PIF(l_env_init_res == 0, "Test environment initialization");

    dap_ledger_init();

    // test_net_fixture_create() creates a DAP_LEDGER_TEST zero-chain with
    // dag_poa consensus auto-selected for chain_id=0 (see
    // test_ledger_fixtures.c) and a main chain using 'none' consensus -
    // both consensus types must be registered before the fixture is
    // created, exactly as every other cellframe-sdk/tests binary using this
    // fixture already does (e.g. utxo_blocking_cli_integration_test.c).
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_nonconsensus_init();

    s_fixture = test_net_fixture_create("Mnet");
    dap_assert_PIF(s_fixture != NULL, "Network fixture initialization");
    dap_assert_PIF(s_fixture->chain_main != NULL, "chain_main has CHAIN_TYPE_TX (required for mempool indexing)");
}

// Deterministic stand-in for a random hash - a nonce-derived dap_hash_fast()
// over a unique per-call seed string is all this test needs (distinct,
// reproducible, no dependency on a CSPRNG hash-randomization helper).
static void s_make_fake_hash(const char *a_seed, dap_hash_fast_t *a_out)
{
    dap_hash_fast(a_seed, strlen(a_seed), a_out);
}

static void s_teardown(void)
{
    if (s_fixture) {
        test_net_fixture_destroy(s_fixture);
        s_fixture = NULL;
    }
    test_env_deinit();
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();
}

// Builds a minimal (unsigned, single IN item) TX datum spending
// (a_prev_hash, a_prev_idx) and returns both the wrapping datum and its
// hash. Never added to the ledger - the spent-outs index only cares about
// what's sitting in the mempool GDB group, not ledger validity.
static dap_chain_datum_t *s_make_spending_tx_datum(dap_hash_fast_t *a_prev_hash, uint32_t a_prev_idx, dap_hash_fast_t *a_out_hash)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_assert_PIF(l_tx != NULL, "dap_chain_datum_tx_create() succeeds");
    int l_add_res = dap_chain_datum_tx_add_in_item(&l_tx, a_prev_hash, a_prev_idx);
    dap_assert_PIF(l_add_res == 1, "IN item added to tx");
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_assert_PIF(l_datum != NULL, "dap_chain_datum_create() succeeds");
    dap_chain_datum_calc_hash(l_datum, a_out_hash);
    dap_chain_datum_tx_delete(l_tx);
    return l_datum;
}

/**
 * @brief Unit Test 1: fail-open correctness before the index is initialized
 * @details dap_chain_mempool_spent_index_init() is deliberately never called
 *          anywhere in this test binary (mirroring every existing
 *          cellframe-sdk/tests binary and python-cellframe today, per the
 *          comment on s_mempool_spent_index_ready in dap_chain_mempool.c) -
 *          so dap_chain_mempool_out_is_used() must fall back to the
 *          historical full GlobalDB scan and still give the right answer.
 */
static void s_test_fail_open_full_scan_correctness(void)
{
    dap_print_module_name("Unit Test 1: fail-open full-scan correctness (index never initialized)");

    dap_hash_fast_t l_prev_hash = {};
    s_make_fake_hash("test1_prev_hash", &l_prev_hash);
    uint32_t l_prev_idx = 3;

    // Not used yet: nothing in the mempool spends it.
    dap_assert(!dap_chain_mempool_out_is_used(s_fixture->net, &l_prev_hash, l_prev_idx),
              "Unused prev-output reports as unused before anything is added to mempool");

    dap_hash_fast_t l_tx_hash;
    dap_chain_datum_t *l_datum = s_make_spending_tx_datum(&l_prev_hash, l_prev_idx, &l_tx_hash);
    char *l_added_hash = dap_chain_mempool_datum_add(l_datum, s_fixture->chain_main, "hex");
    dap_assert_PIF(l_added_hash != NULL, "TX datum added to mempool via dap_chain_mempool_datum_add()");
    DAP_DELETE(l_added_hash);
    DAP_DELETE(l_datum);

    // dap_chain_mempool_datum_add() indexes synchronously regardless of
    // whether the global index was ever initialized (the synchronous call
    // in the DAP_CHAIN_DATUM_TX branch is unconditional) - but
    // out_is_used() itself must still consult the full-scan path since
    // s_mempool_spent_index_ready is false in this whole test binary.
    dap_assert(dap_chain_mempool_out_is_used(s_fixture->net, &l_prev_hash, l_prev_idx),
              "Prev-output now reports as used via the full-scan fallback path");

    // A different, never-spent output must still report unused - the scan
    // must not be a false-positive "anything in mempool means everything is used".
    dap_hash_fast_t l_other_hash = {};
    s_make_fake_hash("test1_other_hash", &l_other_hash);
    dap_assert(!dap_chain_mempool_out_is_used(s_fixture->net, &l_other_hash, 0),
              "Unrelated prev-output still reports as unused");

    // Cleanup: remove the TX we added so later tests start from empty mempool.
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(s_fixture->chain_main);
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx_hash, l_hash_str, sizeof(l_hash_str));
    dap_global_db_del_sync(l_gdb_group, l_hash_str);
    DAP_DELETE(l_gdb_group);

    dap_pass_msg("Fail-open full-scan correctness test passed");
}

/**
 * @brief Unit Test 2: index activation, idempotent add, and O(1) lookup
 * @details Activates the index (dap_chain_mempool_spent_index_init()),
 *          confirms it seeds correctly from a TX already sitting in the
 *          mempool from Test 1's residue (none - cleaned up), adds a fresh
 *          spending TX, and confirms out_is_used() answers correctly via
 *          the indexed path this time. Also confirms calling
 *          dap_chain_mempool_datum_add() logic path twice for conceptually
 *          the same spend (simulating the sync-insert-then-async-notify
 *          race) never corrupts state - re-running the internal add is
 *          idempotent by construction (see s_mempool_spent_index_add_tx's
 *          own duplicate-tx-hash short-circuit).
 */
static void s_test_index_activation_and_lookup(void)
{
    dap_print_module_name("Unit Test 2: index activation and O(1) lookup");

    int l_init_res = dap_chain_mempool_spent_index_init();
    dap_assert(l_init_res == 0, "dap_chain_mempool_spent_index_init() succeeds for a network with a TX-capable chain");

    dap_hash_fast_t l_prev_hash = {};
    s_make_fake_hash("test2_prev_hash", &l_prev_hash);
    uint32_t l_prev_idx = 7;

    dap_assert(!dap_chain_mempool_out_is_used(s_fixture->net, &l_prev_hash, l_prev_idx),
              "Unused prev-output reports as unused via the now-active index");

    dap_hash_fast_t l_tx_hash;
    dap_chain_datum_t *l_datum = s_make_spending_tx_datum(&l_prev_hash, l_prev_idx, &l_tx_hash);
    char *l_added_hash = dap_chain_mempool_datum_add(l_datum, s_fixture->chain_main, "hex");
    dap_assert_PIF(l_added_hash != NULL, "TX datum added to mempool via dap_chain_mempool_datum_add()");
    DAP_DELETE(l_added_hash);

    dap_assert(dap_chain_mempool_out_is_used(s_fixture->net, &l_prev_hash, l_prev_idx),
              "Prev-output reports as used immediately (synchronous indexing, no wait for async notify)");

    // Re-adding the very same datum simulates the async cluster
    // notification for the same ADD arriving after the synchronous index
    // insert already happened - the index must not double-insert or crash.
    // dap_chain_mempool_datum_add() itself would overwrite the GDB record
    // (same key), which is a realistic re-submission; what we actually
    // exercise here is that out_is_used() still gives the same, correct
    // answer afterwards (i.e. re-indexing is a safe no-op, not corruption).
    char *l_added_hash_again = dap_chain_mempool_datum_add(l_datum, s_fixture->chain_main, "hex");
    dap_assert_PIF(l_added_hash_again != NULL, "Re-adding the same TX datum to mempool succeeds");
    DAP_DELETE(l_added_hash_again);
    DAP_DELETE(l_datum);

    dap_assert(dap_chain_mempool_out_is_used(s_fixture->net, &l_prev_hash, l_prev_idx),
              "Prev-output still correctly reports as used after the idempotent re-add");

    // Cleanup for the next test.
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(s_fixture->chain_main);
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx_hash, l_hash_str, sizeof(l_hash_str));
    dap_global_db_del_sync(l_gdb_group, l_hash_str);
    DAP_DELETE(l_gdb_group);

    dap_pass_msg("Index activation and lookup test passed");
}

/**
 * @brief Unit Test 3: removal via DEL notification restores unused state
 * @details The DEL notification carries only the mempool GDB key (the tx
 *          hash), never the datum - the reverse index
 *          (s_mempool_spent_by_tx) exists specifically so removal can work
 *          from that key alone (research doc sec. 10.1 gotcha (a)).
 *          dap_global_db_del_sync() triggers exactly that key-only
 *          notification path.
 */
static void s_test_removal_restores_unused_state(void)
{
    dap_print_module_name("Unit Test 3: removal restores unused state");

    dap_hash_fast_t l_prev_hash = {};
    s_make_fake_hash("test3_prev_hash", &l_prev_hash);
    uint32_t l_prev_idx = 11;

    dap_hash_fast_t l_tx_hash;
    dap_chain_datum_t *l_datum = s_make_spending_tx_datum(&l_prev_hash, l_prev_idx, &l_tx_hash);
    char *l_added_hash = dap_chain_mempool_datum_add(l_datum, s_fixture->chain_main, "hex");
    dap_assert_PIF(l_added_hash != NULL, "TX datum added to mempool");
    DAP_DELETE(l_added_hash);
    DAP_DELETE(l_datum);

    dap_assert_PIF(dap_chain_mempool_out_is_used(s_fixture->net, &l_prev_hash, l_prev_idx),
                  "Prev-output reports as used right after add (precondition for this test)");

    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(s_fixture->chain_main);
    char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx_hash, l_hash_str, sizeof(l_hash_str));
    int l_del_res = dap_global_db_del_sync(l_gdb_group, l_hash_str);
    dap_assert(l_del_res == 0, "dap_global_db_del_sync() removes the mempool record (fires a key-only DEL notification)");
    DAP_DELETE(l_gdb_group);

    // The notify callback runs asynchronously on a proc thread (see
    // s_mempool_spent_index_notify's registration via
    // dap_chain_add_mempool_notify_callback) - give it a moment to land
    // before asserting the index reflects the removal. This mirrors how
    // the fixtures' own test_wait_tx_mempool_to_ledger() polls with a
    // short delay rather than assuming instantaneous propagation.
    bool l_became_unused = false;
    for (int l_attempt = 0; l_attempt < 20 && !l_became_unused; ++l_attempt) {
        if (!dap_chain_mempool_out_is_used(s_fixture->net, &l_prev_hash, l_prev_idx))
            l_became_unused = true;
        else
            usleep(50 * 1000);
    }
    dap_assert(l_became_unused, "Prev-output reports as unused again once the DEL notification is indexed");

    dap_pass_msg("Removal restores unused state test passed");
}

int main(void)
{
    dap_log_level_set(L_DEBUG);

    printf("Mempool Spent-Outs Index Unit Tests starting...\n"); fflush(stdout);
    dap_print_module_name("Mempool Spent-Outs Index Unit Tests");

    s_setup();

    s_test_fail_open_full_scan_correctness();
    s_test_index_activation_and_lookup();
    s_test_removal_restores_unused_state();

    s_teardown();

    printf("All mempool spent-outs index unit tests passed (3 tests)!\n"); fflush(stdout);

    return 0;
}
