/*
 * Regression test for the replay failure classification.
 *
 * Every transaction the chain scan cannot apply is classified as either a local
 * loss - the chain carries its parent, this ledger does not, so the state this
 * ledger stands for is incomplete - or a chain-wide verdict, which every node
 * reaches and which therefore never means the ledger lost anything. The replay
 * report is built on that split, and both directions of a mistake are costly: a
 * verdict misread as a local loss makes an operator chase a phantom, while a
 * loss misread as a verdict hides a real gap in the state.
 *
 * The cases pinned here are the ones that were wrong in the field:
 *
 *   - a transaction spending one output twice within itself: decided from the
 *     datum alone, before the ledger is consulted (Backbone block 1023);
 *   - the double-spend losers (output, emission, reward already used): the chain
 *     carries the winner, so the loser is not a loss either;
 *   - everything else - a forbidden address, a sum mismatch raised by our own
 *     rules - defaults to the local-loss class, which is the safe direction: it
 *     never claims the network agreed with us.
 */

#include <stdio.h>
#include <string.h>

#include "dap_common.h"
#include "dap_file_utils.h"
#include "dap_chain.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_snapshot.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"

#define LOG_TAG "replay_fail_class_test"

static test_net_fixture_t *s_fixture = NULL;

static dap_ledger_t *s_test_ledger(void)
{
    dap_assert_PIF(s_fixture && s_fixture->ledger, "Test fixture has a ledger");
    return s_fixture->ledger;
}

static dap_hash_fast_t s_make_hash(uint8_t a_seed)
{
    dap_hash_fast_t l_hash = {};
    memset(&l_hash, a_seed, sizeof(l_hash));
    return l_hash;
}

/* A transaction datum with a_inputs standard inputs, every one of them spending
 * output 0 of a_prev. No signatures: the classification reads the first input
 * reference and nothing else, and this test is about that decision, not about
 * the transaction being acceptable. */
static dap_chain_datum_t *s_make_tx_datum(const dap_hash_fast_t *a_prev, size_t a_inputs)
{
    // The item size must be exactly what dap_chain_datum_item_tx_get_size()
    // reports for TX_ITEM_TYPE_IN - sizeof(dap_chain_tx_in_t), not a hand-counted
    // header+hash+index: the iteration stops on the first mismatch.
    const size_t l_in_size = sizeof(dap_chain_tx_in_t);
    const size_t l_items_size = l_in_size * a_inputs;
    const size_t l_tx_size = sizeof(dap_chain_datum_tx_t) + l_items_size;
    const size_t l_datum_size = sizeof(dap_chain_datum_t) + l_tx_size;
    dap_chain_datum_t *l_datum = DAP_NEW_Z_SIZE(dap_chain_datum_t, l_datum_size);
    if (!l_datum)
        return NULL;
    l_datum->header.version_id = DAP_CHAIN_DATUM_VERSION;
    l_datum->header.type_id = DAP_CHAIN_DATUM_TX;
    l_datum->header.data_size = (uint32_t)l_tx_size;
    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
    l_tx->header.ts_created = 1700000000;
    l_tx->header.tx_items_size = (uint32_t)l_items_size;
    l_datum->header.ts_create = l_tx->header.ts_created;
    byte_t *l_it = l_tx->tx_items;
    for (size_t i = 0; i < a_inputs; ++i) {
        dap_chain_tx_in_t *l_in = (dap_chain_tx_in_t *)l_it;
        l_in->header.type = TX_ITEM_TYPE_IN;
        l_in->header.tx_prev_hash = *a_prev;
        l_in->header.tx_out_prev_idx = 0;
        l_it += l_in_size;
    }
    return l_datum;
}

static void s_classify(dap_ledger_t *a_ledger, int a_code, dap_chain_datum_t *a_datum,
                       uint64_t *a_loss, uint64_t *a_intrinsic)
{
    dap_ledger_replay_datum_failed_ex(a_ledger, 1023, a_code, a_datum, NULL);
    *a_loss = *a_intrinsic = 0;
    dap_ledger_replay_fail_class_counts(a_loss, a_intrinsic);
}

static void test_intra_tx_double_spend(void)
{
    dap_ledger_t *l_ledger = s_test_ledger();
    dap_hash_fast_t l_prev = s_make_hash(0x11);
    dap_chain_datum_t *l_datum = s_make_tx_datum(&l_prev, 2);
    dap_assert_PIF(l_datum != NULL, "Datum built");
    uint64_t l_loss = 0, l_intrinsic = 0;
    s_classify(l_ledger, DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX, l_datum,
               &l_loss, &l_intrinsic);
    dap_assert_PIF(l_loss == 0, "A transaction spending one output twice is not our loss");
    dap_assert_PIF(l_intrinsic == 1, "It counts as a verdict the whole chain reaches");
    DAP_DELETE(l_datum);
    dap_pass_msg("intra_transaction_double_spend");
}

static void test_double_spend_losers(void)
{
    dap_ledger_t *l_ledger = s_test_ledger();
    dap_hash_fast_t l_prev = s_make_hash(0x33);
    dap_chain_datum_t *l_datum = s_make_tx_datum(&l_prev, 1);
    dap_assert_PIF(l_datum != NULL, "Datum built");
    const int l_loser_codes[] = {
        DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED,
        DAP_LEDGER_TX_CHECK_IN_EMS_ALREADY_USED,
        DAP_LEDGER_TX_CHECK_REWARD_ITEM_ALREADY_USED
    };
    for (size_t i = 0; i < sizeof(l_loser_codes) / sizeof(l_loser_codes[0]); ++i) {
        uint64_t l_loss = 0, l_intrinsic = 0;
        s_classify(l_ledger, l_loser_codes[i], l_datum, &l_loss, &l_intrinsic);
        dap_assert_PIF(l_loss == 0, "A double-spend loser is not our loss");
        dap_assert_PIF(l_intrinsic == 1, "The chain carries the winner, so the verdict is shared");
    }
    DAP_DELETE(l_datum);
    dap_pass_msg("double_spend_losers");
}

static void test_default_is_our_loss(void)
{
    dap_ledger_t *l_ledger = s_test_ledger();
    dap_hash_fast_t l_prev = s_make_hash(0x44);
    dap_chain_datum_t *l_datum = s_make_tx_datum(&l_prev, 1);
    dap_assert_PIF(l_datum != NULL, "Datum built");
    const int l_local_codes[] = {
        DAP_LEDGER_CHECK_ADDR_FORBIDDEN,
        DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE
    };
    for (size_t i = 0; i < sizeof(l_local_codes) / sizeof(l_local_codes[0]); ++i) {
        uint64_t l_loss = 0, l_intrinsic = 0;
        s_classify(l_ledger, l_local_codes[i], l_datum, &l_loss, &l_intrinsic);
        dap_assert_PIF(l_loss == 1, "An unexplained rejection is assumed to be a local loss");
        dap_assert_PIF(l_intrinsic == 0, "It is never reported as a shared verdict");
    }
    DAP_DELETE(l_datum);
    dap_pass_msg("default_is_our_loss");
}

static void test_hrl_verdict_is_shared(void)
{
    dap_ledger_t *l_ledger = s_test_ledger();
    // The reject list blocks a datum; everything spending its outputs inherits
    // the verdict. Marking is what carries it from the blocked datum to them.
    dap_hash_fast_t l_blocked = s_make_hash(0x55);
    dap_ledger_replay_mark_intrinsic(&l_blocked);
    dap_chain_datum_t *l_datum = s_make_tx_datum(&l_blocked, 1);
    dap_assert_PIF(l_datum != NULL, "Datum built");
    uint64_t l_loss = 0, l_intrinsic = 0;
    s_classify(l_ledger, DAP_LEDGER_TX_CHECK_PREV_TX_NOT_FOUND, l_datum, &l_loss, &l_intrinsic);
    dap_assert_PIF(l_loss == 0, "A datum held back by the operator's list is not our loss");
    dap_assert_PIF(l_intrinsic == 1, "Its spenders inherit the shared verdict");
    DAP_DELETE(l_datum);
    dap_pass_msg("hrl_verdict_is_shared");
}

static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    const char *l_tmp = test_get_temp_dir();
    char l_config_dir[512], l_gdb_dir[512];
    snprintf(l_config_dir, sizeof(l_config_dir), "%s%creplay_class_cfg", l_tmp, DAP_DIR_SEPARATOR);
    snprintf(l_gdb_dir, sizeof(l_gdb_dir), "%s%creplay_class_gdb", l_tmp, DAP_DIR_SEPARATOR);
    dap_rm_rf(l_config_dir);
    dap_rm_rf(l_gdb_dir);
    dap_mkdir_with_parents(l_config_dir);
    char l_cfg_path[600];
    snprintf(l_cfg_path, sizeof(l_cfg_path), "%s%ctest.cfg", l_config_dir, DAP_DIR_SEPARATOR);
    FILE *l_cfg = fopen(l_cfg_path, "w");
    dap_assert_PIF(l_cfg != NULL, "Test config file created");
    fputs("[general]\ndebug=true\n", l_cfg);
    fclose(l_cfg);
    dap_assert_PIF(test_env_init(l_config_dir, l_gdb_dir) == 0, "Test environment initialized");

    dap_ledger_init();
    // The fixture builds a zerochain (dag_poa) and a 'none'-consensus main
    // chain, so both have to be registered first.
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_nonconsensus_init();

    s_fixture = test_net_fixture_create("RclassNet");
    dap_assert_PIF(s_fixture != NULL, "Network fixture initialized");
    dap_assert_PIF(s_fixture->ledger != NULL, "Fixture ledger exists");
}

static void s_teardown(void)
{
    if (s_fixture) {
        test_net_fixture_destroy(s_fixture);
        s_fixture = NULL;
    }
    test_env_deinit();
}

int main(void)
{
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("Replay failure classification");
    s_setup();

    test_intra_tx_double_spend();
    test_double_spend_losers();
    test_default_is_our_loss();
    test_hrl_verdict_is_shared();

    s_teardown();
    printf("All replay failure classification tests passed (4)\n");
    return 0;
}
