/*
 * Regression test: Blocked UTXO visibility in listings and arbitrage UTXO lookup
 *
 * Bug: After blocking a UTXO via token_update -utxo_blocked_add, the `wallet outputs`
 *      command stops showing ALL outputs (balance shows 0). The arbitrage command
 *      tx_create -arbitrage also cannot find blocked UTXOs for arbitrage operations.
 *
 * Root cause: The UTXO listing function dap_ledger_get_list_tx_outs_unspent_by_addr
 *             filters out blocked UTXOs when a_skip_blocklist=false (used by wallet outputs).
 *             The arbitrage path uses a_skip_blocklist=true and SHOULD find blocked UTXOs.
 *
 * Expected: 
 *   1. Ledger listing with skip_blocklist=true returns blocked UTXOs
 *   2. Ledger listing with skip_blocklist=false does NOT return blocked UTXOs
 *   3. wallet outputs shows blocked UTXOs with "blocked" annotation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_file_utils.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_tsd.h"
#include "dap_list.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_chain_ledger_utxo.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"

#define LOG_TAG "regression_blocked_utxo_visibility"

test_net_fixture_t *s_net_fixture = NULL;

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];

static void s_setup(void)
{
    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_blocked_vis_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_blocked_vis_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_blocked_vis_certs", l_tmp);

    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_config_dir);
    dap_mkdir_with_parents(s_config_dir);
    dap_mkdir_with_parents(s_certs_dir);

    char l_cfg[2048];
    snprintf(l_cfg, sizeof(l_cfg),
        "[general]\ndebug=true\n[ledger]\ndebug_more=true\n"
        "[global_db]\ndriver=mdbx\npath=%s\n[resources]\nca_folders=%s\n",
        s_gdb_dir, s_certs_dir);

    char l_cfg_path[1024];
    snprintf(l_cfg_path, sizeof(l_cfg_path), "%s/test.cfg", s_config_dir);
    FILE *f = fopen(l_cfg_path, "w");
    if (f) { fwrite(l_cfg, 1, strlen(l_cfg), f); fclose(f); }

    int l_res = test_env_init(s_config_dir, s_gdb_dir);
    dap_assert_PIF(l_res == 0, "Test environment initialized");
    dap_ledger_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_nonconsensus_init();
    s_net_fixture = test_net_fixture_create("RegBlockedVis");
    dap_assert_PIF(s_net_fixture != NULL, "Network fixture created");
}

static void s_teardown(void)
{
    if (s_net_fixture) { test_net_fixture_destroy(s_net_fixture); s_net_fixture = NULL; }
    test_env_deinit();
    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
}

static void test_blocked_utxo_visible_with_skip_blocklist(void)
{
    dap_print_module_name("Blocked UTXO visibility: skip_blocklist=true returns blocked UTXO");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Cert allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cert_vis_test");

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "BVIS", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "BVIS", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    // Phase 1: Before blocking, both paths should find the UTXO
    uint256_t l_value_out = {};
    dap_list_t *l_list_normal = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "BVIS", &l_addr, NULL, &l_value_out,
        false, 0, false, false);
    dap_assert_PIF(l_list_normal != NULL, "Before block: normal listing finds UTXO");
    log_it(L_INFO, "  Before block, normal listing: %zu items", dap_list_length(l_list_normal));
    dap_list_free_full(l_list_normal, NULL);

    uint256_t l_value_out2 = {};
    dap_list_t *l_list_skip = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "BVIS", &l_addr, NULL, &l_value_out2,
        false, 0, false, true);
    dap_assert_PIF(l_list_skip != NULL, "Before block: skip_blocklist listing finds UTXO");
    dap_list_free_full(l_list_skip, NULL);

    // Phase 2: Block the UTXO
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "BVIS", &l_tx->tx_hash, 0, l_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update datum created");
    int l_block_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    log_it(L_INFO, "  Block result: %d (%s)", l_block_res, dap_ledger_check_error_str(l_block_res));
    dap_assert_PIF(l_block_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    // Phase 3: After blocking output 0, normal listing should return FEWER items
    // TX has 2 outputs: output 0 (blocked) and output 1 (change, not blocked)
    uint256_t l_value_out3 = {};
    dap_list_t *l_list_after_normal = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "BVIS", &l_addr, NULL, &l_value_out3,
        false, 0, false, false);
    size_t l_count_normal = l_list_after_normal ? dap_list_length(l_list_after_normal) : 0;
    log_it(L_INFO, "  After block, normal listing: %zu items (expected 1, output 0 filtered)", l_count_normal);
    dap_assert_PIF(l_count_normal == 1,
                   "After block: normal listing should return only the non-blocked output (change)");
    dap_list_free_full(l_list_after_normal, NULL);

    // Phase 4: After blocking, skip_blocklist listing SHOULD find ALL UTXOs (including blocked)
    uint256_t l_value_out4 = {};
    dap_list_t *l_list_after_skip = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "BVIS", &l_addr, NULL, &l_value_out4,
        false, 0, false, true);
    size_t l_count_skip = l_list_after_skip ? dap_list_length(l_list_after_skip) : 0;
    log_it(L_INFO, "  After block, skip_blocklist listing: %zu items (expected 2, both outputs)", l_count_skip);
    dap_assert_PIF(l_count_skip == 2,
                   "REGRESSION: skip_blocklist=true must return ALL UTXOs including blocked "
                   "(arbitrage depends on this)");
    dap_list_free_full(l_list_after_skip, NULL);

    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Blocked UTXO visibility with skip_blocklist=true PASSED");
}

static void test_blocked_utxo_balance_preserved(void)
{
    dap_print_module_name("Blocked UTXO: balance calculation still counts blocked UTXOs");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Cert allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cert_bal_test");

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "BBAL", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "BBAL", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    uint256_t l_balance_before = dap_ledger_calc_balance(s_net_fixture->ledger, &l_addr, "BBAL");
    log_it(L_INFO, "  Balance before block: %s", dap_uint256_to_char(l_balance_before, NULL));
    dap_assert_PIF(!IS_ZERO_256(l_balance_before), "Balance before block is non-zero");

    size_t l_block_size2 = 0;
    dap_chain_datum_token_t *l_block_update2 = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "BBAL", &l_tx->tx_hash, 0, l_cert, 0, &l_block_size2);
    dap_assert_PIF(l_block_update2 != NULL, "Block update datum created");
    int l_block_res2 = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update2, l_block_size2, dap_time_now());
    dap_assert_PIF(l_block_res2 == 0, "UTXO blocked");
    DAP_DELETE(l_block_update2);

    uint256_t l_balance_after = dap_ledger_calc_balance(s_net_fixture->ledger, &l_addr, "BBAL");
    log_it(L_INFO, "  Balance after block: %s", dap_uint256_to_char(l_balance_after, NULL));
    dap_assert_PIF(EQUAL_256(l_balance_before, l_balance_after),
                   "Balance should remain unchanged after UTXO blocking (wallet info still shows it)");

    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Balance preserved after UTXO blocking PASSED");
}

int main(int argc, char **argv)
{
    UNUSED(argc); UNUSED(argv);
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("Regression: Blocked UTXO visibility in listings");
    s_setup();
    test_blocked_utxo_visible_with_skip_blocklist();
    test_blocked_utxo_balance_preserved();
    s_teardown();
    log_it(L_NOTICE, "=== Blocked UTXO visibility regression test COMPLETE ===");
    return 0;
}
