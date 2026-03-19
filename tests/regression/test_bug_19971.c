/*
 * Regression test for Bug #19971: UTXO_BLOCKING_DISABLED flag does not disable UTXO blocking
 *
 * Bug Description:
 * - Token declared with UTXO_BLOCKING_DISABLED flag
 * - UTXO added to blocklist via token_update (UTXO_BLOCKED_ADD TSD)
 * - Transaction using that UTXO is REJECTED despite the flag being set
 *
 * Expected Behavior (per specification):
 * - Adding UTXO to blocklist SHOULD SUCCEED even when UTXO_BLOCKING_DISABLED is set
 * - Transactions using blocked UTXO SHOULD SUCCEED (blocklist is ignored)
 * - This supports the workflow: disable blocking → populate blocklist → re-enable blocking
 *
 * Root Cause:
 * - TSD parser rejected UTXO_BLOCKED_ADD when UTXO_BLOCKING_DISABLED was set
 * - dap_ledger_utxo_block_add() also rejected the add operation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_tsd.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_cs_none.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"

#define LOG_TAG "regression_bug_19971"

test_net_fixture_t *s_net_fixture = NULL;

/**
 * @brief Test 1: Adding UTXO to blocklist succeeds when UTXO_BLOCKING_DISABLED is set
 *
 * Before the fix, dap_ledger_token_add() rejected UTXO_BLOCKED_ADD TSD
 * with DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN when the flag was set.
 */
static void test_blocklist_add_with_disabled_flag(void)
{
    dap_print_module_name("Bug #19971 Test 1: Blocklist add with UTXO_BLOCKING_DISABLED");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cert_19971_t1");

    // Create token with emission
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "B19971A", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    // Set UTXO_BLOCKING_DISABLED flag via token_update
    size_t l_flags_size = 0;
    dap_chain_datum_token_t *l_flags_update = utxo_blocking_test_create_token_update_with_utxo_flags(
        "B19971A", DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED, l_cert, &l_flags_size);
    dap_assert_PIF(l_flags_update != NULL, "UTXO flags update created");

    int l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_flags_update, l_flags_size, dap_time_now());
    log_it(L_INFO, "  UTXO_BLOCKING_DISABLED flag set result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "UTXO_BLOCKING_DISABLED flag set successfully");
    DAP_DELETE(l_flags_update);

    // Create TX from emission to generate UTXO
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B19971A", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction from emission created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");

    // REGRESSION: Add UTXO to blocklist — should succeed (was rejected before fix)
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "B19971A", &l_tx->tx_hash, 0, l_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block token update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    log_it(L_INFO, "  UTXO blocklist add result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "UTXO added to blocklist even though UTXO_BLOCKING_DISABLED is set");
    DAP_DELETE(l_block_update);

    // Cleanup
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Bug #19971 Test 1 PASSED: blocklist add succeeds with UTXO_BLOCKING_DISABLED");
}

/**
 * @brief Test 2: Blocked UTXO can be used in transactions when UTXO_BLOCKING_DISABLED is set
 *
 * Even with UTXO in the blocklist, transactions should go through because the flag
 * instructs the system to ignore the blocklist during validation.
 */
static void test_blocked_utxo_usable_with_disabled_flag(void)
{
    dap_print_module_name("Bug #19971 Test 2: Blocked UTXO usable with UTXO_BLOCKING_DISABLED");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cert_19971_t2");

    // Create token
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "B19971B", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    // Set UTXO_BLOCKING_DISABLED
    size_t l_flags_size = 0;
    dap_chain_datum_token_t *l_flags_update = utxo_blocking_test_create_token_update_with_utxo_flags(
        "B19971B", DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED, l_cert, &l_flags_size);
    dap_assert_PIF(l_flags_update != NULL, "Flags update created");

    int l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_flags_update, l_flags_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO_BLOCKING_DISABLED flag set");
    DAP_DELETE(l_flags_update);

    // Create TX from emission
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B19971B", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction from emission created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");

    // Add UTXO to blocklist
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "B19971B", &l_tx->tx_hash, 0, l_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO blocklist add succeeded");
    DAP_DELETE(l_block_update);

    // REGRESSION: Spend the blocked UTXO — should succeed because flag is set
    dap_chain_datum_tx_t *l_tx_spend = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_spend, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_addr, dap_chain_balance_scan("100.0"), "B19971B");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_addr, dap_chain_balance_scan("900.0"), "B19971B");
    dap_chain_datum_tx_add_sign_item(&l_tx_spend, l_key);

    dap_chain_hash_fast_t l_spend_hash;
    dap_hash_fast(l_tx_spend, dap_chain_datum_tx_get_size(l_tx_spend), &l_spend_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_spend, &l_spend_hash, false, NULL);
    log_it(L_INFO, "  Spend blocked UTXO result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Spending blocked UTXO succeeds when UTXO_BLOCKING_DISABLED is set");

    // Cleanup
    DAP_DELETE(l_tx_spend);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Bug #19971 Test 2 PASSED: blocked UTXO usable with UTXO_BLOCKING_DISABLED");
}

/**
 * @brief Test 3: Without UTXO_BLOCKING_DISABLED, blocking still works (sanity check)
 */
static void test_blocking_works_without_flag(void)
{
    dap_print_module_name("Bug #19971 Test 3: Blocking works without UTXO_BLOCKING_DISABLED (sanity)");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Certificate allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cert_19971_t3");

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "B19971C", "10000.0", "5000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B19971C", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");

    // Block UTXO (flag NOT set — normal blocking)
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "B19971C", &l_tx->tx_hash, 0, l_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    // Spend blocked UTXO — should FAIL (blocking is enabled)
    dap_chain_datum_tx_t *l_tx_spend = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_spend, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_addr, dap_chain_balance_scan("100.0"), "B19971C");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_addr, dap_chain_balance_scan("900.0"), "B19971C");
    dap_chain_datum_tx_add_sign_item(&l_tx_spend, l_key);

    dap_chain_hash_fast_t l_spend_hash;
    dap_hash_fast(l_tx_spend, dap_chain_datum_tx_get_size(l_tx_spend), &l_spend_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_spend, &l_spend_hash, false, NULL);
    log_it(L_INFO, "  Spend blocked UTXO (no flag) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
                   "Spending blocked UTXO correctly rejected when UTXO_BLOCKING_DISABLED is NOT set");

    DAP_DELETE(l_tx_spend);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Bug #19971 Test 3 PASSED: blocking works without flag (sanity)");
}

int main(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);

    dap_print_module_name("Bug #19971 Regression Test: UTXO_BLOCKING_DISABLED");

    dap_chain_cs_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();

    test_env_init(NULL, NULL);
    s_net_fixture = test_net_fixture_create("RegNet19971");
    dap_assert_PIF(s_net_fixture != NULL, "Network fixture created");

    test_blocklist_add_with_disabled_flag();
    test_blocked_utxo_usable_with_disabled_flag();
    test_blocking_works_without_flag();

    test_net_fixture_destroy(s_net_fixture);
    s_net_fixture = NULL;
    test_env_deinit();

    log_it(L_NOTICE, "=== Bug #19971 Regression Test COMPLETE ===");
    return 0;
}
