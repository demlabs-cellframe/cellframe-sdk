/*
 * Regression test for Bug #20605: Arbitrage TX removed from mempool too fast for tx_sign
 * Also covers Bug #20138: tx_create doesn't accept -arbitrage flag (same root cause)
 *
 * Bug Description:
 * - Arbitrage TX created on node 1-r with user cert (not token owner)
 * - Token owner on node 0-r tries to sign via tx_sign
 * - TX already removed from mempool: "Transaction not found in mempool"
 *
 * Root Cause:
 * - dap_chain_arbitrage_tx_check_auth() returned -1 when zero owner signatures were present
 * - This mapped to DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED
 * - dap_chain_node_mempool_process() removed the TX from mempool
 * - The fix: check outputs (structure) first, then if structure is valid but signatures
 *   are missing, return DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS (TX stays in mempool)
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
#include "dap_chain_arbitrage.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"

#define LOG_TAG "regression_bug_20605"

test_net_fixture_t *s_net_fixture = NULL;

/**
 * @brief Test 1: Arbitrage TX with zero owner signatures returns NOT_ENOUGH_VALID_SIGNS
 *
 * Before the fix, the auth check returned -1 (hard reject) when zero owner signatures
 * were present, causing the TX to be deleted from mempool. After the fix, it returns
 * DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS, which keeps the TX in mempool for tx_sign.
 */
static void test_arbitrage_zero_owner_signs_stays_in_mempool(void)
{
    dap_print_module_name("Bug #20605 Test 1: Arbitrage TX with 0 owner signs → NOT_ENOUGH_VALID_SIGNS");

    // Owner key (for token declaration)
    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key generation");

    dap_chain_addr_t l_owner_addr = {0};
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner cert allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "cert_20605_owner");

    // User key (NOT the token owner — simulates node 1-r creating arbitrage TX)
    dap_enc_key_t *l_user_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_user_key != NULL, "User key generation");

    dap_chain_addr_t l_user_addr = {0};
    dap_chain_addr_fill_from_key(&l_user_addr, l_user_key, s_net_fixture->net->pub.id);

    // Create token (owned by l_owner_cert)
    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "B20605A", "10000.0", "5000.0", &l_user_addr, l_owner_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    // Create TX from emission
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B20605A", "1000.0", &l_user_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");

    // Block UTXO via token_update
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "B20605A", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    // Set up network fee address (required for arbitrage output validation)
    uint256_t l_fee_value = dap_chain_balance_scan("0.1");
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_fee_value, l_owner_addr);

    // Create arbitrage TX signed ONLY by user (not by owner)
    // This simulates the scenario from bug report: user on node 1-r creates TX, owner on 0-r needs to tx_sign
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();

    // Add input from blocked UTXO
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);

    // Add arbitrage TSD marker
    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_chain_datum_tx_add_item(&l_arb_tx, (const uint8_t *)l_tsd_arb);
    DAP_DELETE(l_tsd_arb);

    // All outputs go to fee address (owner address = fee address)
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_owner_addr, dap_chain_balance_scan("1000.0"), "B20605A");

    // Sign only by USER key (not owner) — simulates distributed signing workflow
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_user_key);

    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);

    // REGRESSION: Verify that ledger returns NOT_ENOUGH_VALID_SIGNS (not ARBITRAGE_NOT_AUTHORIZED)
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (user-signed only) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));

    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS,
                   "Arbitrage TX with 0 owner signatures returns NOT_ENOUGH_VALID_SIGNS (stays in mempool)");

    // Cleanup
    DAP_DELETE(l_arb_tx);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_owner_cert->enc_key = NULL;
    DAP_DELETE(l_owner_cert);
    dap_enc_key_delete(l_owner_key);
    dap_enc_key_delete(l_user_key);

    dap_pass_msg("Bug #20605 Test 1 PASSED: arbitrage TX with 0 owner signs stays in mempool");
}

/**
 * @brief Test 2: Arbitrage TX with wrong outputs is hard-rejected (-1 / ARBITRAGE_NOT_AUTHORIZED)
 *
 * If outputs don't go to fee address, the TX is fundamentally broken and should be removed.
 */
static void test_arbitrage_wrong_outputs_hard_rejected(void)
{
    dap_print_module_name("Bug #20605 Test 2: Arbitrage TX with wrong outputs → hard reject");

    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key generation");

    dap_chain_addr_t l_owner_addr = {0};
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Cert allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "cert_20605_t2");

    // Another address (NOT fee address)
    dap_enc_key_t *l_other_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_other_addr = {0};
    dap_chain_addr_fill_from_key(&l_other_addr, l_other_key, s_net_fixture->net->pub.id);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "B20605B", "10000.0", "5000.0", &l_owner_addr, l_owner_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B20605B", "1000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added");

    // Set fee address
    uint256_t l_fee_value = dap_chain_balance_scan("0.1");
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_fee_value, l_owner_addr);

    // Create arbitrage TX with outputs to WRONG address (not fee address)
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);

    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_chain_datum_tx_add_item(&l_arb_tx, (const uint8_t *)l_tsd_arb);
    DAP_DELETE(l_tsd_arb);

    // Output to OTHER address (not fee address) — this should be hard-rejected
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_other_addr, dap_chain_balance_scan("1000.0"), "B20605B");
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);

    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (wrong outputs) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));

    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_ARBITRAGE_NOT_AUTHORIZED,
                   "Arbitrage TX with wrong outputs is HARD REJECTED");

    DAP_DELETE(l_arb_tx);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_owner_cert->enc_key = NULL;
    DAP_DELETE(l_owner_cert);
    dap_enc_key_delete(l_owner_key);
    dap_enc_key_delete(l_other_key);

    dap_pass_msg("Bug #20605 Test 2 PASSED: wrong outputs hard-rejected");
}

/**
 * @brief Test 3: Arbitrage TX with correct owner signature is fully authorized
 */
static void test_arbitrage_with_owner_signature_authorized(void)
{
    dap_print_module_name("Bug #20605 Test 3: Arbitrage TX with owner signature → authorized");

    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key generation");

    dap_chain_addr_t l_owner_addr = {0};
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Cert allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "cert_20605_t3");

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "B20605C", "10000.0", "5000.0", &l_owner_addr, l_owner_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B20605C", "1000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added");

    // Block UTXO
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "B20605C", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    // Set fee address
    uint256_t l_fee_value = dap_chain_balance_scan("0.1");
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_fee_value, l_owner_addr);

    // Create arbitrage TX signed by OWNER (should be fully authorized)
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);

    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_chain_datum_tx_add_item(&l_arb_tx, (const uint8_t *)l_tsd_arb);
    DAP_DELETE(l_tsd_arb);

    // All outputs to fee address (= owner address)
    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_owner_addr, dap_chain_balance_scan("1000.0"), "B20605C");

    // Sign by owner (the token creator)
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);

    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (owner signed) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Arbitrage TX with owner signature is authorized and processed");

    DAP_DELETE(l_arb_tx);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_owner_cert->enc_key = NULL;
    DAP_DELETE(l_owner_cert);
    dap_enc_key_delete(l_owner_key);

    dap_pass_msg("Bug #20605 Test 3 PASSED: arbitrage TX with owner signature authorized");
}

int main(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);

    dap_print_module_name("Bug #20605 Regression Test: Arbitrage TX mempool retention");

    dap_chain_cs_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();

    test_env_init(NULL, NULL);
    s_net_fixture = test_net_fixture_create("RegNet20605");
    dap_assert_PIF(s_net_fixture != NULL, "Network fixture created");

    test_arbitrage_zero_owner_signs_stays_in_mempool();
    test_arbitrage_wrong_outputs_hard_rejected();
    test_arbitrage_with_owner_signature_authorized();

    test_net_fixture_destroy(s_net_fixture);
    s_net_fixture = NULL;
    test_env_deinit();

    log_it(L_NOTICE, "=== Bug #20605 Regression Test COMPLETE ===");
    return 0;
}
