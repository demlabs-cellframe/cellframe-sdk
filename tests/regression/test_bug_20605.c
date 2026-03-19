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
#include <sys/stat.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_file_utils.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_tsd.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_arbitrage.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
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
/**
 * @brief Helper: Create token datum with signs_valid=1, sign with cert, add to ledger + emission
 */
static int s_create_token_with_auth(dap_ledger_t *a_ledger, const char *a_ticker,
                                     const char *a_supply_str, const char *a_emission_str,
                                     dap_chain_addr_t *a_addr, dap_cert_t *a_cert,
                                     dap_chain_hash_fast_t *a_emission_hash_out)
{
    uint256_t l_supply = dap_chain_balance_scan(a_supply_str);
    dap_chain_datum_token_t *l_tok = DAP_NEW_Z(dap_chain_datum_token_t);
    l_tok->version = 2;
    l_tok->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_tok->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    strncpy(l_tok->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_tok->signs_valid = 1;
    l_tok->total_supply = l_supply;
    l_tok->header_native_decl.decimals = 18;
    l_tok->signs_total = 0;

    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_tok, sizeof(dap_chain_datum_token_t));
    if (!l_sign) { DAP_DELETE(l_tok); return -1; }
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_tok = DAP_REALLOC(l_tok, sizeof(dap_chain_datum_token_t) + l_sign_size);
    memcpy(l_tok->tsd_n_signs, l_sign, l_sign_size);
    l_tok->signs_total = 1;
    DAP_DELETE(l_sign);

    int l_res = dap_ledger_token_add(a_ledger, (byte_t *)l_tok, sizeof(dap_chain_datum_token_t) + l_sign_size, dap_time_now());
    DAP_DELETE(l_tok);
    if (l_res != 0) return l_res;

    test_emission_fixture_t *l_em = test_emission_fixture_create_with_cert(
        a_ticker, dap_chain_balance_scan(a_emission_str), a_addr, a_cert);
    if (!l_em) return -2;
    l_res = test_emission_fixture_add_to_ledger(a_ledger, l_em);
    if (l_res != 0) return l_res;
    if (a_emission_hash_out) test_emission_fixture_get_hash(l_em, a_emission_hash_out);
    return 0;
}

static void test_arbitrage_zero_owner_signs_stays_in_mempool(void)
{
    dap_print_module_name("Bug #20605 Test 1: Arbitrage TX with 0 owner signs → NOT_ENOUGH_VALID_SIGNS");

    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key generation");

    dap_chain_addr_t l_owner_addr = {0};
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Owner cert allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "cert_20605_owner");

    dap_enc_key_t *l_user_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_user_key != NULL, "User key generation");

    dap_chain_addr_t l_user_addr = {0};
    dap_chain_addr_fill_from_key(&l_user_addr, l_user_key, s_net_fixture->net->pub.id);

    // Create token with signs_valid=1 so auth check actually requires owner signature
    dap_chain_hash_fast_t l_emission_hash;
    int l_res = s_create_token_with_auth(s_net_fixture->ledger, "B20605A", "10000.0", "5000.0",
                                          &l_user_addr, l_owner_cert, &l_emission_hash);
    dap_assert_PIF(l_res == 0, "Token with emission created (signs_valid=1)");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B20605A", "1000.0", &l_user_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "Transaction created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "Transaction added to ledger");

    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "B20605A", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    // Set fee address with zero fee (only address needed for output validation)
    uint256_t l_zero_fee = uint256_0;
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_owner_addr);

    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);

    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_chain_datum_tx_add_item(&l_arb_tx, (const uint8_t *)l_tsd_arb);
    DAP_DELETE(l_tsd_arb);

    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_owner_addr, dap_chain_balance_scan("1000.0"), "B20605A");

    // Sign only by USER key (not owner) — simulates distributed signing workflow
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_user_key);

    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);

    // REGRESSION: auth check sees 0 owner signs < signs_valid(1) → NOT_ENOUGH_VALID_SIGNS
    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (user-signed only) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));

    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS,
                   "Arbitrage TX with 0 owner signatures returns NOT_ENOUGH_VALID_SIGNS (stays in mempool)");

    DAP_DELETE(l_arb_tx);
    test_tx_fixture_destroy(l_tx);
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

    dap_enc_key_t *l_other_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_other_addr = {0};
    dap_chain_addr_fill_from_key(&l_other_addr, l_other_key, s_net_fixture->net->pub.id);

    dap_chain_hash_fast_t l_emission_hash;
    int l_res = s_create_token_with_auth(s_net_fixture->ledger, "B20605B", "10000.0", "5000.0",
                                          &l_owner_addr, l_owner_cert, &l_emission_hash);
    dap_assert_PIF(l_res == 0, "Token created (signs_valid=1)");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B20605B", "1000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added");

    uint256_t l_zero_fee = uint256_0;
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_owner_addr);

    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);

    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_chain_datum_tx_add_item(&l_arb_tx, (const uint8_t *)l_tsd_arb);
    DAP_DELETE(l_tsd_arb);

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

    dap_enc_key_t *l_user_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_user_key != NULL, "User key generation");
    dap_chain_addr_t l_user_addr = {0};
    dap_chain_addr_fill_from_key(&l_user_addr, l_user_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_user_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_user_cert != NULL, "User cert allocation");
    l_user_cert->enc_key = l_user_key;
    snprintf(l_user_cert->name, sizeof(l_user_cert->name), "cert_20605_t3_user");

    dap_chain_hash_fast_t l_emission_hash;
    int l_res = s_create_token_with_auth(s_net_fixture->ledger, "B20605C", "10000.0", "5000.0",
                                          &l_user_addr, l_owner_cert, &l_emission_hash);
    dap_assert_PIF(l_res == 0, "Token created (signs_valid=1)");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "B20605C", "1000.0", &l_user_addr, l_user_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added");

    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "B20605C", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    uint256_t l_zero_fee = uint256_0;
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_owner_addr);

    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);

    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_chain_datum_tx_add_item(&l_arb_tx, (const uint8_t *)l_tsd_arb);
    DAP_DELETE(l_tsd_arb);

    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_owner_addr, dap_chain_balance_scan("1000.0"), "B20605C");

    // First signature: user (wallet) — skipped by arbitrage auth check
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_user_key);
    // Second signature: owner (authorization) — checked by arbitrage auth
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);

    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (owner signed) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Arbitrage TX with owner signature is authorized and processed");

    DAP_DELETE(l_arb_tx);
    test_tx_fixture_destroy(l_tx);
    l_owner_cert->enc_key = NULL;
    DAP_DELETE(l_owner_cert);
    l_user_cert->enc_key = NULL;
    DAP_DELETE(l_user_cert);
    dap_enc_key_delete(l_owner_key);
    dap_enc_key_delete(l_user_key);

    dap_pass_msg("Bug #20605 Test 3 PASSED: arbitrage TX with owner signature authorized");
}

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];

static void s_setup(void)
{
    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg20605_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg20605_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg20605_certs", l_tmp);

    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_config_dir);

    dap_mkdir_with_parents(s_config_dir);
    dap_mkdir_with_parents(s_certs_dir);

    char l_cfg[2048];
    snprintf(l_cfg, sizeof(l_cfg),
        "[general]\ndebug=true\n"
        "[ledger]\ndebug_more=true\n"
        "[global_db]\ndriver=mdbx\npath=%s\n"
        "[resources]\nca_folders=%s\n",
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

    s_net_fixture = test_net_fixture_create("RegNet20605");
    dap_assert_PIF(s_net_fixture != NULL, "Network fixture created");
}

static void s_teardown(void)
{
    if (s_net_fixture) {
        test_net_fixture_destroy(s_net_fixture);
        s_net_fixture = NULL;
    }
    test_env_deinit();

    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
}

int main(int argc, char **argv)
{
    UNUSED(argc);
    UNUSED(argv);

    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);

    dap_print_module_name("Bug #20605 Regression Test: Arbitrage TX mempool retention");

    s_setup();

    test_arbitrage_zero_owner_signs_stays_in_mempool();
    test_arbitrage_wrong_outputs_hard_rejected();
    test_arbitrage_with_owner_signature_authorized();

    s_teardown();

    log_it(L_NOTICE, "=== Bug #20605 Regression Test COMPLETE ===");
    return 0;
}
