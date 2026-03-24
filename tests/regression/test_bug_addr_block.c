/*
 * Regression test: Address blocking (tx_sender_blocked / tx_receiver_blocked)
 *
 * Bug: Address blocking via TX_SENDER_BLOCKED_ADD and TX_RECEIVER_BLOCKED_ADD does not
 *      take effect. Transactions from blocked senders or to blocked receivers are not
 *      rejected as expected.
 *
 * Expected: After adding an address to the sender blocklist, transactions spending UTXOs
 *           belonging to that address should be rejected with ADDR_FORBIDDEN.
 *           After adding an address to the receiver blocklist, transactions with outputs
 *           to that address should be rejected.
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
#include "dap_chain_ledger.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"

#define LOG_TAG "regression_addr_block"

test_net_fixture_t *s_net_fixture = NULL;

static void test_sender_blocked(void)
{
    dap_print_module_name("Address Block Test 1: tx_sender_blocked prevents spending");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Cert allocation");
    l_cert->enc_key = l_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cert_sender_block");

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "SBLK", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "SBLK", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    // Block sender address
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_address_block(
        "SBLK", &l_addr, true, l_cert, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Sender block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    log_it(L_INFO, "  Sender block result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Sender address blocked");
    DAP_DELETE(l_block_update);

    // Try to spend from blocked sender → should be rejected
    dap_chain_datum_tx_t *l_tx_spend = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_spend, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_addr, dap_chain_balance_scan("1000.0"), "SBLK");
    dap_chain_datum_tx_add_sign_item(&l_tx_spend, l_key);

    dap_chain_hash_fast_t l_spend_hash;
    dap_hash_fast(l_tx_spend, dap_chain_datum_tx_get_size(l_tx_spend), &l_spend_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_spend, &l_spend_hash, false, NULL);
    log_it(L_INFO, "  Spend from blocked sender result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_ADDR_FORBIDDEN,
                   "REGRESSION: TX from blocked sender should be rejected with ADDR_FORBIDDEN");

    DAP_DELETE(l_tx_spend);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Sender block test PASSED");
}

static void test_receiver_blocked(void)
{
    dap_print_module_name("Address Block Test 2: tx_receiver_blocked prevents receiving");

    dap_enc_key_t *l_sender_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_sender_key != NULL, "Sender key generation");

    dap_chain_addr_t l_sender_addr = {0};
    dap_chain_addr_fill_from_key(&l_sender_addr, l_sender_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_cert != NULL, "Cert allocation");
    l_cert->enc_key = l_sender_key;
    snprintf(l_cert->name, sizeof(l_cert->name), "cert_recv_block");

    dap_enc_key_t *l_recv_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_recv_addr = {0};
    dap_chain_addr_fill_from_key(&l_recv_addr, l_recv_key, s_net_fixture->net->pub.id);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "RBLK", "100000.0", "50000.0", &l_sender_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "RBLK", "1000.0", &l_sender_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    // Block receiver address
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_address_block(
        "RBLK", &l_recv_addr, false, l_cert, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Receiver block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    log_it(L_INFO, "  Receiver block result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0, "Receiver address blocked");
    DAP_DELETE(l_block_update);

    // Try to send to blocked receiver → should be rejected
    dap_chain_datum_tx_t *l_tx_spend = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_spend, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_recv_addr, dap_chain_balance_scan("500.0"), "RBLK");
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_sender_addr, dap_chain_balance_scan("500.0"), "RBLK");
    dap_chain_datum_tx_add_sign_item(&l_tx_spend, l_sender_key);

    dap_chain_hash_fast_t l_spend_hash;
    dap_hash_fast(l_tx_spend, dap_chain_datum_tx_get_size(l_tx_spend), &l_spend_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_spend, &l_spend_hash, false, NULL);
    log_it(L_INFO, "  Send to blocked receiver result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_CHECK_ADDR_FORBIDDEN,
                   "REGRESSION: TX to blocked receiver should be rejected with ADDR_FORBIDDEN");

    DAP_DELETE(l_tx_spend);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    l_cert->enc_key = NULL;
    DAP_DELETE(l_cert);
    dap_enc_key_delete(l_sender_key);
    dap_enc_key_delete(l_recv_key);

    dap_pass_msg("Receiver block test PASSED");
}

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];

static void s_setup(void)
{
    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_addr_block_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_addr_block_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_addr_block_certs", l_tmp);

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
    s_net_fixture = test_net_fixture_create("RegAddrBlock");
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

int main(int argc, char **argv)
{
    UNUSED(argc); UNUSED(argv);
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("Regression: Address blocking (sender/receiver)");
    s_setup();
    test_sender_blocked();
    test_receiver_blocked();
    s_teardown();
    log_it(L_NOTICE, "=== Address block regression test COMPLETE ===");
    return 0;
}
