/*
 * Regression test: Address blocking (tx_sender_blocked / tx_receiver_blocked)
 * via full CLI pipeline (token_update → mempool → ledger)
 *
 * Bug: Address blocking via -tx_sender_blocked and -tx_receiver_blocked
 *      does not take effect when applied through the CLI command.
 *
 * Expected: After token_update -tx_sender_blocked <addr>, transactions from
 *           that address should be rejected with ADDR_FORBIDDEN.
 *           After token_update -tx_receiver_blocked <addr>, transactions to
 *           that address should be rejected.
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
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_cs_none.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node.h"
#include "dap_cert_file.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"
#include <json-c/json.h>

#define LOG_TAG "regression_addr_block"

test_net_fixture_t *s_net_fixture = NULL;

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];
static char s_wallets_dir[512];

static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);

    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_addr_block_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_addr_block_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_addr_block_certs", l_tmp);
    snprintf(s_wallets_dir, sizeof(s_wallets_dir), "%s/reg_addr_block_wallets", l_tmp);

    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_wallets_dir);
    dap_mkdir_with_parents(s_config_dir);
    dap_mkdir_with_parents(s_certs_dir);
    dap_mkdir_with_parents(s_wallets_dir);

    char l_cfg_path[1024];
    snprintf(l_cfg_path, sizeof(l_cfg_path), "%s/test.cfg", s_config_dir);
    FILE *f = fopen(l_cfg_path, "w");
    if (f) {
        fprintf(f,
            "[general]\ndebug_mode=true\n\n"
            "[ledger]\ndebug_more=true\n\n"
            "[wallet]\ndebug_more=true\n\n"
            "[wallets]\nwallets_cache=all\n\n"
            "[global_db]\ndriver=mdbx\npath=%s\n\n"
            "[cli-server]\nenabled=true\n\n"
            "[resources]\nwallets_path=%s\nca_folders=%s\n",
            s_gdb_dir, s_wallets_dir, s_certs_dir);
        fclose(f);
    }

    dap_chain_cs_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();

    test_env_init(s_config_dir, s_gdb_dir);
    dap_chain_wallet_cache_init();

    s_net_fixture = test_net_fixture_create("RegAddrBlock");
    dap_assert_PIF(s_net_fixture != NULL, "Network fixture created");

    dap_chain_node_cli_init(g_config);
}

static void s_teardown(void)
{
    dap_chain_wallet_cache_deinit();
    dap_chain_node_cli_delete();
    if (s_net_fixture) { test_net_fixture_destroy(s_net_fixture); s_net_fixture = NULL; }
    test_env_deinit();
    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_wallets_dir);
}

static void test_sender_blocked(void)
{
    dap_print_module_name("Address Block Test 1: CLI -tx_sender_blocked prevents spending");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("cert_sender_block", DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          "sender_block_seed", 17);
    dap_assert_PIF(l_cert != NULL, "Cert generated");
    dap_cert_save_to_folder(l_cert, s_certs_dir);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "SBLK", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "SBLK", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);

    /* Block sender via CLI pipeline: token_update -tx_sender_blocked <addr> */
    char l_cmd[4096];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net %s -chain %s -token SBLK -type CF20 -certs %s "
             "-tx_sender_blocked %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_addr_str);

    log_it(L_INFO, "CLI command: %s", l_cmd);

    char l_json_req[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "token_update", l_json_req, sizeof(l_json_req), 1);
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "CLI reply: %s", l_reply ? l_reply : "(null)");

    /* Check CLI reply for errors */
    bool l_cli_ok = l_reply && strstr(l_reply, "error") == NULL;
    log_it(l_cli_ok ? L_INFO : L_ERROR, "  CLI result: %s", l_cli_ok ? "OK" : "ERROR in reply");
    DAP_DEL_Z(l_reply);

    /* Process mempool to apply token_update to the ledger */
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Verify: TX from blocked sender should be rejected */
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
    dap_cert_delete(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("CLI sender block test PASSED");
}

static void test_receiver_blocked(void)
{
    dap_print_module_name("Address Block Test 2: CLI -tx_receiver_blocked prevents receiving");

    dap_enc_key_t *l_sender_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_sender_key != NULL, "Sender key generation");

    dap_chain_addr_t l_sender_addr = {0};
    dap_chain_addr_fill_from_key(&l_sender_addr, l_sender_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("cert_recv_block", DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          "recv_block_seed", 15);
    dap_assert_PIF(l_cert != NULL, "Cert generated");
    dap_cert_save_to_folder(l_cert, s_certs_dir);

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

    const char *l_recv_addr_str = dap_chain_addr_to_str_static(&l_recv_addr);

    /* Block receiver via CLI pipeline */
    char l_cmd[4096];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net %s -chain %s -token RBLK -type CF20 -certs %s "
             "-tx_receiver_blocked %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_recv_addr_str);

    log_it(L_INFO, "CLI command: %s", l_cmd);

    char l_json_req[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "token_update", l_json_req, sizeof(l_json_req), 1);
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "CLI reply: %s", l_reply ? l_reply : "(null)");
    DAP_DEL_Z(l_reply);

    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Verify: TX to blocked receiver should be rejected */
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
    dap_cert_delete(l_cert);
    dap_enc_key_delete(l_sender_key);
    dap_enc_key_delete(l_recv_key);

    dap_pass_msg("CLI receiver block test PASSED");
}

int main(int argc, char **argv)
{
    UNUSED(argc); UNUSED(argv);
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("Regression: Address blocking via CLI pipeline (sender/receiver)");
    s_setup();
    test_sender_blocked();
    test_receiver_blocked();
    s_teardown();
    log_it(L_NOTICE, "=== Address block CLI regression test COMPLETE ===");
    return 0;
}
