/*
 * Regression test: Delayed activation of UTXO blocking via CLI timestamp parameter
 *
 * Bug: The CLI command `token_update -utxo_blocked_add <hash>:<idx>:<future_timestamp>`
 *      does not correctly support delayed activation. The UTXO is either blocked immediately
 *      or the timestamp parameter is not properly processed through the CLI pipeline.
 *
 * Expected: A UTXO blocked with a future timestamp via CLI should remain spendable until
 *           the blockchain time reaches that timestamp. Similarly, an unblock with a future
 *           timestamp should keep the UTXO blocked until that time.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
#include "dap_chain_net_tx.h"
#include "dap_chain_mempool.h"
#include "dap_chain_node.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"
#include <json-c/json.h>

#define LOG_TAG "regression_delayed_block"

test_net_fixture_t *s_net_fixture = NULL;

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];
static char s_wallets_dir[512];

static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);

    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_delayed_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_delayed_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_delayed_certs", l_tmp);
    snprintf(s_wallets_dir, sizeof(s_wallets_dir), "%s/reg_delayed_wallets", l_tmp);

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

    s_net_fixture = test_net_fixture_create("RegDelayed");
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

static void test_cli_delayed_block_future_timestamp(void)
{
    dap_print_module_name("Delayed Block CLI Test: -utxo_blocked_add with future timestamp");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("cert_delayed", DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          "delayed_seed_1234", 17);
    dap_assert_PIF(l_cert != NULL, "Cert generated");
    dap_cert_save_to_folder(l_cert, s_certs_dir);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "DBLK", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "DBLK", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    dap_time_t l_future = dap_time_now() + 86400;

    /* Call CLI: block UTXO with future becomes_effective timestamp */
    char l_cmd[4096];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net %s -chain %s -token DBLK -type CF20 -certs %s "
             "-utxo_blocked_add %s:0:%"DAP_UINT64_FORMAT_U,
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_tx_hash_str, l_future);

    log_it(L_INFO, "CLI command: %s", l_cmd);
    log_it(L_INFO, "  Future timestamp: %"DAP_UINT64_FORMAT_U" (now + 86400)", l_future);

    char l_json_req[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "token_update", l_json_req, sizeof(l_json_req), 1);
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "CLI reply: %s", l_reply ? l_reply : "(null)");
    DAP_DEL_Z(l_reply);

    /* Process mempool to apply token_update to the ledger */
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Spend UTXO — should succeed because becomes_effective is in the future */
    dap_chain_datum_tx_t *l_tx_spend = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_spend, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_addr, dap_chain_balance_scan("1000.0"), "DBLK");
    dap_chain_datum_tx_add_sign_item(&l_tx_spend, l_key);
    dap_chain_hash_fast_t l_spend_hash;
    dap_hash_fast(l_tx_spend, dap_chain_datum_tx_get_size(l_tx_spend), &l_spend_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_spend, &l_spend_hash, false, NULL);
    log_it(L_INFO, "  Spend (future block): %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == 0,
                   "REGRESSION: UTXO with future becomes_effective should still be spendable via CLI");

    DAP_DELETE(l_tx_spend);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    dap_cert_delete(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Delayed block CLI test PASSED");
}

static void test_cli_delayed_unblock_future_timestamp(void)
{
    dap_print_module_name("Delayed Block CLI Test 2: block immediately, unblock with future timestamp");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("cert_delayed2", DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          "delayed_seed_5678", 17);
    dap_assert_PIF(l_cert != NULL, "Cert generated");
    dap_cert_save_to_folder(l_cert, s_certs_dir);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "DBLK2", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "DBLK2", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    /* Step 1: Block UTXO immediately via CLI */
    char l_cmd_block[4096];
    snprintf(l_cmd_block, sizeof(l_cmd_block),
             "token_update -net %s -chain %s -token DBLK2 -type CF20 -certs %s "
             "-utxo_blocked_add %s:0",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_tx_hash_str);

    char l_json_req_block[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd_block, "token_update", l_json_req_block, sizeof(l_json_req_block), 1);
    char *l_reply_block = dap_cli_cmd_exec(l_json_req_block);
    log_it(L_INFO, "Block reply: %s", l_reply_block ? l_reply_block : "(null)");
    DAP_DEL_Z(l_reply_block);

    /* Process mempool to apply immediate block */
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Step 2: Unblock with future timestamp via CLI */
    dap_time_t l_future = dap_time_now() + 86400;
    char l_cmd_unblock[4096];
    snprintf(l_cmd_unblock, sizeof(l_cmd_unblock),
             "token_update -net %s -chain %s -token DBLK2 -type CF20 -certs %s "
             "-utxo_blocked_remove %s:0:%"DAP_UINT64_FORMAT_U,
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_tx_hash_str, l_future);

    log_it(L_INFO, "Unblock CLI command: %s", l_cmd_unblock);

    char l_json_req_unblock[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd_unblock, "token_update", l_json_req_unblock, sizeof(l_json_req_unblock), 1);
    char *l_reply_unblock = dap_cli_cmd_exec(l_json_req_unblock);
    log_it(L_INFO, "Unblock reply: %s", l_reply_unblock ? l_reply_unblock : "(null)");
    DAP_DEL_Z(l_reply_unblock);

    /* Process mempool to apply the future-dated unblock */
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Spend UTXO — should FAIL because the unblock is scheduled for the future */
    dap_chain_datum_tx_t *l_tx_spend = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_tx_spend, &l_tx->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx_spend, &l_addr, dap_chain_balance_scan("1000.0"), "DBLK2");
    dap_chain_datum_tx_add_sign_item(&l_tx_spend, l_key);
    dap_chain_hash_fast_t l_spend_hash;
    dap_hash_fast(l_tx_spend, dap_chain_datum_tx_get_size(l_tx_spend), &l_spend_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_tx_spend, &l_spend_hash, false, NULL);
    log_it(L_INFO, "  Spend (future unblock): %d (%s)", l_res, dap_ledger_check_error_str(l_res));
    dap_assert_PIF(l_res == DAP_LEDGER_TX_CHECK_OUT_ITEM_BLOCKED,
                   "REGRESSION: UTXO should remain blocked (unblock scheduled for future via CLI)");

    DAP_DELETE(l_tx_spend);
    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    dap_cert_delete(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Delayed unblock CLI test PASSED");
}

int main(int argc, char **argv)
{
    UNUSED(argc); UNUSED(argv);
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("Regression: Delayed activation of UTXO blocking/unblocking via CLI");
    s_setup();
    test_cli_delayed_block_future_timestamp();
    test_cli_delayed_unblock_future_timestamp();
    s_teardown();
    log_it(L_NOTICE, "=== Delayed block CLI regression test COMPLETE ===");
    return 0;
}
