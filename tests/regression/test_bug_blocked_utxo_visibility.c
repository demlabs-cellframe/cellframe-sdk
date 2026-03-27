/*
 * Regression test: Blocked UTXO visibility in listings and wallet outputs CLI
 *
 * Bug: After blocking a UTXO via token_update -utxo_blocked_add, the `wallet outputs`
 *      command stops showing ALL outputs (balance shows 0). The arbitrage command
 *      tx_create -arbitrage also cannot find blocked UTXOs for arbitrage operations.
 *
 * Root cause: The wallet outputs CLI called UTXO listing with a_skip_blocklist=false,
 *             so blocked UTXOs were silently filtered out of the response.
 *
 * Expected:
 *   1. Ledger API with skip_blocklist=true returns blocked UTXOs
 *   2. Ledger API with skip_blocklist=false does NOT return blocked UTXOs
 *   3. CLI `wallet outputs` returns ALL UTXOs with "status" annotation (blocked/available)
 *   4. CLI `wallet outputs` includes separate available_value and blocked_value totals
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
#include "dap_chain_ledger_utxo.h"
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

#define LOG_TAG "regression_blocked_utxo_visibility"

test_net_fixture_t *s_net_fixture = NULL;

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];
static char s_wallets_dir[512];

static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);

    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_blocked_vis_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_blocked_vis_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_blocked_vis_certs", l_tmp);
    snprintf(s_wallets_dir, sizeof(s_wallets_dir), "%s/reg_blocked_vis_wallets", l_tmp);

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

    s_net_fixture = test_net_fixture_create("RegBlockedVis");
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

    uint256_t l_value_out = {};
    dap_list_t *l_list_normal = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "BVIS", &l_addr, NULL, &l_value_out,
        false, 0, false, false);
    dap_assert_PIF(l_list_normal != NULL, "Before block: normal listing finds UTXO");
    log_it(L_INFO, "  Before block, normal listing: %zu items", dap_list_length(l_list_normal));
    dap_list_free_full(l_list_normal, NULL);

    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "BVIS", &l_tx->tx_hash, 0, l_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update datum created");
    int l_block_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    log_it(L_INFO, "  Block result: %d (%s)", l_block_res, dap_ledger_check_error_str(l_block_res));
    dap_assert_PIF(l_block_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    uint256_t l_value_out3 = {};
    dap_list_t *l_list_after_normal = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "BVIS", &l_addr, NULL, &l_value_out3,
        false, 0, false, false);
    size_t l_count_normal = l_list_after_normal ? dap_list_length(l_list_after_normal) : 0;
    log_it(L_INFO, "  After block, normal listing: %zu items (expected 1, output 0 filtered)", l_count_normal);
    dap_assert_PIF(l_count_normal == 1,
                   "After block: normal listing should return only the non-blocked output (change)");
    dap_list_free_full(l_list_after_normal, NULL);

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

static void test_wallet_outputs_cli_shows_blocked_utxo(void)
{
    dap_print_module_name("CLI wallet outputs: blocked UTXO visible with status annotation");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generation");

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("cert_cli_vis", DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          "cli_vis_seed_42", 15);
    dap_assert_PIF(l_cert != NULL, "Cert generated");
    dap_cert_save_to_folder(l_cert, s_certs_dir);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "TCLI", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "TCLI", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    /* Block output 0 via CLI pipeline */
    char l_cmd_block[4096];
    snprintf(l_cmd_block, sizeof(l_cmd_block),
             "token_update -net %s -chain %s -token TCLI -type CF20 -certs %s "
             "-utxo_blocked_add %s:0",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_tx_hash_str);

    char l_json_req[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd_block, "token_update", l_json_req, sizeof(l_json_req), 1);
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "Block CLI reply: %s", l_reply ? l_reply : "(null)");
    DAP_DEL_Z(l_reply);

    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Call wallet outputs via CLI */
    const char *l_addr_str = dap_chain_addr_to_str_static(&l_addr);
    char l_cmd_wallet[4096];
    snprintf(l_cmd_wallet, sizeof(l_cmd_wallet),
             "wallet outputs -net %s -addr %s -token TCLI",
             s_net_fixture->net->pub.name, l_addr_str);

    char l_json_wallet[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd_wallet, "wallet", l_json_wallet, sizeof(l_json_wallet), 2);
    char *l_wallet_reply = dap_cli_cmd_exec(l_json_wallet);
    log_it(L_INFO, "Wallet outputs CLI reply: %.500s", l_wallet_reply ? l_wallet_reply : "(null)");

    dap_assert_PIF(l_wallet_reply != NULL, "wallet outputs returned a reply");

    /* Parse JSON-RPC response */
    json_object *l_jobj = json_tokener_parse(l_wallet_reply);
    dap_assert_PIF(l_jobj != NULL, "wallet outputs reply is valid JSON");

    json_object *l_result_arr = NULL;
    json_object_object_get_ex(l_jobj, "result", &l_result_arr);
    dap_assert_PIF(l_result_arr != NULL && json_object_is_type(l_result_arr, json_type_array),
                   "JSON has result array");

    json_object *l_inner_arr = json_object_array_get_idx(l_result_arr, 0);
    dap_assert_PIF(l_inner_arr != NULL && json_object_is_type(l_inner_arr, json_type_array),
                   "Result has inner wallet array");

    json_object *l_wallet_obj = json_object_array_get_idx(l_inner_arr, 0);
    dap_assert_PIF(l_wallet_obj != NULL, "Inner array has wallet object");

    json_object *l_outs_arr = NULL;
    json_object_object_get_ex(l_wallet_obj, "outs", &l_outs_arr);
    dap_assert_PIF(l_outs_arr != NULL && json_object_is_type(l_outs_arr, json_type_array),
                   "Wallet object has outs array");

    int l_outs_count = json_object_array_length(l_outs_arr);
    log_it(L_INFO, "  wallet outputs returned %d UTXOs", l_outs_count);
    dap_assert_PIF(l_outs_count >= 2,
                   "REGRESSION: wallet outputs must show ALL UTXOs including blocked (got %d, expected >= 2)");

    /* Verify each UTXO has a "status" field */
    bool l_found_blocked = false;
    bool l_found_available = false;
    for (int i = 0; i < l_outs_count; i++) {
        json_object *l_out = json_object_array_get_idx(l_outs_arr, i);
        json_object *l_status_obj = NULL;
        json_object_object_get_ex(l_out, "status", &l_status_obj);
        dap_assert_PIF(l_status_obj != NULL,
                       "REGRESSION: each UTXO in wallet outputs must have 'status' field");
        const char *l_status = json_object_get_string(l_status_obj);
        if (strcmp(l_status, "blocked") == 0) l_found_blocked = true;
        if (strcmp(l_status, "available") == 0) l_found_available = true;
        log_it(L_INFO, "  UTXO[%d] status=%s", i, l_status);
    }
    dap_assert_PIF(l_found_blocked,
                   "REGRESSION: wallet outputs must show at least one UTXO with status=blocked");
    dap_assert_PIF(l_found_available,
                   "REGRESSION: wallet outputs must show at least one UTXO with status=available");

    /* Verify blocked/available value totals */
    json_object *l_blocked_coins = NULL, *l_avail_coins = NULL;
    json_object_object_get_ex(l_wallet_obj, "blocked_value_coins", &l_blocked_coins);
    json_object_object_get_ex(l_wallet_obj, "available_value_coins", &l_avail_coins);
    dap_assert_PIF(l_blocked_coins != NULL,
                   "REGRESSION: wallet outputs must include blocked_value_coins when UTXOs are blocked");
    dap_assert_PIF(l_avail_coins != NULL,
                   "REGRESSION: wallet outputs must include available_value_coins when UTXOs are blocked");

    log_it(L_INFO, "  blocked_value_coins=%s, available_value_coins=%s",
           json_object_get_string(l_blocked_coins), json_object_get_string(l_avail_coins));

    json_object_put(l_jobj);
    DAP_DEL_Z(l_wallet_reply);

    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    dap_cert_delete(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("CLI wallet outputs blocked UTXO visibility PASSED");
}

static void test_edge_duplicate_block(void)
{
    dap_print_module_name("Edge case: blocking already-blocked UTXO is idempotent");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("cert_dup_blk", DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          "dup_blk_seed_42", 15);
    dap_cert_save_to_folder(l_cert, s_certs_dir);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "TDUP", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token with emission created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "TDUP", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");
    dap_assert_PIF(test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx) == 0, "TX added");

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    /* Block output 0 — first time */
    char l_cmd[4096];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net %s -chain %s -token TDUP -type CF20 -certs %s "
             "-utxo_blocked_add %s:0",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_tx_hash_str);

    char l_json_req[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "token_update", l_json_req, sizeof(l_json_req), 1);
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    DAP_DEL_Z(l_reply);
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Block output 0 — second time (duplicate) */
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "token_update", l_json_req, sizeof(l_json_req), 2);
    l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "Duplicate block reply: %s", l_reply ? l_reply : "(null)");
    DAP_DEL_Z(l_reply);
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Verify: UTXO is still blocked, ledger is consistent */
    uint256_t l_val = {};
    dap_list_t *l_list = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "TDUP", &l_addr, NULL, &l_val,
        false, 0, false, false);
    size_t l_count = l_list ? dap_list_length(l_list) : 0;
    log_it(L_INFO, "  After duplicate block, normal listing: %zu items (expected 1 — change only)", l_count);
    dap_assert_PIF(l_count == 1, "Duplicate block: output 0 still blocked, only change visible");
    dap_list_free_full(l_list, NULL);

    uint256_t l_val2 = {};
    dap_list_t *l_list2 = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "TDUP", &l_addr, NULL, &l_val2,
        false, 0, false, true);
    size_t l_count2 = l_list2 ? dap_list_length(l_list2) : 0;
    dap_assert_PIF(l_count2 == 2, "Duplicate block: skip_blocklist still returns both outputs");
    dap_list_free_full(l_list2, NULL);

    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    dap_cert_delete(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Duplicate UTXO block is idempotent PASSED");
}

static void test_edge_unblock_not_blocked(void)
{
    dap_print_module_name("Edge case: unblocking a non-blocked UTXO");

    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("cert_unblk", DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          "unblk_seed_42", 13);
    dap_cert_save_to_folder(l_cert, s_certs_dir);

    dap_chain_hash_fast_t l_emission_hash;
    test_token_fixture_t *l_token = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, "TUNB", "100000.0", "50000.0", &l_addr, l_cert, &l_emission_hash);
    dap_assert_PIF(l_token != NULL, "Token created");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "TUNB", "1000.0", &l_addr, l_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");
    dap_assert_PIF(test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx) == 0, "TX added");

    char l_tx_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_tx->tx_hash, l_tx_hash_str, sizeof(l_tx_hash_str));

    /* Try to unblock output 0 that was never blocked */
    char l_cmd[4096];
    snprintf(l_cmd, sizeof(l_cmd),
             "token_update -net %s -chain %s -token TUNB -type CF20 -certs %s "
             "-utxo_blocked_remove %s:0",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             l_cert->name, l_tx_hash_str);

    char l_json_req[8192];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "token_update", l_json_req, sizeof(l_json_req), 1);
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "Unblock non-blocked reply: %s", l_reply ? l_reply : "(null)");
    DAP_DEL_Z(l_reply);
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);

    /* Verify: all UTXOs still accessible (nothing broken) */
    uint256_t l_val = {};
    dap_list_t *l_list = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, "TUNB", &l_addr, NULL, &l_val,
        false, 0, false, false);
    size_t l_count = l_list ? dap_list_length(l_list) : 0;
    log_it(L_INFO, "  After unblock-not-blocked, normal listing: %zu items (expected 2)", l_count);
    dap_assert_PIF(l_count == 2, "Unblock non-blocked: all outputs still accessible");
    dap_list_free_full(l_list, NULL);

    test_tx_fixture_destroy(l_tx);
    test_token_fixture_destroy(l_token);
    dap_cert_delete(l_cert);
    dap_enc_key_delete(l_key);

    dap_pass_msg("Unblock non-blocked UTXO is safe PASSED");
}

int main(int argc, char **argv)
{
    UNUSED(argc); UNUSED(argv);
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);
    dap_print_module_name("Regression: Blocked UTXO visibility in listings");
    s_setup();
    test_blocked_utxo_visible_with_skip_blocklist();
    test_wallet_outputs_cli_shows_blocked_utxo();
    test_edge_duplicate_block();
    test_edge_unblock_not_blocked();
    s_teardown();
    log_it(L_NOTICE, "=== Blocked UTXO visibility regression test COMPLETE ===");
    return 0;
}
