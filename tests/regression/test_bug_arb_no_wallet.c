/*
 * Regression test: Arbitrage TX requires wallet, no cert-only path
 *
 * Bug: The arbitrage mechanism requires a wallet (from_wallet) to create the transaction.
 *      There is no way to perform arbitrage using only token owner certificates without
 *      owning a wallet with funds. The first TX signature is always treated as a "wallet"
 *      signature and skipped during owner authorization, making it impossible to authorize
 *      an arbitrage TX when the only signers are token owner certs.
 *
 * Expected: An arbitrage TX signed solely by authorized token owner certificate(s) should
 *           be processable. The arbitrage authorization should recognize that if the signer
 *           IS a token owner, it counts for authorization even as the first signature.
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
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"

#define LOG_TAG "regression_arb_no_wallet"

test_net_fixture_t *s_net_fixture = NULL;

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

static void test_arbitrage_with_owner_cert_only(void)
{
    dap_print_module_name("Arbitrage No-Wallet Test: owner cert signs arbitrage TX without wallet");

    dap_enc_key_t *l_owner_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_owner_key != NULL, "Owner key generation");

    dap_chain_addr_t l_owner_addr = {0};
    dap_chain_addr_fill_from_key(&l_owner_addr, l_owner_key, s_net_fixture->net->pub.id);

    dap_cert_t *l_owner_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(l_owner_cert != NULL, "Cert allocation");
    l_owner_cert->enc_key = l_owner_key;
    snprintf(l_owner_cert->name, sizeof(l_owner_cert->name), "cert_arb_owner");

    dap_chain_hash_fast_t l_emission_hash;
    int l_res = s_create_token_with_auth(s_net_fixture->ledger, "ARBNW", "100000.0", "50000.0",
                                          &l_owner_addr, l_owner_cert, &l_emission_hash);
    dap_assert_PIF(l_res == 0, "Token created (signs_valid=1)");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_emission_hash, "ARBNW", "1000.0", &l_owner_addr, l_owner_cert);
    dap_assert_PIF(l_tx != NULL, "TX created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx);
    dap_assert_PIF(l_res == 0, "TX added to ledger");

    // Block UTXO so we need arbitrage to spend it
    size_t l_block_size = 0;
    dap_chain_datum_token_t *l_block_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        "ARBNW", &l_tx->tx_hash, 0, l_owner_cert, 0, &l_block_size);
    dap_assert_PIF(l_block_update != NULL, "Block update created");

    l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_block_update, l_block_size, dap_time_now());
    dap_assert_PIF(l_res == 0, "UTXO blocked");
    DAP_DELETE(l_block_update);

    // Set fee address
    uint256_t l_zero_fee = uint256_0;
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_owner_addr);

    // Create arbitrage TX signed ONLY by the owner cert (no separate wallet signature)
    dap_chain_datum_tx_t *l_arb_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_arb_tx, &l_tx->tx_hash, 0);

    byte_t l_arb_data = 0;
    dap_chain_tx_tsd_t *l_tsd_arb = dap_chain_datum_tx_item_tsd_create(&l_arb_data, DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE, 1);
    dap_chain_datum_tx_add_item(&l_arb_tx, (const uint8_t *)l_tsd_arb);
    DAP_DELETE(l_tsd_arb);

    dap_chain_datum_tx_add_out_ext_item(&l_arb_tx, &l_owner_addr, dap_chain_balance_scan("1000.0"), "ARBNW");

    // Sign ONLY with owner cert — no wallet signature
    dap_chain_datum_tx_add_sign_item(&l_arb_tx, l_owner_key);

    dap_chain_hash_fast_t l_arb_hash;
    dap_hash_fast(l_arb_tx, dap_chain_datum_tx_get_size(l_arb_tx), &l_arb_hash);

    l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_arb_tx, &l_arb_hash, false, NULL);
    log_it(L_INFO, "  Arbitrage TX (owner-only, no wallet) result: %d (%s)", l_res, dap_ledger_check_error_str(l_res));

    // BUG: Currently the first (and only) signature is skipped as "wallet" signature,
    //      leaving 0 owner signs. The auth check fails with NOT_ENOUGH_VALID_SIGNS.
    // EXPECTED: Owner cert signature should be recognized as authorization even when
    //           it is the first/only signature.
    dap_assert_PIF(l_res == 0,
                   "REGRESSION: Arbitrage TX signed only by owner cert should be authorized");

    DAP_DELETE(l_arb_tx);
    test_tx_fixture_destroy(l_tx);
    l_owner_cert->enc_key = NULL;
    DAP_DELETE(l_owner_cert);
    dap_enc_key_delete(l_owner_key);

    dap_pass_msg("Arbitrage no-wallet test PASSED");
}

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];

static void s_setup(void)
{
    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_arb_nw_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_arb_nw_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_arb_nw_certs", l_tmp);

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
    s_net_fixture = test_net_fixture_create("RegArbNW");
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
    dap_print_module_name("Regression: Arbitrage TX without wallet (cert-only)");
    s_setup();
    test_arbitrage_with_owner_cert_only();
    s_teardown();
    log_it(L_NOTICE, "=== Arbitrage no-wallet regression test COMPLETE ===");
    return 0;
}
