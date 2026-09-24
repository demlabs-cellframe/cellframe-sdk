/**
 * @file test_utxo_blocklist_mc_common.c
 * @brief Implementation of shared scenario helpers (see the .h for details)
 */

#include "test_utxo_blocklist_mc_common.h"

#include "dap_chain_datum_tx.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_global_db.h"
#include "dap_test.h"
#include "dap_file_utils.h"
#include "utxo_blocking_test_helpers.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "utxo_blocklist_mc_common"

// Defined here once; both regression executables link this translation unit
test_net_fixture_t *s_net_fixture = NULL;

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];
static char s_wallets_dir[512];

int utxo_mc_setup_env(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    log_it(L_NOTICE, "=== utxo_mc: test environment setup ===");

    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_test_config_utxo_mc", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_test_gdb_utxo_mc", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_test_certs_utxo_mc", l_tmp);
    snprintf(s_wallets_dir, sizeof(s_wallets_dir), "%s/reg_test_wallets_utxo_mc", l_tmp);

    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_wallets_dir);

    dap_mkdir_with_parents(s_config_dir);
    dap_mkdir_with_parents(s_wallets_dir);
    dap_mkdir_with_parents(s_certs_dir);

    char l_cfg_path[1024];
    snprintf(l_cfg_path, sizeof(l_cfg_path), "%s/test.cfg", s_config_dir);
    FILE *l_cfg = fopen(l_cfg_path, "w");
    if (!l_cfg) {
        log_it(L_ERROR, "Can't create test config %s", l_cfg_path);
        return -1;
    }
    fprintf(l_cfg,
            "[general]\n"
            "debug_mode=true\n\n"
            "[ledger]\n"
            "debug_more=true\n\n"
            "[global_db]\n"
            "driver=mdbx\n"
            "path=%s\n\n"
            "[resources]\n"
            "wallets_path=%s\n"
            "ca_folders=%s\n",
            s_gdb_dir, s_wallets_dir, s_certs_dir);
    fclose(l_cfg);

    dap_chain_cs_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();

    test_env_init(s_config_dir, s_gdb_dir);
    dap_chain_wallet_cache_init();

    s_net_fixture = test_net_fixture_create("UtxoMcNet");
    if (!s_net_fixture) {
        log_it(L_ERROR, "Network fixture creation failed");
        return -1;
    }
    return 0;
}

void utxo_mc_teardown_env(void)
{
    log_it(L_NOTICE, "=== utxo_mc: test environment teardown ===");
    dap_chain_wallet_cache_deinit();
    dap_chain_node_cli_delete();
    if (s_net_fixture) {
        test_net_fixture_destroy(s_net_fixture);
        s_net_fixture = NULL;
    }
    test_env_deinit();
    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_wallets_dir);
}

static int s_ctx_addr_init(utxo_mc_ctx_t *a_ctx)
{
    memset(a_ctx, 0, sizeof(*a_ctx));

    a_ctx->spender_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    if (!a_ctx->spender_key)
        return -1;
    dap_chain_addr_fill_from_key(&a_ctx->spender_addr, a_ctx->spender_key, s_net_fixture->net->pub.id);

    a_ctx->dst_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    if (!a_ctx->dst_key)
        return -1;
    dap_chain_addr_fill_from_key(&a_ctx->dst_addr, a_ctx->dst_key, s_net_fixture->net->pub.id);

    a_ctx->owner_cert = DAP_NEW_Z(dap_cert_t);
    if (!a_ctx->owner_cert)
        return -1;
    a_ctx->owner_cert->enc_key = a_ctx->spender_key; // borrowed, freed via spender_key
    snprintf(a_ctx->owner_cert->name, sizeof(a_ctx->owner_cert->name), "utxo_mc_owner_cert");

    // No network fee for these scenarios
    dap_chain_addr_t l_blank_addr = {0};
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, uint256_0, l_blank_addr);
    return 0;
}

int utxo_mc_ctx_multichannel_init(utxo_mc_ctx_t *a_ctx)
{
    if (s_ctx_addr_init(a_ctx) != 0) {
        log_it(L_ERROR, "Failed to init addresses/cert");
        return -1;
    }

    // Both tokens in the parent input set: with native among them the main-ticker
    // derivation resolves to the non-native one (SECND), as in real fee-paying txs
    s_net_fixture->net->pub.native_ticker = UTXO_MC_TOK_NATIVE;

    dap_chain_hash_fast_t l_em_native = {}, l_em_second = {};
    a_ctx->tok_native = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, UTXO_MC_TOK_NATIVE, "10000.0", "5000.0",
        &a_ctx->spender_addr, a_ctx->owner_cert, &l_em_native);
    if (!a_ctx->tok_native)
        return -1;
    a_ctx->tok_second = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, UTXO_MC_TOK_SECOND, "10000.0", "5000.0",
        &a_ctx->spender_addr, a_ctx->owner_cert, &l_em_second);
    if (!a_ctx->tok_second)
        return -1;

    a_ctx->fund_native = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_em_native, UTXO_MC_TOK_NATIVE, UTXO_MC_FUND_VALUE,
        &a_ctx->spender_addr, a_ctx->owner_cert);
    if (!a_ctx->fund_native)
        return -1;
    if (test_tx_fixture_add_to_ledger(s_net_fixture->ledger, a_ctx->fund_native) != 0)
        return -1;

    a_ctx->fund_second = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_em_second, UTXO_MC_TOK_SECOND, UTXO_MC_FUND_VALUE,
        &a_ctx->spender_addr, a_ctx->owner_cert);
    if (!a_ctx->fund_second)
        return -1;
    if (test_tx_fixture_add_to_ledger(s_net_fixture->ledger, a_ctx->fund_second) != 0)
        return -1;

    // Multichannel parent: in SECND + in MCHN, out#0 = MCHN, out#1 = SECND
    dap_chain_datum_tx_t *l_parent = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_parent, &a_ctx->fund_second->tx_hash, 0);
    dap_chain_datum_tx_add_in_item(&l_parent, &a_ctx->fund_native->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_parent, &a_ctx->spender_addr,
                                        dap_chain_balance_scan(UTXO_MC_FUND_VALUE), UTXO_MC_TOK_NATIVE);
    dap_chain_datum_tx_add_out_ext_item(&l_parent, &a_ctx->spender_addr,
                                        dap_chain_balance_scan(UTXO_MC_FUND_VALUE), UTXO_MC_TOK_SECOND);
    dap_chain_datum_tx_add_sign_item(&l_parent, a_ctx->spender_key);

    dap_hash_fast(l_parent, dap_chain_datum_tx_get_size(l_parent), &a_ctx->parent_hash);
    int l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_parent, &a_ctx->parent_hash, false, NULL);
    log_it(L_INFO, "utxo_mc: multichannel parent %s add: %d (%s)",
           dap_chain_hash_fast_to_str_static(&a_ctx->parent_hash), l_res,
           dap_ledger_check_error_str(l_res));
    DAP_DELETE(l_parent);
    if (l_res != 0)
        return -1;

    dap_ledger_tx_item_t *l_item = NULL;
    dap_ledger_tx_find_datum_by_hash(s_net_fixture->ledger, &a_ctx->parent_hash, &l_item, false);
    if (!l_item)
        return -1;
    dap_strncpy(a_ctx->parent_main_ticker, l_item->cache_data.token_ticker,
                sizeof(a_ctx->parent_main_ticker) - 1);
    a_ctx->parent_multichannel = l_item->cache_data.multichannel;
    log_it(L_INFO, "utxo_mc: parent main ticker '%s', multichannel=%d",
           a_ctx->parent_main_ticker, (int)a_ctx->parent_multichannel);

    // The scenario requires main ticker != actual token of out #0
    if (!a_ctx->parent_multichannel || !dap_strcmp(a_ctx->parent_main_ticker, UTXO_MC_TOK_NATIVE)) {
        log_it(L_ERROR, "utxo_mc: parent is not a bypass-shaped multichannel tx "
                        "(main='%s' multichannel=%d)",
               a_ctx->parent_main_ticker, (int)a_ctx->parent_multichannel);
        return -1;
    }
    return 0;
}

int utxo_mc_ctx_single_init(utxo_mc_ctx_t *a_ctx)
{
    if (s_ctx_addr_init(a_ctx) != 0) {
        log_it(L_ERROR, "Failed to init addresses/cert");
        return -1;
    }

    dap_chain_hash_fast_t l_em_single = {};
    a_ctx->tok_single = test_token_fixture_create_with_emission(
        s_net_fixture->ledger, UTXO_MC_TOK_SINGLE, "10000.0", "5000.0",
        &a_ctx->spender_addr, a_ctx->owner_cert, &l_em_single);
    if (!a_ctx->tok_single)
        return -1;

    a_ctx->fund_single = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, &l_em_single, UTXO_MC_TOK_SINGLE, UTXO_MC_FUND_VALUE,
        &a_ctx->spender_addr, a_ctx->owner_cert);
    if (!a_ctx->fund_single)
        return -1;
    if (test_tx_fixture_add_to_ledger(s_net_fixture->ledger, a_ctx->fund_single) != 0)
        return -1;

    // Plain single-token parent: in SINGLE -> out#0 = SINGLE
    dap_chain_datum_tx_t *l_parent = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_in_item(&l_parent, &a_ctx->fund_single->tx_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_parent, &a_ctx->spender_addr,
                                        dap_chain_balance_scan(UTXO_MC_FUND_VALUE), UTXO_MC_TOK_SINGLE);
    dap_chain_datum_tx_add_sign_item(&l_parent, a_ctx->spender_key);

    dap_hash_fast(l_parent, dap_chain_datum_tx_get_size(l_parent), &a_ctx->single_parent_hash);
    int l_res = dap_ledger_tx_add(s_net_fixture->ledger, l_parent, &a_ctx->single_parent_hash, false, NULL);
    log_it(L_INFO, "utxo_mc: single-token parent %s add: %d (%s)",
           dap_chain_hash_fast_to_str_static(&a_ctx->single_parent_hash), l_res,
           dap_ledger_check_error_str(l_res));
    DAP_DELETE(l_parent);
    return l_res == 0 ? 0 : -1;
}

void utxo_mc_ctx_free(utxo_mc_ctx_t *a_ctx)
{
    if (a_ctx->fund_second)
        test_tx_fixture_destroy(a_ctx->fund_second);
    if (a_ctx->fund_native)
        test_tx_fixture_destroy(a_ctx->fund_native);
    if (a_ctx->fund_single)
        test_tx_fixture_destroy(a_ctx->fund_single);
    if (a_ctx->tok_second)
        test_token_fixture_destroy(a_ctx->tok_second);
    if (a_ctx->tok_native)
        test_token_fixture_destroy(a_ctx->tok_native);
    if (a_ctx->tok_single)
        test_token_fixture_destroy(a_ctx->tok_single);
    if (a_ctx->owner_cert) {
        a_ctx->owner_cert->enc_key = NULL; // key freed below
        DAP_DELETE(a_ctx->owner_cert);
    }
    if (a_ctx->dst_key)
        dap_enc_key_delete(a_ctx->dst_key);
    if (a_ctx->spender_key)
        dap_enc_key_delete(a_ctx->spender_key);
    memset(a_ctx, 0, sizeof(*a_ctx));
}

int utxo_mc_block(const char *a_ticker, test_token_fixture_t *a_token_fixture,
                  dap_chain_hash_fast_t *a_tx_hash, uint32_t a_out_idx)
{
    size_t l_update_size = 0;
    dap_chain_datum_token_t *l_update = utxo_blocking_test_create_token_update_with_utxo_block_tsd(
        a_ticker, a_tx_hash, a_out_idx, a_token_fixture->owner_cert, 0, &l_update_size);
    if (!l_update) {
        log_it(L_ERROR, "utxo_mc: token_update creation failed for %s", a_ticker);
        return -1;
    }
    int l_res = dap_ledger_token_add(s_net_fixture->ledger, (byte_t *)l_update, l_update_size, dap_time_now());
    log_it(L_INFO, "utxo_mc: token_update (%s blocklist) blocks %s:%u -> %d (%s)", a_ticker,
           dap_chain_hash_fast_to_str_static(a_tx_hash), a_out_idx,
           l_res, dap_ledger_check_error_str(l_res));
    DAP_DELETE(l_update);
    return l_res;
}

int utxo_mc_check_spend(dap_chain_hash_fast_t *a_parent_hash, uint32_t a_out_idx,
                        const char *a_token, dap_enc_key_t *a_spender_key,
                        dap_chain_addr_t *a_dst, const char *a_value, bool a_in_cond)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (a_in_cond)
        dap_chain_datum_tx_add_in_cond_item(&l_tx, a_parent_hash, a_out_idx, 0);
    else
        dap_chain_datum_tx_add_in_item(&l_tx, a_parent_hash, a_out_idx);
    dap_chain_datum_tx_add_out_ext_item(&l_tx, a_dst, dap_chain_balance_scan(a_value), a_token);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_spender_key);

    dap_chain_hash_fast_t l_tx_hash;
    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
    int l_res = dap_ledger_tx_add_check(s_net_fixture->ledger, l_tx,
                                        dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
    log_it(L_INFO, "utxo_mc: central check %s spend of %s:%u (%s): %d (%s)",
           a_in_cond ? "in_cond" : "in",
           dap_chain_hash_fast_to_str_static(a_parent_hash), a_out_idx, a_token,
           l_res, dap_ledger_check_error_str(l_res));
    DAP_DELETE(l_tx);
    return l_res;
}

bool utxo_mc_wallet_lists(const char *a_token, dap_chain_addr_t *a_addr,
                          dap_chain_hash_fast_t *a_tx_hash, uint32_t a_out_idx)
{
    dap_list_t *l_outs = dap_ledger_get_list_tx_outs_unspent_by_addr(
        s_net_fixture->ledger, a_token, a_addr, NULL, NULL, false, 0, false, false);
    bool l_found = false;
    for (dap_list_t *it = l_outs; it; it = it->next) {
        dap_chain_tx_used_out_item_t *l_out = it->data;
        if (l_out->num_idx_out == a_out_idx && dap_hash_fast_compare(&l_out->tx_hash_fast, a_tx_hash))
            l_found = true;
    }
    dap_list_free_full(l_outs, NULL);
    log_it(L_INFO, "utxo_mc: wallet enumeration (%s) %s %s:%u", a_token,
           l_found ? "RETURNS" : "hides",
           dap_chain_hash_fast_to_str_static(a_tx_hash), a_out_idx);
    return l_found;
}
