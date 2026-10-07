/**
 * @file ledger_cache_resume_integration_test.c
 * @brief Ledger cache (DAP_LEDGER_CACHE_ENABLED): incremental fill + resume
 * @details Verifies the cached ledger is filled incrementally while txs are
 * added (not rebuilt at the end), survives a graceful stop, and the next
 * start CONTINUES from the cached state instead of starting from scratch:
 *   - records for added txs appear in GlobalDB immediately (within the queue
 *     drain window), together with the balance records;
 *   - a restart (ledger freed and re-created from GlobalDB) restores exactly
 *     the cached txs - the cache is neither wiped nor duplicated;
 *   - adding more txs on top appends to the existing cache (count grows);
 *   - re-adding an already cached tx is idempotent (counts unchanged).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_file_utils.h"
#include "dap_enc.h"
#include "dap_cert.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_test.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_ledger.h"
#include "dap_global_db.h"
#include "dap_global_db_cluster.h"

#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_transaction_fixtures.h"

#define LOG_TAG "ledger_cache_resume_test"

#define TEST_NET_NAME      "ledger_cache_resume_test"
#define TEST_TOKEN_TICKER  "LCR1"
#define PHASE1_TXS         40
#define PHASE2_TXS         40
#define GDB_WAIT_TIMEOUT_MS 10000

static test_net_fixture_t *s_fixture = NULL;
static dap_enc_key_t *s_key = NULL;
static dap_cert_t *s_cert = NULL;
static dap_chain_addr_t s_test_addr = {};
static dap_chain_hash_fast_t s_emission_hash = {};
static test_token_fixture_t *s_token = NULL;
/* Tx datums we created (kept alive until teardown). */
static dap_chain_datum_tx_t *s_txs[PHASE1_TXS + PHASE2_TXS + 4] = {};
static size_t s_tx_count = 0;
static test_tx_fixture_t *s_first_spend = NULL;   /* owns s_txs[0] */

static uint64_t s_ledger_cache_flags(void)
{
    return DAP_LEDGER_CHECK_TOKEN_EMISSION | DAP_LEDGER_CHECK_LOCAL_DS | DAP_LEDGER_CACHE_ENABLED;
}

/* Number of records in the cached txs group right now. */
static size_t s_gdb_txs_count(dap_ledger_t *a_ledger)
{
    char *l_group = dap_ledger_get_gdb_group(a_ledger, DAP_LEDGER_TXS_STR);
    size_t l_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_group, &l_count);
    if (l_objs)
        dap_global_db_objs_delete(l_objs, l_count);
    DAP_DELETE(l_group);
    return l_count;
}

/* The record writes go through the GlobalDB I/O pool: wait (bounded) until
 * the group reflects everything added so far. A failure here means the cache
 * is NOT filled incrementally. */
static void s_wait_gdb_txs_at_least(dap_ledger_t *a_ledger, size_t a_expected)
{
    for (int i = 0; i < GDB_WAIT_TIMEOUT_MS / 20; ++i) {
        if (s_gdb_txs_count(a_ledger) >= a_expected)
            return;
        dap_usleep(20 * 1000);
    }
}

static dap_chain_datum_tx_t *s_make_spend_tx(const dap_chain_hash_fast_t *a_prev_hash, uint256_t a_value)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_return_val_if_fail(l_tx, NULL);
    dap_chain_datum_tx_add_in_item(&l_tx, (dap_chain_hash_fast_t *)a_prev_hash, 0);
    dap_chain_datum_tx_add_out_ext_item(&l_tx, &s_test_addr, a_value, TEST_TOKEN_TICKER);
    dap_chain_datum_tx_add_sign_item(&l_tx, s_key);
    return l_tx;
}

static char s_cfg_dir[512], s_gdb_dir[512], s_certs_dir[512];
static dap_config_t *s_config = NULL;

static void s_setup(void)
{
    dap_enc_init();
    dap_chain_wallet_init();

    snprintf(s_cfg_dir, sizeof(s_cfg_dir), "%s/ledger_cache_resume_test_config", test_get_temp_dir());
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/ledger_cache_resume_test_gdb", test_get_temp_dir());
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/ledger_cache_resume_test_certs", test_get_temp_dir());
    dap_mkdir_with_parents(s_cfg_dir);
    dap_mkdir_with_parents(s_certs_dir);

    // Config that points GlobalDB at a private directory (same shape as the
    // DEX integration test uses).
    char l_config_content[2048];
    snprintf(l_config_content, sizeof(l_config_content),
        "[general]\ndebug_mode=true\n"
        "[global_db]\ndriver=%s\npath=%s\n"
        "[resources]\nca_folders=%s\n", getenv("LCR_GDB_DRIVER") ? getenv("LCR_GDB_DRIVER") : "mdbx", s_gdb_dir, s_certs_dir);
    char l_config_path[1024];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", s_cfg_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    dap_assert_PIF(l_config_file != NULL, "Test config written");
    fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
    fclose(l_config_file);

    dap_config_init(s_cfg_dir);
    s_config = dap_config_open("test");
    dap_assert_PIF(s_config != NULL, "Config opened");
    char l_log_path[1024];
    snprintf(l_log_path, sizeof(l_log_path), "%s/log.txt", s_cfg_dir);
    dap_common_init(NULL, l_log_path);

    dap_assert_PIF(test_env_init(s_cfg_dir, s_gdb_dir) == 0, "Test environment init");
    dap_ledger_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();

    s_fixture = test_net_fixture_create(TEST_NET_NAME);
    dap_assert_PIF(s_fixture != NULL, "Network fixture created");

    // Swap the plain fixture ledger for a cached one on the same network. Publish the new
    // ledger before freeing the old one: chain timers registered for the network write into
    // net->pub.ledger (s_blockchain_timer_callback), so freeing it first leaves them writing
    // into freed memory for as long as the swap takes.
    dap_ledger_t *l_old_ledger = s_fixture->ledger;
    s_fixture->ledger = dap_ledger_create(s_fixture->net, s_ledger_cache_flags());
    dap_assert_PIF(s_fixture->ledger != NULL, "Cached ledger created");
    s_fixture->net->pub.ledger = s_fixture->ledger;
    if (l_old_ledger)
        dap_ledger_handle_free(l_old_ledger);
    s_fixture->net->pub.ledger = s_fixture->ledger;

    s_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(s_key != NULL, "Key generated");
    s_cert = DAP_NEW_Z(dap_cert_t);
    dap_assert_PIF(s_cert != NULL, "Certificate allocated");
    s_cert->enc_key = s_key;
    snprintf(s_cert->name, sizeof(s_cert->name), "ledger_cache_resume_test_cert");
    dap_assert_PIF(dap_cert_add(s_cert) == 0, "Certificate added to storage");
    dap_chain_addr_fill_from_key(&s_test_addr, s_key, s_fixture->net->pub.id);
    s_fixture->net->pub.fee_value = uint256_0;
    s_fixture->net->pub.fee_addr = c_dap_chain_addr_blank;

    // Sanity probe: the GlobalDB in this test environment must accept and
    // return a plain record (isolates "set_raw never lands" from "tx_add
    // never calls it").
    char l_probe_group[256];
    snprintf(l_probe_group, sizeof(l_probe_group), "local.ledger-cache.%s.probe", s_fixture->net->pub.name);
    dap_global_db_set(l_probe_group, "k1", "v1", 3, false, NULL, NULL);
    {
        bool l_probe_ok = false;
        for (int i = 0; i < 200 && !l_probe_ok; ++i) {
            size_t l_cnt = 0;
            dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_probe_group, &l_cnt);
            if (l_objs && l_cnt) { l_probe_ok = true; dap_global_db_objs_delete(l_objs, l_cnt); }
            else dap_usleep(10 * 1000);
        }
        log_it(L_NOTICE, "ledger_cache_resume: GlobalDB probe %s", l_probe_ok ? "PASS" : "FAILED");
        dap_assert_PIF(l_probe_ok, "GlobalDB accepts writes in the test environment");
    }

    s_token = test_token_fixture_create_with_emission(s_fixture->ledger, TEST_TOKEN_TICKER,
                                                      "100000.0", "50000.0", &s_test_addr, s_cert, &s_emission_hash);
    dap_assert_PIF(s_token != NULL, "Token with emission created");
}

static void s_add_spend_chain(size_t a_count)
{
    for (size_t i = 0; i < a_count; ++i) {
        if (s_tx_count == 0) {
            // The very first tx must spend the emission (an emission is not a
            // tx, so the fixture's dedicated helper builds it).
            test_tx_fixture_t *l_first = test_tx_fixture_create_from_emission(
                s_fixture->ledger, &s_emission_hash, TEST_TOKEN_TICKER, "500.0", &s_test_addr, s_cert);
            dap_assert_PIF(l_first != NULL, "Emission spend tx created");
            dap_assert_PIF(test_tx_fixture_add_to_ledger(s_fixture->ledger, l_first) == 0,
                           "Emission spend tx added to the ledger");
            s_first_spend = l_first;
            s_txs[s_tx_count++] = l_first->tx;
            continue;
        }
        dap_chain_hash_fast_t l_prev_hash;
        dap_hash_fast(s_txs[s_tx_count - 1], dap_chain_datum_tx_get_size(s_txs[s_tx_count - 1]), &l_prev_hash);
        // Spend out#0 of the previous tx in full: the chain stays balanced and
        // every tx spends the same 500.0 output.
        dap_chain_datum_tx_t *l_tx = s_make_spend_tx(&l_prev_hash, dap_chain_balance_scan("500.0"));
        dap_assert_PIF(l_tx != NULL, "Spend tx created");
        dap_chain_hash_fast_t l_hash;
        dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);
        int l_res = dap_ledger_tx_add(s_fixture->ledger, l_tx, &l_hash, false, NULL);
        dap_assert_PIF(l_res == 0, "Tx added to the ledger");
        s_txs[s_tx_count++] = l_tx;
    }
}

/* The cache must contain records for the txs already processed, while the
 * process is still running (fill is incremental, not rebuilt at the end). */
static void s_test_incremental_fill(void)
{
    s_add_spend_chain(PHASE1_TXS);
    s_wait_gdb_txs_at_least(s_fixture->ledger, PHASE1_TXS);
    size_t l_gdb_count = s_gdb_txs_count(s_fixture->ledger);
    log_it(L_NOTICE, "ledger_cache_resume: RAM txs=%u, GDB txs=%zu (expected %d)",
           dap_ledger_count(s_fixture->ledger), l_gdb_count, PHASE1_TXS);
    dap_assert(l_gdb_count == PHASE1_TXS,
               "Ledger cache holds one record per added tx while running");
    dap_assert(dap_ledger_count(s_fixture->ledger) == PHASE1_TXS, "Ledger holds all phase-1 txs");
}

/* Graceful stop (ledger freed, cache left on disk) + fresh start must restore
 * exactly the cached state - no wipe, no duplicates. */
static void s_test_resume_after_stop(void)
{
    // Restart: new ledger published first, old one freed after (see the setup swap).
    dap_ledger_t *l_old_ledger = s_fixture->ledger;
    s_fixture->ledger = dap_ledger_create(s_fixture->net, s_ledger_cache_flags());
    dap_assert_PIF(s_fixture->ledger != NULL, "Cached ledger re-created (restart)");
    s_fixture->net->pub.ledger = s_fixture->ledger;
    if (l_old_ledger)
        dap_ledger_handle_free(l_old_ledger);

    dap_assert(dap_ledger_count(s_fixture->ledger) == PHASE1_TXS,
               "Restart restored phase-1 txs from the cache");
    dap_assert(s_gdb_txs_count(s_fixture->ledger) == PHASE1_TXS,
               "Restart did not wipe or duplicate the cache");

    // Continue building on top of the restored cache.
    s_add_spend_chain(PHASE2_TXS);
    s_wait_gdb_txs_at_least(s_fixture->ledger, PHASE1_TXS + PHASE2_TXS);
    dap_assert(dap_ledger_count(s_fixture->ledger) == PHASE1_TXS + PHASE2_TXS,
               "Cache continued from the stop point (all txs present)");
    dap_assert(s_gdb_txs_count(s_fixture->ledger) == PHASE1_TXS + PHASE2_TXS,
               "Cache appended phase-2 txs without duplicates");
}

/* Re-adding an already cached tx changes nothing. */
static void s_test_readd_idempotent(void)
{
    dap_chain_datum_tx_t *l_first = s_txs[0];
    dap_chain_hash_fast_t l_hash;
    dap_hash_fast(l_first, dap_chain_datum_tx_get_size(l_first), &l_hash);
    dap_ledger_tx_add(s_fixture->ledger, l_first, &l_hash, false, NULL);
    dap_assert(dap_ledger_count(s_fixture->ledger) == PHASE1_TXS + PHASE2_TXS,
               "Re-adding a cached tx is idempotent");
}

/* A restart that lands in the middle of a chain load: the cache already holds the txs and the
 * loader walks the chain again from its beginning. A tx the cache restored must be recognized
 * as already present instead of being re-processed (that is what makes the resume cheap), and
 * a tx past the cached point must be appended and cached as usual. */
static void s_test_resume_mid_load(void)
{
    size_t l_size_before = dap_ledger_count(s_fixture->ledger);
    size_t l_gdb_before = s_gdb_txs_count(s_fixture->ledger);

    dap_chain_net_test_set_load_mode(s_fixture->net, true);

    dap_chain_hash_fast_t l_cached_hash;
    dap_hash_fast(s_txs[0], dap_chain_datum_tx_get_size(s_txs[0]), &l_cached_hash);
    int l_res = dap_ledger_tx_load(s_fixture->ledger, s_txs[0], &l_cached_hash, NULL);
    dap_assert(l_res == DAP_LEDGER_CHECK_ALREADY_CACHED,
               "Mid-load resume: a tx restored from the cache is not processed twice");
    dap_assert(dap_ledger_count(s_fixture->ledger) == l_size_before,
               "Mid-load resume: ledger size unchanged for a cached tx");

    // The next tx the loader would produce after the cached point.
    dap_chain_hash_fast_t l_prev_hash;
    dap_hash_fast(s_txs[s_tx_count - 1], dap_chain_datum_tx_get_size(s_txs[s_tx_count - 1]), &l_prev_hash);
    dap_chain_datum_tx_t *l_tx = s_make_spend_tx(&l_prev_hash, dap_chain_balance_scan("500.0"));
    dap_assert_PIF(l_tx != NULL, "Mid-load resume: continuation tx created");
    dap_chain_hash_fast_t l_tx_hash;
    dap_hash_fast(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_tx_hash);
    l_res = dap_ledger_tx_load(s_fixture->ledger, l_tx, &l_tx_hash, NULL);
    dap_assert(l_res == 0, "Mid-load resume: the tx past the cached point is loaded");
    s_txs[s_tx_count++] = l_tx;
    dap_assert(dap_ledger_count(s_fixture->ledger) == l_size_before + 1,
               "Mid-load resume: the ledger continues from the cached state");

    dap_chain_net_test_set_load_mode(s_fixture->net, false);

    s_wait_gdb_txs_at_least(s_fixture->ledger, l_gdb_before + 1);
    dap_assert(s_gdb_txs_count(s_fixture->ledger) == l_gdb_before + 1,
               "Mid-load resume: the continuation tx is cached too");
}

/* Cache reset must drop every cached group, leave the ledger itself alone and let the cache
 * start filling again from that point. */
static void s_test_cache_reset(void)
{
    size_t l_size_before = dap_ledger_count(s_fixture->ledger);
    dap_assert(s_gdb_txs_count(s_fixture->ledger) > 0, "Cache holds records before the reset");

    dap_assert(dap_ledger_cache_reset(s_fixture->ledger) == 0, "Ledger cache reset reports success");
    dap_assert(s_gdb_txs_count(s_fixture->ledger) == 0, "Cache reset dropped the cached txs");
    dap_assert(dap_ledger_count(s_fixture->ledger) == l_size_before,
               "Cache reset left the ledger itself untouched");

    s_add_spend_chain(1);
    s_wait_gdb_txs_at_least(s_fixture->ledger, 1);
    dap_assert(s_gdb_txs_count(s_fixture->ledger) >= 1, "Cache fills again after the reset");
    dap_assert(dap_ledger_count(s_fixture->ledger) == l_size_before + 1,
               "Ledger grew by the transaction added after the reset");
}

static void s_teardown(void)
{
    if (s_first_spend) { test_tx_fixture_destroy(s_first_spend); s_first_spend = NULL; }
    for (size_t i = (s_first_spend ? 0 : s_tx_count); i < s_tx_count; ++i)
        dap_chain_datum_tx_delete(s_txs[i]);
    s_tx_count = 0;
    if (s_token)   { test_token_fixture_destroy(s_token); s_token = NULL; }
    // The certificate is owned by the cert storage (dap_cert_add took it).
    s_cert = NULL;
    if (s_key)     { dap_enc_key_delete(s_key); s_key = NULL; }
    if (s_fixture) { test_net_fixture_destroy(s_fixture); s_fixture = NULL; }
    test_env_deinit();
    if (s_config) { dap_config_close(s_config); s_config = NULL; }
    dap_config_deinit();
    dap_rm_rf(s_cfg_dir);
    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
}

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;
    dap_test_msg("Ledger cache: incremental fill and resume");
    s_setup();

    s_test_incremental_fill();
    s_test_resume_after_stop();
    s_test_readd_idempotent();
    s_test_resume_mid_load();
    s_test_cache_reset();

    s_teardown();
    dap_test_msg("Ledger cache resume tests completed");
    return 0;
}
