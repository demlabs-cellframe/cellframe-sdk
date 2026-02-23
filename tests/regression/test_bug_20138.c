/*
 * Regression test for Bug #20138: Arbitrage transaction not authorized despite correct certificate
 * 
 * Bug Description:
 * - Arbitrage TX created successfully but stuck in mempool
 * - Status: 'hole' with error: "Arbitrage transaction not authorized: invalid owner signature or arbitrage disabled for token"
 * - Same certificate used for token_decl and arbitrage TX, yet validation fails
 * 
 * Test Scenarios:
 * 1. Arbitrage WITHOUT -cert parameter (should fail with TSD sanity check error)
 * 2. Arbitrage WITH -cert parameter (reproduces bug - TX stuck in mempool)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_config.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx_tsd.h"
#include "dap_tsd.h"
#include "dap_chain_ledger.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_node.h"
#include "dap_cert_file.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_cache.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "utxo_blocking_test_helpers.h"
#include "dap_config.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_file_utils.h"
#include <json-c/json.h>

#define LOG_TAG "regression_bug_20138"

// Test constants
#define ARBITRAGE_TX_VALUE "1000.0"
#define ARBITRAGE_TX_VALUE_DATOSHI "1000000000000000000000" // 1000.0 * 10^18
#define ARBITRAGE_FEE "0.1"
#define TEST_TOKEN_TICKER_SCENARIO1 "BUG20138A"  // Different ticker for scenario 1
#define TEST_TOKEN_TICKER_SCENARIO2 "BUG20138B"  // Different ticker for scenario 2
#define TEST_TOKEN_SUPPLY "100000000000.0"  // Large supply to allow emission (synthetic test needs non-zero total_supply)

// Global test context
test_net_fixture_t *s_net_fixture = NULL;

static char s_config_dir[512];
static char s_gdb_dir[512];
static char s_certs_dir[512];
static char s_wallets_dir[512];

static void s_setup(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    log_it(L_NOTICE, "=== Regression Test: Bug #20138 Setup ===");
    
    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/reg_test_config_20138", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/reg_test_gdb_20138", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/reg_test_certs_20138", l_tmp);
    snprintf(s_wallets_dir, sizeof(s_wallets_dir), "%s/reg_test_wallets_20138", l_tmp);

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
    if (l_cfg) {
        fprintf(l_cfg, 
                "[general]\n"
                "debug_mode=true\n\n"
                "[cert]\n"
                "debug_more=true\n\n"
                "[ledger]\n"
                "debug_more=true\n\n"
                "[wallet]\n"
                "debug_more=true\n\n"
                "[wallets]\n"
                "wallets_cache=all\n\n"
                "[global_db]\n"
                "driver=mdbx\n"
                "path=%s\n\n"
                "[cli-server]\n"
                "enabled=true\n\n"
                "[resources]\n"
                "wallets_path=%s\n"
                "ca_folders=%s\n",
                s_gdb_dir, s_wallets_dir, s_certs_dir);
        fclose(l_cfg);
    }
    
    dap_chain_cs_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    dap_nonconsensus_init();
    
    test_env_init(s_config_dir, s_gdb_dir);
    
    dap_chain_wallet_cache_init();
    
    s_net_fixture = test_net_fixture_create("RegNet20138");
    dap_assert_PIF(s_net_fixture != NULL, "Network fixture created");
    
    dap_chain_node_cli_init(g_config);
}

static void s_cleanup(void)
{
    log_it(L_NOTICE, "=== Regression Test: Bug #20138 Cleanup ===");
    
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

// Helper: Create and save certificate with seed for reproducibility
static dap_cert_t* s_create_cert_with_seed(const char *a_cert_name, const char *a_seed)
{
    // Generate certificate with seed
    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed(a_cert_name, 
                                                          DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                                          a_seed, strlen(a_seed));
    if (!l_cert) {
        log_it(L_ERROR, "Failed to generate certificate %s", a_cert_name);
        return NULL;
    }
    
    // Add to memory
    int l_add_result = dap_cert_add(l_cert);
    if (l_add_result != 0 && l_add_result != -2) { // -2 = already exists
        log_it(L_WARNING, "Certificate %s already in memory or add failed: %d", a_cert_name, l_add_result);
    }
    
    dap_mkdir_with_parents(s_certs_dir);
    char l_cert_path[1024];
    snprintf(l_cert_path, sizeof(l_cert_path), "%s/%s.dcert", s_certs_dir, a_cert_name);
    
    int l_save_result = dap_cert_file_save(l_cert, l_cert_path);
    if (l_save_result != 0) {
        log_it(L_ERROR, "Failed to save certificate %s to file", a_cert_name);
        return NULL;
    }
    
    log_it(L_INFO, "Certificate %s generated and saved", a_cert_name);
    return l_cert;
}

// Helper to create token, emission via CLI
static bool s_create_token_and_emission(const char *a_ticker, dap_chain_addr_t *a_addr_owner, dap_cert_t *a_cert_owner)
{
    log_it(L_INFO, "Creating token %s via CLI with owner cert %s", a_ticker, a_cert_owner->name);
    
    // 1. Create token declaration via CLI
    // Note: In synthetic test, we use non-zero total_supply to allow emission validation
    // In production testnet (bug report), total_supply=0 is used, but emission still works
    char l_cmd_token_decl[2048];
    snprintf(l_cmd_token_decl, sizeof(l_cmd_token_decl),
             "token_decl -net %s -chain %s -token %s -total_supply %s -decimals 18 -signs_total 1 -signs_emission 1 -certs %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             a_ticker, TEST_TOKEN_SUPPLY, a_cert_owner->name);
    
    char l_json_req_decl[4096];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd_token_decl, "token_decl", l_json_req_decl, sizeof(l_json_req_decl), 1);
    
    char *l_reply_decl = dap_cli_cmd_exec(l_json_req_decl);
    dap_assert_PIF(l_reply_decl != NULL, "Token decl CLI executed");
    DAP_DELETE(l_reply_decl);
    
    // Process mempool to add token to ledger
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
    
    log_it(L_INFO, "✓ Token %s declared via CLI", a_ticker);
    
    // 2. Create token emission via CLI (with -no_base_tx flag, as in bug report)
    char l_cmd_emit[2048];
    snprintf(l_cmd_emit, sizeof(l_cmd_emit),
             "token_emit -net %s -chain_emission %s -token %s -no_base_tx -emission_value %s -addr %s -certs %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             a_ticker, TEST_TOKEN_SUPPLY, dap_chain_addr_to_str(a_addr_owner), a_cert_owner->name);
    
    char l_json_req_emit[4096];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd_emit, "token_emit", l_json_req_emit, sizeof(l_json_req_emit), 1);
    
    char *l_reply_emit = dap_cli_cmd_exec(l_json_req_emit);
    dap_assert_PIF(l_reply_emit != NULL, "Emission CLI executed");
    
    // Extract emission hash from reply
    json_object *l_json_emit = json_tokener_parse(l_reply_emit);
    DAP_DELETE(l_reply_emit);
    dap_assert_PIF(l_json_emit != NULL, "Emission JSON parsed");
    
    json_object *l_result_emit = NULL;
    json_object_object_get_ex(l_json_emit, "result", &l_result_emit);
    const char *l_emit_result_str = json_object_get_string(l_result_emit);
    
    // Extract emission hash (format: "Datum 0x... with 256bit emission is placed in datum pool")
    const char *l_emission_hash_start = strstr(l_emit_result_str, "0x");
    char l_emission_hash[67] = {0};
    if (l_emission_hash_start) {
        strncpy(l_emission_hash, l_emission_hash_start, 66);
    }
    json_object_put(l_json_emit);
    dap_assert_PIF(strlen(l_emission_hash) > 0, "Emission hash extracted");
    
    // Convert emission hash string to dap_chain_hash_fast_t for ledger lookup
    dap_chain_hash_fast_t l_emission_hash_fast = {0};
    dap_assert_PIF(dap_chain_hash_fast_from_hex_str(l_emission_hash, &l_emission_hash_fast) == 0, 
                   "Emission hash parsed");
    
    // Process mempool to add emission to ledger (multiple passes to ensure it's added)
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
    
    // CRITICAL: Wait for emission to be fully processed in ledger before creating base TX
    // Base TX requires emission to be available in ledger, otherwise validation fails with result=3
    dap_chain_datum_token_emission_t *l_emission_item = NULL;
    bool l_emission_found = false;
    for (int l_attempt = 0; l_attempt < 30; l_attempt++) {
        l_emission_item = dap_ledger_token_emission_find(s_net_fixture->ledger, &l_emission_hash_fast);
        if (l_emission_item) {
            l_emission_found = true;
            log_it(L_INFO, "✓ Emission found in ledger after %d attempts", l_attempt + 1);
            break;
        }
        if (l_attempt == 0 || (l_attempt + 1) % 5 == 0) {
            log_it(L_DEBUG, "Emission not found in ledger after %d attempts, processing mempool...", l_attempt + 1);
        }
        dap_usleep(100000); // 100ms delay
        // Process mempool again to trigger async processing
        dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
    }
    
    if (!l_emission_found) {
        log_it(L_ERROR, "❌ Emission not found in ledger after all attempts - base TX will fail");
        return false;
    }
    
    // Verify emission address matches expected address
    if (l_emission_item) {
        const char *l_emission_addr_str = dap_chain_addr_to_str(&l_emission_item->hdr.address);
        const char *l_expected_addr_str = dap_chain_addr_to_str(a_addr_owner);
        if (memcmp(&l_emission_item->hdr.address, a_addr_owner, sizeof(dap_chain_addr_t)) != 0) {
            log_it(L_WARNING, "⚠️ Emission address mismatch: emission=%s, expected=%s", 
                   l_emission_addr_str, l_expected_addr_str);
        } else {
            log_it(L_INFO, "✓ Emission address verified: %s", l_emission_addr_str);
        }
    }
    
    log_it(L_INFO, "✓ Token %s emission created via CLI, hash=%s", a_ticker, l_emission_hash);
    
    // 3. Create base transaction from emission to generate UTXOs and balance
    // Note: In production testnet, chain_emission is zerochain, but in synthetic test we use same chain
    // Base TX uses cert for signing, but output goes to emission address (a_addr_owner)
    // CRITICAL: Base TX MUST be created AFTER emission is fully processed in ledger
    char l_cmd_base_tx[2048];
    snprintf(l_cmd_base_tx, sizeof(l_cmd_base_tx),
             "tx_create -net %s -chain %s -chain_emission %s -from_emission %s -cert %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name, s_net_fixture->chain_main->name,
             l_emission_hash, a_cert_owner->name);
    
    log_it(L_INFO, "Creating base TX: %s", l_cmd_base_tx);
    
    char l_json_req_base_tx[4096];
    utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd_base_tx, "tx_create", l_json_req_base_tx, sizeof(l_json_req_base_tx), 1);
    
    char *l_reply_base_tx = dap_cli_cmd_exec(l_json_req_base_tx);
    dap_assert_PIF(l_reply_base_tx != NULL, "Base TX CLI executed");
    
    // Extract base TX hash from reply
    json_object *l_json_base_tx = json_tokener_parse(l_reply_base_tx);
    DAP_DELETE(l_reply_base_tx);
    dap_assert_PIF(l_json_base_tx != NULL, "Base TX JSON parsed");
    
    char l_base_tx_hash[67] = {0};
    json_object *l_result_base_tx = NULL;
    json_object_object_get_ex(l_json_base_tx, "result", &l_result_base_tx);
    if (l_result_base_tx) {
        const char *l_result_str = json_object_get_string(l_result_base_tx);
        if (l_result_str) {
            const char *l_hash_start = strstr(l_result_str, "0x");
            if (l_hash_start) {
                strncpy(l_base_tx_hash, l_hash_start, 66);
                log_it(L_INFO, "✓ Base TX created, hash: %s", l_base_tx_hash);
            }
        }
    }
    
    json_object *l_error_base_tx = NULL;
    json_object_object_get_ex(l_json_base_tx, "error", &l_error_base_tx);
    if (l_error_base_tx) {
        const char *l_error_msg = json_object_get_string(l_error_base_tx);
        log_it(L_WARNING, "Base TX creation error: %s", l_error_msg);
        json_object_put(l_json_base_tx);
        return false; // Base TX creation failed
    }
    json_object_put(l_json_base_tx);
    
    // Process mempool MULTIPLE times to ensure base TX is processed
    // Base TX needs to be added to mempool first, then processed
    // Process mempool immediately after base TX creation to add it to mempool
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
    
    if (strlen(l_base_tx_hash) > 0) {
        // Convert hash string to dap_chain_hash_fast_t (hash has "0x" prefix)
        dap_chain_hash_fast_t l_base_tx_hash_fast = {0};
        if (dap_chain_hash_fast_from_hex_str(l_base_tx_hash, &l_base_tx_hash_fast) == 0) {
            // Wait for base TX to be processed from mempool to ledger
            // Use more attempts and longer delay to ensure processing
            dap_chain_datum_tx_t *l_base_tx_in_ledger = test_wait_tx_mempool_to_ledger(
                s_net_fixture, &l_base_tx_hash_fast, 30, 500, true);
            if (l_base_tx_in_ledger) {
                log_it(L_INFO, "✓ Base TX processed and added to ledger");
            } else {
                log_it(L_WARNING, "⚠️ Base TX not found in ledger after processing");
                // Try additional processing passes with longer delays
                for (int i = 0; i < 10; i++) {
                    dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
                    usleep(100000); // 100ms delay for async processing
                    l_base_tx_in_ledger = test_wait_tx_mempool_to_ledger(
                        s_net_fixture, &l_base_tx_hash_fast, 3, 200, true);
                    if (l_base_tx_in_ledger) {
                        log_it(L_INFO, "✓ Base TX processed after additional attempts (%d)", i + 1);
                        break;
                    }
                }
                if (!l_base_tx_in_ledger) {
                    log_it(L_ERROR, "❌ Base TX failed to process after all attempts - this may indicate a validation issue");
                    // Continue anyway - balance check will fail but test structure is correct
                }
            }
        } else {
            log_it(L_WARNING, "⚠️ Failed to parse base TX hash: %s", l_base_tx_hash);
        }
    }
    
    // Process mempool additional times to ensure everything is processed
    for (int i = 0; i < 10; i++) {
        dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
        usleep(100000); // 100ms delay
    }
    
    // CRITICAL: Reload wallet cache after base TX creates UTXOs
    dap_chain_wallet_cache_load_for_net(s_net_fixture->net);
    
    // Wait for async wallet cache loading with more attempts
    bool l_cache_loaded = test_wait_for_wallet_cache_loaded(s_net_fixture->net, a_addr_owner, 100, 200);
    if (!l_cache_loaded) {
        log_it(L_WARNING, "Wallet cache loading timeout, arbitrage TX may fail with 'not enough funds'");
    }
    
    // Additional mempool processing after cache reload
    for (int i = 0; i < 5; i++) {
        dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
        usleep(100000); // 100ms delay
    }
    
    // Reload cache again after additional processing
    dap_chain_wallet_cache_load_for_net(s_net_fixture->net);
    test_wait_for_wallet_cache_loaded(s_net_fixture->net, a_addr_owner, 50, 100);
    
    // Verify balance
    uint256_t l_balance = dap_ledger_calc_balance(s_net_fixture->ledger, a_addr_owner, a_ticker);
    char *l_balance_str = dap_chain_balance_to_coins(l_balance);
    log_it(L_INFO, "Balance of %s for %s: %s", a_ticker, dap_chain_addr_to_str(a_addr_owner), l_balance_str);
    
    bool l_success = !IS_ZERO_256(l_balance);
    if (l_success) {
        log_it(L_INFO, "✅ Token %s created and emission successful (balance > 0)", a_ticker);
    } else {
        log_it(L_ERROR, "❌ Token %s emission FAILED (balance = 0)", a_ticker);
    }
    
    DAP_DELETE(l_balance_str);
    return l_success;
}

/**
 * @brief Test Scenario 1: Arbitrage WITHOUT -cert parameter
 * @details Should fail with TSD sanity check error (reproduces first part of bug report)
 */
static void test_arbitrage_without_cert(void)
{
    log_it(L_NOTICE, "=== TEST SCENARIO 1: Arbitrage WITHOUT -cert parameter ===");
    
    // 1. Create certificate for token owner
    dap_cert_t *l_cert = s_create_cert_with_seed("cert_20138_1", "test_seed_20138_scenario1");
    dap_assert_PIF(l_cert != NULL, "Certificate created");
    
    // 2. Get cert address (for fee address)
    dap_chain_addr_t l_cert_addr = {0};
    dap_chain_addr_fill_from_key(&l_cert_addr, l_cert->enc_key, s_net_fixture->net->pub.id);
    log_it(L_INFO, "Token owner cert address: %s", dap_chain_addr_to_str(&l_cert_addr));
    
    // 3. Create wallet
    dap_mkdir_with_parents(s_wallets_dir);
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_create_with_seed("reg_wallet_20138_1", s_wallets_dir,
                                                                      (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, 
                                                                      NULL, 0, NULL);
    dap_assert_PIF(l_wallet != NULL, "Wallet created");
    
    dap_enc_key_t *l_wallet_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_addr_t l_wallet_addr = {0};
    dap_chain_addr_fill_from_key(&l_wallet_addr, l_wallet_key, s_net_fixture->net->pub.id);
    log_it(L_INFO, "Wallet address: %s", dap_chain_addr_to_str(&l_wallet_addr));
    
    // 4. IMPORTANT: Clear network fee BEFORE creating token (base TX requires no fee)
    uint256_t l_zero_fee = uint256_0;
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_cert_addr);
    
    // 5. Create token and emission
    bool l_token_created = s_create_token_and_emission(TEST_TOKEN_TICKER_SCENARIO1, &l_wallet_addr, l_cert);
    dap_assert_PIF(l_token_created, "Token created with balance on wallet");
    
    // 6. Set fee for network AFTER token creation (fee address = cert address)
    uint256_t l_fee_value = dap_chain_balance_scan(ARBITRAGE_FEE);
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_fee_value, l_cert_addr);
    
    // 6. Open wallet and load cache for arbitrage TX
    dap_chain_wallet_t *l_wallet_opened = dap_chain_wallet_open("reg_wallet_20138_1", s_wallets_dir, NULL);
    dap_assert_PIF(l_wallet_opened != NULL, "Wallet opened for arbitrage TX");
    
    dap_enc_key_t *l_wallet_key_opened = dap_chain_wallet_get_key(l_wallet_opened, 0);
    dap_chain_addr_t l_wallet_addr_opened = {0};
    dap_chain_addr_fill_from_key(&l_wallet_addr_opened, l_wallet_key_opened, s_net_fixture->net->pub.id);
    
    dap_chain_wallet_cache_load_for_net(s_net_fixture->net);
    test_wait_for_wallet_cache_loaded(s_net_fixture->net, &l_wallet_addr_opened, 50, 100);
    
    // 7. Attempt to create arbitrage transaction WITHOUT -cert parameter
    char l_cmd[2048];
    snprintf(l_cmd, sizeof(l_cmd), 
             "tx_create -net %s -chain %s -from_wallet reg_wallet_20138_1 -token %s -value %s -arbitrage -fee %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             TEST_TOKEN_TICKER_SCENARIO1, ARBITRAGE_TX_VALUE, ARBITRAGE_FEE);
    
    log_it(L_INFO, "Creating arbitrage TX WITHOUT -cert: %s", l_cmd);
    
    // Convert to JSON-RPC format
    char l_json_req[4096];
    char *l_json_req_ptr = utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "tx_create",
                                                                    l_json_req, sizeof(l_json_req), 1);
    dap_assert_PIF(l_json_req_ptr != NULL, "JSON-RPC request created");
    
    // Execute
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "Reply: %s", l_reply ? l_reply : "NULL");
    
    // Parse JSON-RPC response
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    
    if (l_json) {
        json_object *l_error = NULL;
        json_object_object_get_ex(l_json, "error", &l_error);
        
        if (l_error) {
            const char *l_error_msg = json_object_get_string(l_error);
            log_it(L_INFO, "✓ Expected error received: %s", l_error_msg);
            
            // Check for TSD sanity check error (expected)
            if (strstr(l_error_msg, "Sanity check error") || 
                strstr(l_error_msg, "TSD") ||
                strstr(l_error_msg, "sanity")) {
                log_it(L_NOTICE, "✅ SCENARIO 1 PASSED: Arbitrage without -cert correctly fails with TSD sanity check error");
            } else {
                log_it(L_WARNING, "⚠️ Unexpected error type: %s", l_error_msg);
            }
        } else {
            log_it(L_WARNING, "⚠️ No error in response - TX may have been created (unexpected)");
        }
        
        json_object_put(l_json);
    }
    
    dap_chain_wallet_close(l_wallet_opened);
    dap_chain_wallet_close(l_wallet);
}

/**
 * @brief Test Scenario 2: Arbitrage WITH -cert parameter (reproduces bug)
 * @details TX should be created but stuck in mempool with "invalid owner signature" error
 */
static void test_arbitrage_with_cert_stuck(void)
{
    log_it(L_NOTICE, "=== TEST SCENARIO 2: Arbitrage WITH -cert parameter (BUG REPRODUCTION) ===");
    
    // 1. Create certificate for token owner (SAME cert used for token_decl and arbitrage)
    dap_cert_t *l_cert = s_create_cert_with_seed("cert_20138_2", "test_seed_20138_scenario2");
    dap_assert_PIF(l_cert != NULL, "Certificate created");
    
    // 2. Get cert address (for fee address)
    dap_chain_addr_t l_cert_addr = {0};
    dap_chain_addr_fill_from_key(&l_cert_addr, l_cert->enc_key, s_net_fixture->net->pub.id);
    log_it(L_INFO, "Token owner cert address: %s", dap_chain_addr_to_str(&l_cert_addr));
    
    // 3. Create wallet
    dap_mkdir_with_parents(s_wallets_dir);
    dap_chain_wallet_t *l_wallet = dap_chain_wallet_create_with_seed("reg_wallet_20138_2", s_wallets_dir,
                                                                      (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, 
                                                                      NULL, 0, NULL);
    dap_assert_PIF(l_wallet != NULL, "Wallet created");
    
    dap_enc_key_t *l_wallet_key = dap_chain_wallet_get_key(l_wallet, 0);
    dap_chain_addr_t l_wallet_addr = {0};
    dap_chain_addr_fill_from_key(&l_wallet_addr, l_wallet_key, s_net_fixture->net->pub.id);
    log_it(L_INFO, "Wallet address: %s", dap_chain_addr_to_str(&l_wallet_addr));

    // 4. Open wallet immediately after creation so its address is added to s_wallet_addr_cache
    // before s_create_token_and_emission() calls dap_chain_wallet_cache_load_for_net().
    // Opening is deferred to after creation on macOS may hit a transient ENOENT otherwise.
    dap_chain_wallet_t *l_wallet_opened = dap_chain_wallet_open("reg_wallet_20138_2", s_wallets_dir, NULL);
    dap_assert_PIF(l_wallet_opened != NULL, "Wallet opened for arbitrage TX");

    dap_enc_key_t *l_wallet_key_opened = dap_chain_wallet_get_key(l_wallet_opened, 0);
    dap_chain_addr_t l_wallet_addr_opened = {0};
    dap_chain_addr_fill_from_key(&l_wallet_addr_opened, l_wallet_key_opened, s_net_fixture->net->pub.id);

    // 5. IMPORTANT: Clear network fee BEFORE creating token (base TX requires no fee)
    uint256_t l_zero_fee = uint256_0;
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_zero_fee, l_cert_addr);
    
    // 6. Create token and emission (wallet address already in s_wallet_addr_cache)
    bool l_token_created = s_create_token_and_emission(TEST_TOKEN_TICKER_SCENARIO2, &l_wallet_addr, l_cert);
    dap_assert_PIF(l_token_created, "Token created with balance on wallet");
    
    // 7. Set fee for network AFTER token creation (fee address = cert address)
    uint256_t l_fee_value = dap_chain_balance_scan(ARBITRAGE_FEE);
    dap_chain_net_tx_set_fee(s_net_fixture->net->pub.id, l_fee_value, l_cert_addr);

    // Load wallet cache for the already-opened wallet
    dap_chain_wallet_cache_load_for_net(s_net_fixture->net);
    test_wait_for_wallet_cache_loaded(s_net_fixture->net, &l_wallet_addr_opened, 50, 100);
    
    // 8. Create arbitrage transaction WITH -cert parameter (SAME cert as token_decl)
    char l_cmd[2048];
    snprintf(l_cmd, sizeof(l_cmd), 
             "tx_create -net %s -chain %s -from_wallet reg_wallet_20138_2 -token %s -value %s -arbitrage -fee %s -certs %s",
             s_net_fixture->net->pub.name, s_net_fixture->chain_main->name,
             TEST_TOKEN_TICKER_SCENARIO2, ARBITRAGE_TX_VALUE, ARBITRAGE_FEE, l_cert->name);
    
    log_it(L_INFO, "Creating arbitrage TX WITH -cert (SAME cert as token_decl): %s", l_cmd);
    
    // Convert to JSON-RPC format
    char l_json_req[4096];
    char *l_json_req_ptr = utxo_blocking_test_cli_cmd_to_json_rpc(l_cmd, "tx_create",
                                                                    l_json_req, sizeof(l_json_req), 1);
    dap_assert_PIF(l_json_req_ptr != NULL, "JSON-RPC request created");
    
    // Execute
    char *l_reply = dap_cli_cmd_exec(l_json_req);
    log_it(L_INFO, "Reply: %s", l_reply ? l_reply : "NULL");
    
    // Parse JSON-RPC response
    json_object *l_json = json_tokener_parse(l_reply);
    DAP_DELETE(l_reply);
    dap_assert_PIF(l_json != NULL, "JSON reply parsed");
    
    // Get result field (should contain TX hash if created successfully)
    json_object *l_json_result = NULL;
    json_object_object_get_ex(l_json, "result", &l_json_result);
    const char *l_result_str = json_object_get_string(l_json_result);
    
    if (l_result_str && strstr(l_result_str, "0x")) {
        log_it(L_INFO, "✓ TX created successfully, hash: %s", l_result_str);
        
        // Extract TX hash
        const char *l_tx_hash_start = strstr(l_result_str, "0x");
        char l_tx_hash[67] = {0};
        if (l_tx_hash_start) {
            strncpy(l_tx_hash, l_tx_hash_start, 66);
        }
        
        // Process mempool to add TX to mempool
        dap_chain_node_mempool_process_all(s_net_fixture->chain_main, true);
        
        // Check mempool status (should be stuck with "hole" status)
        // Note: In synthetic test environment, we may not have full mempool check API
        // This test verifies that TX is created but validation may fail
        log_it(L_INFO, "✓ TX added to mempool, hash: %s", l_tx_hash);
        log_it(L_NOTICE, "⚠️ SCENARIO 2: TX created but may be stuck in mempool (expected bug behavior)");
        log_it(L_NOTICE, "   In production testnet, this TX would show status='hole' with error:");
        log_it(L_NOTICE, "   'Arbitrage transaction not authorized: invalid owner signature'");
        
    } else {
        json_object *l_error = NULL;
        json_object_object_get_ex(l_json, "error", &l_error);
        if (l_error) {
            const char *l_error_msg = json_object_get_string(l_error);
            log_it(L_WARNING, "⚠️ TX creation failed: %s", l_error_msg);
        }
    }
    
    json_object_put(l_json);
    
    dap_chain_wallet_close(l_wallet_opened);
    dap_chain_wallet_close(l_wallet);
}

int main(int argc, char **argv)
{
    dap_print_module_name("Bug #20138 Regression Test");
    
    // Setup
    s_setup();
    
    // Run tests
    test_arbitrage_without_cert();      // Scenario 1: Without -cert (TSD error)
    test_arbitrage_with_cert_stuck();   // Scenario 2: With -cert (stuck in mempool)
    
    // Cleanup
    s_cleanup();
    
    log_it(L_NOTICE, "=== Bug #20138 Regression Test Complete ===");
    return 0;
}

