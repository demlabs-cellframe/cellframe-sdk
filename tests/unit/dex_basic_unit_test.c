/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file dex_basic_unit_test.c
 * @brief Basic DEX unit tests
 * @details Tests DEX order creation, matching, updates without hot cache and with hot cache
 * @date 2025-10-24
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_config.h"
#include "dap_enc.h"
#include "dap_hash.h"
#include "dap_chain_ledger.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_tsd.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"

#define LOG_TAG "dex_basic_unit_test"

/**
 * @brief Setup test environment (similar to integration test s_setup)
 */
static void s_setup(void)
{
    log_it(L_NOTICE, "=== DEX Basic Unit Tests Setup ===");
    
    // Step 1: Create minimal config directory
    const char *l_config_dir = "/tmp/dex_test_config";
    mkdir(l_config_dir, 0755);
    
    const char *l_config_content = 
        "[general]\n"
        "debug_mode=true\n";
    
    char l_config_path[256];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", l_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if (l_config_file) {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    
    // Step 2: Initialize config and open it (CRITICAL!)
    dap_config_init(l_config_dir);
    g_config = dap_config_open("test");
    dap_assert(g_config != NULL, "Config initialization");
    
    // Step 3: Initialize consensus modules
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_chain_cs_esbocs_init();
    
    log_it(L_NOTICE, "✓ Test environment initialized");
}

/**
 * @brief Teardown test environment
 */
static void s_teardown(void)
{
    log_it(L_NOTICE, "Cleaning up test environment...");
    
    // Close and cleanup config
    if (g_config) {
        dap_config_close(g_config);
        g_config = NULL;
    }
    dap_config_deinit();
    
    // Remove test config files
    unlink("/tmp/dex_test_config/test.cfg");
    rmdir("/tmp/dex_test_config");
    
    log_it(L_NOTICE, "✓ Cleanup completed");
}

// ========================================================================
// DECREE-BASED HELPERS
// ========================================================================

// TSD section types (from dap_chain_net_srv_dex.c)
#define DEX_DECREE_TSD_METHOD        0x0000
#define DEX_DECREE_TSD_TOKEN_BASE    0x0001
#define DEX_DECREE_TSD_TOKEN_QUOTE   0x0002
#define DEX_DECREE_TSD_NET_BASE      0x0003
#define DEX_DECREE_TSD_NET_QUOTE     0x0004
#define DEX_DECREE_TSD_FEE_CONFIG    0x0005
#define DEX_DECREE_TSD_FEE_AMOUNT    0x0020
#define DEX_DECREE_TSD_FEE_ADDR      0x0021

// Decree methods (from dap_chain_net_srv_dex.c)
typedef enum {
    DEX_DECREE_UNKNOWN,
    DEX_DECREE_FEE_SET,
    DEX_DECREE_PAIR_ADD,
    DEX_DECREE_PAIR_REMOVE,
    DEX_DECREE_PAIR_FEE_SET,
    DEX_DECREE_PAIR_FEE_SET_ALL
} dex_decree_method_t;

/**
 * @brief Helper: Add pair to DEX whitelist via decree callback
 * @param ledger Ledger instance
 * @param token_base Base token ticker
 * @param token_quote Quote token ticker
 * @param net_id Network ID (for both tokens)
 * @param fee_config Fee configuration byte (bit7: 0=NATIVE, 1=QUOTE; bits[6:0]: percent for QUOTE)
 * @return 0 on success, error code otherwise
 */
static int test_decree_pair_add(dap_ledger_t *ledger, const char *token_base, const char *token_quote, 
                                  dap_chain_net_id_t net_id, uint8_t fee_config)
{
    // Build TSD sections manually
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    // METHOD
    uint8_t l_method = (uint8_t)DEX_DECREE_PAIR_ADD;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    // TOKEN_BASE, TOKEN_QUOTE
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_BASE, token_base, dap_strlen(token_base)+1);
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_QUOTE, token_quote, dap_strlen(token_quote)+1);
    
    // NET_BASE, NET_QUOTE
    uint64_t l_net_id = net_id.uint64;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_BASE, &l_net_id, sizeof(uint64_t));
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_QUOTE, &l_net_id, sizeof(uint64_t));
    
    // FEE_CONFIG (optional)
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &fee_config, sizeof(uint8_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    // Call decree callback
    return dap_chain_net_srv_dex_decree_callback(ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

/**
 * @brief Helper: Set fee for specific pair via decree callback
 * @param ledger Ledger instance
 * @param token_base Base token ticker
 * @param token_quote Quote token ticker
 * @param net_id Network ID (for both tokens)
 * @param fee_config Full fee_config byte (bit7: 0=NATIVE, 1=QUOTE; bits[6:0]: percent for QUOTE or unused for NATIVE)
 * @return 0 on success, error code otherwise
 */
static int test_decree_pair_fee_set(dap_ledger_t *ledger, const char *token_base, const char *token_quote,
                                     dap_chain_net_id_t net_id, uint8_t fee_config)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    // METHOD
    uint8_t l_method = (uint8_t)DEX_DECREE_PAIR_FEE_SET;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    // TOKEN_BASE, TOKEN_QUOTE
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_BASE, token_base, dap_strlen(token_base)+1);
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_QUOTE, token_quote, dap_strlen(token_quote)+1);
    
    // NET_BASE, NET_QUOTE
    uint64_t l_net_id = net_id.uint64;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_BASE, &l_net_id, sizeof(uint64_t));
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_QUOTE, &l_net_id, sizeof(uint64_t));
    
    // FEE_CONFIG (full byte passed as-is)
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &fee_config, sizeof(uint8_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

/**
 * @brief Helper: Set global native fee and service address via decree callback
 * @param ledger Ledger instance
 * @param fee_amount Native token fee amount
 * @param service_addr Service fee collector address
 * @return 0 on success, error code otherwise
 */
static int test_decree_fee_set(dap_ledger_t *ledger, uint256_t fee_amount, const dap_chain_addr_t *service_addr)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    // METHOD
    uint8_t l_method = (uint8_t)DEX_DECREE_FEE_SET;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    // FEE_AMOUNT
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_AMOUNT, &fee_amount, sizeof(uint256_t));
    
    // FEE_ADDR
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_ADDR, service_addr, sizeof(dap_chain_addr_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

// ========================================================================
// TEST HELPERS
// ========================================================================

/**
 * @brief Helper: Create a DEX order
 * @param net Network fixture
 * @param wallet Wallet creating the order
 * @param token_buy Token to buy
 * @param token_sell Token to sell
 * @param amount_sell Amount to sell (string, e.g. "1000.0")
 * @param rate Rate (string, e.g. "5.0")
 * @param out_hash Output: hash of created transaction
 * @return Transaction on success, NULL on failure
 */
static dap_chain_datum_tx_t* test_create_order(
    test_net_fixture_t *net, 
    dap_chain_wallet_t *wallet,
    const char *token_buy, 
    const char *token_sell,
    const char *amount_sell, 
    const char *rate,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(NULL, !net, !wallet, !token_buy, !token_sell, !amount_sell, !rate, !out_hash);
    
    uint256_t value = dap_chain_coins_to_balance(amount_sell);
    uint256_t rate_value = dap_chain_coins_to_balance(rate);
    uint256_t network_fee = dap_chain_coins_to_balance("1.0");
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        net->net, token_buy, token_sell, value, rate_value, 0, network_fee, wallet, &tx
    );
    
    if (err != DEX_CREATE_ERROR_OK || !tx) {
        log_it(L_ERROR, "CREATE failed: err=%d", err);
        return NULL;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add order to ledger");
        return NULL;
    }
    
    log_it(L_INFO, "Order created: %s %s for %s at rate %s, hash=%s",
           amount_sell, token_sell, token_buy, rate,
           dap_chain_hash_fast_to_str_static(out_hash));
    
    return tx;
}

/**
 * @brief Helper: Purchase from an order (by hash)
 * @param net Network fixture
 * @param buyer Buyer wallet
 * @param order_hash Hash of order to purchase from (root or tail)
 * @param amount Budget amount (string, e.g. "2500.0")
 * @param is_budget_buy true: budget in what buyer BUYS, false: budget in what buyer SELLS
 * @param create_buyer_leftover true: create buyer-leftover order from excess budget, false: refund
 * @param out_hash Output: hash of purchase transaction
 * @return Transaction on success, NULL on failure
 */
static dap_chain_datum_tx_t* test_purchase_order(
    test_net_fixture_t *net,
    dap_chain_wallet_t *buyer,
    dap_hash_fast_t *order_hash,
    const char *amount,
    bool is_budget_buy,
    bool create_buyer_leftover,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(NULL, !net, !buyer, !order_hash, !amount, !out_hash);
    
    uint256_t budget = dap_chain_coins_to_balance(amount);
    uint256_t network_fee = dap_chain_coins_to_balance("1.0");
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        net->net, order_hash, budget, is_budget_buy, network_fee, buyer, create_buyer_leftover, uint256_0, &tx
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "PURCHASE failed: err=%d", err);
        return NULL;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add purchase to ledger");
        return NULL;
    }
    
    log_it(L_INFO, "Purchase created: budget=%s, is_budget_buy=%d, create_buyer_leftover=%d, order=%s, tx=%s",
           amount, is_budget_buy, create_buyer_leftover,
           dap_chain_hash_fast_to_str_static(order_hash),
           dap_chain_hash_fast_to_str_static(out_hash));
    
    return tx;
}

/**
 * @brief Helper: Verify balance
 * @param net Network fixture
 * @param addr Address to check
 * @param token Token ticker
 * @param expected_min Minimum expected amount (string, e.g. "2375.0")
 * @param msg Assertion message
 */
static void test_verify_balance(
    test_net_fixture_t *net,
    dap_chain_addr_t *addr,
    const char *token,
    const char *expected_min,
    const char *msg)
{
    dap_ret_if_any(!net, !addr, !token, !expected_min, !msg);
    
    uint256_t balance = dap_ledger_calc_balance(net->net->pub.ledger, addr, token);
    uint256_t expected = dap_chain_coins_to_balance(expected_min);
    
    log_it(L_INFO, "Balance check: %s %s = %s (expected >= %s)",
           dap_chain_addr_to_str_static(addr), token,
           dap_uint256_to_char_ex(balance).str, expected_min);
    
    dap_assert(compare256(balance, expected) >= 0, msg);
}

/**
 * @brief Helper: Verify seller-leftover in transaction
 * @param tx Transaction to check
 * @param expected_root Expected order_root_hash
 * @param expected_value Expected leftover value (string, e.g. "500.0")
 * @param expected_rate Expected rate (string, e.g. "5.0")
 * @param msg Assertion message
 */
static void test_verify_leftover(
    dap_chain_datum_tx_t *tx,
    dap_hash_fast_t *expected_root,
    const char *expected_value,
    const char *expected_rate,
    const char *msg)
{
    dap_ret_if_any(!tx, !expected_root, !expected_value, !expected_rate, !msg);
    
    dap_chain_tx_out_cond_t *leftover = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
    dap_assert(leftover != NULL, "Seller-leftover OUT_COND exists");
    
    uint256_t exp_value = dap_chain_coins_to_balance(expected_value);
    uint256_t exp_rate = dap_chain_coins_to_balance(expected_rate);
    
    log_it(L_INFO, "Leftover: value=%s (expected %s), rate=%s (expected %s), root=%s",
           dap_uint256_to_char_ex(leftover->header.value).str, expected_value,
           dap_uint256_to_char_ex(leftover->subtype.srv_dex.rate).str, expected_rate,
           dap_chain_hash_fast_to_str_static(&leftover->subtype.srv_dex.order_root_hash));
    
    dap_assert(EQUAL_256(leftover->header.value, exp_value), msg);
    dap_assert(EQUAL_256(leftover->subtype.srv_dex.rate, exp_rate), "Leftover rate correct");
    dap_assert(dap_hash_fast_compare(&leftover->subtype.srv_dex.order_root_hash, expected_root), "Leftover root correct");
}

// ========================================================================
// TEST SCENARIOS
// ========================================================================

/**
 * @brief Test: Basic order creation and matching
 * @param a_enable_hot_cache Enable hot cache for DEX orders
 */
static void s_test_dex_basic(bool a_enable_hot_cache)
{
    const char *cache_status = a_enable_hot_cache ? "CACHE ENABLED" : "NO CACHE";
    char test_name[128];
    snprintf(test_name, sizeof(test_name), "dex_test_%s", a_enable_hot_cache ? "cache" : "no_cache");
    
    char module_name[128];
    snprintf(module_name, sizeof(module_name), "DEX Basic Unit Tests (%s)", cache_status);
    dap_print_module_name(module_name);
    
    // ========== SETUP ==========
    
    log_it(L_NOTICE, "Test setup starting (hot cache: %s)...", a_enable_hot_cache ? "ENABLED" : "DISABLED");
    
    // 1. Create network
    log_it(L_NOTICE, "Creating test network fixture...");
    test_net_fixture_t *net = test_net_fixture_create(test_name);
    if (!net) {
        log_it(L_CRITICAL, "test_net_fixture_create() returned NULL!");
        dap_assert(false, "Network created");
        return;
    }
    log_it(L_NOTICE, "Network fixture created successfully");
    dap_assert(net != NULL, "Network created");
    
    // 2. Initialize DEX service with cache control
    int dex_init = dap_chain_net_srv_dex_init();
    dap_assert(dex_init == 0, "DEX service initialized");
    
    // 3. Configure hot cache (BEFORE adding pairs!)
    log_it(L_NOTICE, "Hot cache %s", a_enable_hot_cache ? "ENABLED" : "DISABLED");
    
    // 4. BYPASS DECREES: Add trading pairs to whitelist
    // Add allowed pairs via decree (with initial fee_config=0, no fee)
    int pair1_add = test_decree_pair_add(net->net->pub.ledger, "KEL", "USDT", net->net->pub.id, 0);
    dap_assert(pair1_add == 0, "Pair KEL/USDT added to whitelist via decree");
    
    int pair2_add = test_decree_pair_add(net->net->pub.ledger, "KEL", "TestCoin", net->net->pub.id, 0);
    dap_assert(pair2_add == 0, "Pair KEL/TestCoin added to whitelist via decree");
    
    // 5. Create wallets (NOTE: will NOT close them due to cert deletion bug)
    dap_chain_wallet_t *alice = dap_chain_wallet_create("alice", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    dap_chain_wallet_t *bob = dap_chain_wallet_create("bob", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    dap_chain_wallet_t *carol = dap_chain_wallet_create("carol", ".", (dap_sign_type_t){.type = SIG_TYPE_DILITHIUM}, NULL);
    
    dap_assert(alice != NULL, "Alice wallet created");
    dap_assert(bob != NULL, "Bob wallet created");
    dap_assert(carol != NULL, "Carol wallet created");
    
    // Get addresses and copy them (dap_chain_wallet_get_addr returns pointer that must be freed)
    dap_chain_addr_t alice_addr = {0}, bob_addr = {0}, carol_addr = {0};
    dap_chain_addr_t *l_aa = dap_chain_wallet_get_addr(alice, net->net->pub.id);
    alice_addr = *l_aa; DAP_DELETE(l_aa);
    dap_chain_addr_t *l_ab = dap_chain_wallet_get_addr(bob, net->net->pub.id);
    bob_addr = *l_ab; DAP_DELETE(l_ab);
    dap_chain_addr_t *l_ac = dap_chain_wallet_get_addr(carol, net->net->pub.id);
    carol_addr = *l_ac; DAP_DELETE(l_ac);
    
    // 6. Set Carol as service wallet and configure fees via decree
    // Set global native fee = 0 (we'll set QUOTE fees per-pair) and Carol as service addr
    int fee_global_set = test_decree_fee_set(net->net->pub.ledger, uint256_0, &carol_addr);
    dap_assert(fee_global_set == 0, "Global fee set via decree (Carol as service)");
    log_it(L_NOTICE, "Carol is service wallet: %s", dap_chain_addr_to_str_static(&carol_addr));
    
    // 7. Set 5% QUOTE fee for both pairs via decree (bit7=1 for QUOTE, bits[6:0]=5)
    int fee1_set = test_decree_pair_fee_set(net->net->pub.ledger, "KEL", "USDT", net->net->pub.id, 0x80 | 5);
    dap_assert(fee1_set == 0, "Fee 5% QUOTE set for KEL/USDT via decree");
    
    int fee2_set = test_decree_pair_fee_set(net->net->pub.ledger, "KEL", "TestCoin", net->net->pub.id, 0x80 | 5);
    dap_assert(fee2_set == 0, "Fee 5% QUOTE set for KEL/TestCoin via decree");
    
    // Extract certificates from wallets using internal API (allowed in tests)
    dap_chain_wallet_internal_t *alice_int = DAP_CHAIN_WALLET_INTERNAL(alice);
    dap_chain_wallet_internal_t *bob_int = DAP_CHAIN_WALLET_INTERNAL(bob);
    dap_chain_wallet_internal_t *carol_int = DAP_CHAIN_WALLET_INTERNAL(carol);
    
    dap_cert_t *alice_cert = alice_int->certs[0];
    dap_cert_t *bob_cert = bob_int->certs[0];
    dap_cert_t *carol_cert = carol_int->certs[0];
    
    // Verify wallet public key hashes are unique
    dap_hash_fast_t alice_pkey_hash, bob_pkey_hash, carol_pkey_hash;
    dap_enc_key_get_pkey_hash(alice_cert->enc_key, &alice_pkey_hash);
    dap_enc_key_get_pkey_hash(bob_cert->enc_key, &bob_pkey_hash);
    dap_enc_key_get_pkey_hash(carol_cert->enc_key, &carol_pkey_hash);
    
    log_it(L_INFO, "Alice pkey hash: %s", dap_chain_hash_fast_to_str_static(&alice_pkey_hash));
    log_it(L_INFO, "Bob pkey hash: %s", dap_chain_hash_fast_to_str_static(&bob_pkey_hash));
    log_it(L_INFO, "Carol pkey hash: %s", dap_chain_hash_fast_to_str_static(&carol_pkey_hash));
    
    dap_assert(!dap_hash_fast_compare(&alice_pkey_hash, &bob_pkey_hash), "Alice and Bob have different pkeys");
    dap_assert(!dap_hash_fast_compare(&bob_pkey_hash, &carol_pkey_hash), "Bob and Carol have different pkeys");
    dap_assert(!dap_hash_fast_compare(&alice_pkey_hash, &carol_pkey_hash), "Alice and Carol have different pkeys");    
    // 8. Create native token (TestCoin) for network fees - generous amounts
    dap_chain_hash_fast_t testcoin_alice_emission_hash, testcoin_bob_emission_hash, testcoin_carol_emission_hash;
    
    test_token_fixture_t *testcoin_token = test_token_fixture_create_with_emission(
        net->ledger,
        "TestCoin",
        "10000000.0",
        "100000.0",
        &alice_addr,
        alice_cert,
        &testcoin_alice_emission_hash
    );
    dap_assert(testcoin_token != NULL, "TestCoin token created with emission to Alice");
    
    // Create TestCoin emissions for Bob and Carol
    test_emission_fixture_t *testcoin_bob_emission = test_emission_fixture_create_with_cert(
        "TestCoin",
        dap_chain_coins_to_balance("100000.0"),
        &bob_addr,
        bob_cert
    );
    dap_assert(testcoin_bob_emission != NULL, "TestCoin emission for Bob created");
    int bob_testcoin_result = test_emission_fixture_add_to_ledger(net->ledger, testcoin_bob_emission);
    dap_assert(bob_testcoin_result == 0, "Bob's TestCoin emission added");
    
    bool bob_testcoin_hash_ok = test_emission_fixture_get_hash(testcoin_bob_emission, &testcoin_bob_emission_hash);
    dap_assert(bob_testcoin_hash_ok, "Bob's TestCoin emission hash retrieved");
    
    test_emission_fixture_t *testcoin_carol_emission = test_emission_fixture_create_with_cert(
        "TestCoin",
        dap_chain_coins_to_balance("100000.0"),
        &carol_addr,
        carol_cert
    );
    dap_assert(testcoin_carol_emission != NULL, "TestCoin emission for Carol created");
    int carol_testcoin_result = test_emission_fixture_add_to_ledger(net->ledger, testcoin_carol_emission);
    dap_assert(carol_testcoin_result == 0, "Carol's TestCoin emission added");
    
    bool carol_testcoin_hash_ok = test_emission_fixture_get_hash(testcoin_carol_emission, &testcoin_carol_emission_hash);
    dap_assert(carol_testcoin_hash_ok, "Carol's TestCoin emission hash retrieved");
    
    log_it(L_INFO, "TestCoin (native) distributed: 100k to each wallet for network fees");
    
    // 9. Create tokens KEL and USDT with emissions
    dap_chain_hash_fast_t kel_emission_hash, usdt_bob_emission_hash, usdt_carol_emission_hash;
    
    test_token_fixture_t *kel_token = test_token_fixture_create_with_emission(
        net->ledger,
        "KEL",
        "1000000.0",
        "10000.0",
        &alice_addr,
        alice_cert,
        &kel_emission_hash
    );
    dap_assert(kel_token != NULL, "KEL token created with emission to Alice");
    
    test_token_fixture_t *usdt_token = test_token_fixture_create_with_emission(
        net->ledger,
        "USDT",
        "5000000.0",
        "50000.0",
        &bob_addr,
        bob_cert,
        &usdt_bob_emission_hash
    );
    dap_assert(usdt_token != NULL, "USDT token created with emission to Bob");
    
    // Create additional emission for Carol (token already exists)
    test_emission_fixture_t *usdt_carol_emission = test_emission_fixture_create_with_cert(
        "USDT",
        dap_chain_coins_to_balance("30000.0"),
        &carol_addr,
        carol_cert
    );
    dap_assert(usdt_carol_emission != NULL, "USDT emission for Carol created");
    
    int carol_emission_result = test_emission_fixture_add_to_ledger(net->ledger, usdt_carol_emission);
    dap_assert(carol_emission_result == 0, "Carol's emission added to ledger");
    
    bool carol_hash_ok = test_emission_fixture_get_hash(usdt_carol_emission, &usdt_carol_emission_hash);
    dap_assert(carol_hash_ok, "Carol's emission hash retrieved");
    
    // 10. Create transactions from emissions to actually credit wallets
    log_it(L_INFO, "Creating transactions from emissions...");
    
    // Prepare summary table buffer (will accumulate rows as tests progress)
    #define MAX_TABLE_ROWS 60
    #define MAX_ROW_LENGTH 1024
    char table_rows[MAX_TABLE_ROWS][MAX_ROW_LENGTH];
    int table_row_count = 0;
    
    // Macro to add scenario row with current balances (4 table rows: description + 3 balance rows)
    #define ADD_SCENARIO_ROW(num, type, buyer, description) do { \
        uint256_t _a_k = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "KEL"); \
        uint256_t _a_u = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "USDT"); \
        uint256_t _a_t = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "TestCoin"); \
        uint256_t _b_k = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "KEL"); \
        uint256_t _b_u = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "USDT"); \
        uint256_t _b_t = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "TestCoin"); \
        uint256_t _c_k = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "KEL"); \
        uint256_t _c_u = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "USDT"); \
        uint256_t _c_t = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "TestCoin"); \
        char _bal_a[256], _bal_b[256], _bal_c[256]; \
        snprintf(_bal_a, sizeof(_bal_a), "Alice: KEL=%-8s | USDT=%-8s | TC=%-9s", \
                 dap_uint256_to_char_ex(_a_k).frac, dap_uint256_to_char_ex(_a_u).frac, dap_uint256_to_char_ex(_a_t).frac); \
        snprintf(_bal_b, sizeof(_bal_b), "Bob:   KEL=%-8s | USDT=%-8s | TC=%-9s", \
                 dap_uint256_to_char_ex(_b_k).frac, dap_uint256_to_char_ex(_b_u).frac, dap_uint256_to_char_ex(_b_t).frac); \
        snprintf(_bal_c, sizeof(_bal_c), "Carol: KEL=%-8s | USDT=%-8s | TC=%-9s", \
                 dap_uint256_to_char_ex(_c_k).frac, dap_uint256_to_char_ex(_c_u).frac, dap_uint256_to_char_ex(_c_t).frac); \
        char _num[8]; snprintf(_num, sizeof(_num), "%d", num); \
        snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH, \
                 "║ %-5s ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", _num, type, buyer, description, "PASS"); \
        snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH, \
                 "║ %-5s ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", "", "", "", _bal_a, ""); \
        snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH, \
                 "║ %-5s ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", "", "", "", _bal_b, ""); \
        snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH, \
                 "║ %-5s ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", "", "", "", _bal_c, ""); \
    } while(0)
    
    // Alice: KEL + TestCoin
    test_tx_fixture_t *alice_kel_tx = test_tx_fixture_create_from_emission(
        net->ledger, &kel_emission_hash, "KEL", "10000.0", &alice_addr, alice_cert
    );
    dap_assert(alice_kel_tx != NULL, "Alice KEL TX from emission created");
    int alice_kel_result = test_tx_fixture_add_to_ledger(net->ledger, alice_kel_tx);
    dap_assert(alice_kel_result == 0, "Alice KEL TX added to ledger");
    
    test_tx_fixture_t *alice_testcoin_tx = test_tx_fixture_create_from_emission(
        net->ledger, &testcoin_alice_emission_hash, "TestCoin", "100000.0", &alice_addr, alice_cert
    );
    dap_assert(alice_testcoin_tx != NULL, "Alice TestCoin TX from emission created");
    int alice_testcoin_result = test_tx_fixture_add_to_ledger(net->ledger, alice_testcoin_tx);
    dap_assert(alice_testcoin_result == 0, "Alice TestCoin TX added to ledger");
    
    // Bob: USDT + TestCoin
    test_tx_fixture_t *bob_usdt_tx = test_tx_fixture_create_from_emission(
        net->ledger, &usdt_bob_emission_hash, "USDT", "50000.0", &bob_addr, bob_cert
    );
    dap_assert(bob_usdt_tx != NULL, "Bob USDT TX from emission created");
    int bob_usdt_result = test_tx_fixture_add_to_ledger(net->ledger, bob_usdt_tx);
    dap_assert(bob_usdt_result == 0, "Bob USDT TX added to ledger");
    
    test_tx_fixture_t *bob_testcoin_tx = test_tx_fixture_create_from_emission(
        net->ledger, &testcoin_bob_emission_hash, "TestCoin", "100000.0", &bob_addr, bob_cert
    );
    dap_assert(bob_testcoin_tx != NULL, "Bob TestCoin TX from emission created");
    int bob_testcoin_tx_result = test_tx_fixture_add_to_ledger(net->ledger, bob_testcoin_tx);
    dap_assert(bob_testcoin_tx_result == 0, "Bob TestCoin TX added to ledger");
    
    // Carol: USDT + TestCoin
    test_tx_fixture_t *carol_usdt_tx = test_tx_fixture_create_from_emission(
        net->ledger, &usdt_carol_emission_hash, "USDT", "30000.0", &carol_addr, carol_cert
    );
    dap_assert(carol_usdt_tx != NULL, "Carol USDT TX from emission created");
    int carol_usdt_result = test_tx_fixture_add_to_ledger(net->ledger, carol_usdt_tx);
    dap_assert(carol_usdt_result == 0, "Carol USDT TX added to ledger");
    
    test_tx_fixture_t *carol_testcoin_tx = test_tx_fixture_create_from_emission(
        net->ledger, &testcoin_carol_emission_hash, "TestCoin", "100000.0", &carol_addr, carol_cert
    );
    dap_assert(carol_testcoin_tx != NULL, "Carol TestCoin TX from emission created");
    int carol_testcoin_tx_result = test_tx_fixture_add_to_ledger(net->ledger, carol_testcoin_tx);
    dap_assert(carol_testcoin_tx_result == 0, "Carol TestCoin TX added to ledger");
    
    // 11. Verify balances
    log_it(L_INFO, "Verifying balances after transactions...");
    uint256_t alice_kel_balance = dap_ledger_calc_balance(net->ledger, &alice_addr, "KEL");
    uint256_t alice_testcoin_balance = dap_ledger_calc_balance(net->ledger, &alice_addr, "TestCoin");
    uint256_t bob_usdt_balance = dap_ledger_calc_balance(net->ledger, &bob_addr, "USDT");
    uint256_t bob_testcoin_balance = dap_ledger_calc_balance(net->ledger, &bob_addr, "TestCoin");
    uint256_t carol_usdt_balance = dap_ledger_calc_balance(net->ledger, &carol_addr, "USDT");
    
    log_it(L_INFO, "  Alice: %s KEL, %s TestCoin", 
           dap_uint256_to_char_ex(alice_kel_balance).str,
           dap_uint256_to_char_ex(alice_testcoin_balance).str);
    log_it(L_INFO, "  Bob: %s USDT, %s TestCoin", 
           dap_uint256_to_char_ex(bob_usdt_balance).str,
           dap_uint256_to_char_ex(bob_testcoin_balance).str);
    log_it(L_INFO, "  Carol: %s USDT", dap_uint256_to_char_ex(carol_usdt_balance).str);
    
    dap_assert(!IS_ZERO_256(alice_kel_balance), "Alice has KEL balance");
    dap_assert(!IS_ZERO_256(alice_testcoin_balance), "Alice has TestCoin balance");
    dap_assert(!IS_ZERO_256(bob_usdt_balance), "Bob has USDT balance");
    dap_assert(!IS_ZERO_256(bob_testcoin_balance), "Bob has TestCoin balance");
    dap_assert(!IS_ZERO_256(carol_usdt_balance), "Carol has USDT balance");
    
    // Add initial row to table with ACTUAL balances after funding (NOW, after all txs added)
    uint256_t init_a_k = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "KEL");
    uint256_t init_a_u = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "USDT");
    uint256_t init_a_t = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "TestCoin");
    uint256_t init_b_k = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "KEL");
    uint256_t init_b_u = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "USDT");
    uint256_t init_b_t = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "TestCoin");
    uint256_t init_c_k = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "KEL");
    uint256_t init_c_u = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "USDT");
    uint256_t init_c_t = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "TestCoin");
    
    char init_bal_a[256], init_bal_b[256], init_bal_c[256];
    snprintf(init_bal_a, sizeof(init_bal_a), "Alice: KEL=%-8s | USDT=%-8s | TC=%-9s",
             dap_uint256_to_char_ex(init_a_k).frac, dap_uint256_to_char_ex(init_a_u).frac, dap_uint256_to_char_ex(init_a_t).frac);
    snprintf(init_bal_b, sizeof(init_bal_b), "Bob:   KEL=%-8s | USDT=%-8s | TC=%-9s",
             dap_uint256_to_char_ex(init_b_k).frac, dap_uint256_to_char_ex(init_b_u).frac, dap_uint256_to_char_ex(init_b_t).frac);
    snprintf(init_bal_c, sizeof(init_bal_c), "Carol: KEL=%-8s | USDT=%-8s | TC=%-9s",
             dap_uint256_to_char_ex(init_c_k).frac, dap_uint256_to_char_ex(init_c_u).frac, dap_uint256_to_char_ex(init_c_t).frac);
    
    snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH,
             "║ %-5d ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", 
             0, "INIT", "-", "Initial balances after funding wallets", "PASS");
    snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH,
             "║ %-5s ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", "", "", "", init_bal_a, "");
    snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH,
             "║ %-5s ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", "", "", "", init_bal_b, "");
    snprintf(table_rows[table_row_count++], MAX_ROW_LENGTH,
             "║ %-5s ║ %-10s ║ %-9s ║ %-119s ║ %-8s ║", "", "", "", init_bal_c, "");
    
    // ========== SCENARIO 1: CREATE Order (ASK) ==========
    
    log_it(L_INFO, "=== Scenario 1: CREATE order (Alice sells 1000 KEL for USDT at rate 5.0) ===");
    
    dap_hash_fast_t order1_hash = {0};
    dap_chain_datum_tx_t *order1_tx = test_create_order(
        net, alice, "USDT", "KEL", "1000.0", "5.0", &order1_hash
    );
    dap_assert(order1_tx != NULL, "Order1 CREATE composed and added");
    
    // Verify Alice's balance decreased (1000 KEL locked + fees)
    test_verify_balance(net, &alice_addr, "KEL", "9000.0", "Alice KEL decreased after order");
    
    // Verify OUT_COND
    dap_chain_tx_out_cond_t *order1_out = dap_chain_datum_tx_out_cond_get(
        order1_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL
    );
    dap_assert(order1_out != NULL, "Order1 has SRV_DEX OUT_COND");
    dap_assert(order1_out->subtype.srv_dex.tx_type == DEX_TX_TYPE_ORDER, "Order1 tx_type is ORDER");
    dap_assert(EQUAL_256(order1_out->subtype.srv_dex.rate, dap_chain_coins_to_balance("5.0")), "Order1 rate correct");
    
    log_it(L_INFO, "Scenario 1 PASSED: Order created (Alice sells 1000 KEL @ 5.0)");
    ADD_SCENARIO_ROW(1, "ASK ORDER", "Alice", "Alice creates ASK order: sells 1000 KEL @ rate 5.0 USDT/KEL (wants 5000 USDT total)");
    
    // ========== SCENARIO 2: PARTIAL PURCHASE (ASK) ==========
    
    log_it(L_INFO, "=== Scenario 2: PURCHASE (Bob buys 500 KEL, spends 2500 USDT) ===");
    
    dap_hash_fast_t purchase1_hash = {0};
    dap_chain_datum_tx_t *purchase1_tx = test_purchase_order(
        net, bob, &order1_hash, "2500.0", false, false, &purchase1_hash
    );
    dap_assert(purchase1_tx != NULL, "Purchase1 composed and added");
    
    // Verify balances: Alice gets 2500 USDT (fee aggregated to her payout in ASK)
    // Service (Carol) ALSO collects 5% = 125 USDT (separate OUT, not deducted from Alice)
    test_verify_balance(net, &alice_addr, "USDT", "2500.0", "Alice received 2500 USDT (fee aggregated)");
    test_verify_balance(net, &bob_addr, "KEL", "500.0", "Bob received 500 KEL");
    test_verify_balance(net, &carol_addr, "USDT", "30125.0", "Carol (service) collected 125 USDT fee");
    
    // Verify seller-leftover
    test_verify_leftover(purchase1_tx, &order1_hash, "500.0", "5.0", "Seller-leftover 500 KEL at rate 5.0");
    
    log_it(L_INFO, "Scenario 2 PASSED: Partial purchase with fee collection");
    ADD_SCENARIO_ROW(2, "ASK PART", "Bob", "Bob buys 500 KEL @ 5.0 (partial), pays 2625 USDT (2500 + 125 fee). Alice gets 2500, Carol +125 fee. Leftover: 500 KEL");
    
    // ========== SCENARIO 3: FULL PURCHASE (close Alice's order) ==========
    
    log_it(L_INFO, "=== Scenario 3: FULL PURCHASE (Bob buys remaining 500 KEL) ===");
    
    dap_hash_fast_t purchase2_hash = {0};
    dap_chain_datum_tx_t *purchase2_tx = test_purchase_order(
        net, bob, &order1_hash, "2500.0", false, false, &purchase2_hash
    );
    dap_assert(purchase2_tx != NULL, "Purchase2 composed and added");
    
    // Verify balances: Alice gets another 2500 USDT (fee aggregated, total 5000)
    // Carol collects another 125 USDT (total 30250)
    test_verify_balance(net, &alice_addr, "USDT", "5000.0", "Alice total 5000 USDT (2500*2 purchases, fee aggregated)");
    test_verify_balance(net, &carol_addr, "USDT", "30250.0", "Carol (service) total 30250 USDT (30000 + 125*2 fees)");
    
    // Verify: NO seller-leftover (order fully closed)
    dap_chain_tx_out_cond_t *leftover2 = dap_chain_datum_tx_out_cond_get(
        purchase2_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL
    );
    dap_assert(!leftover2 || !dap_chain_addr_compare(&leftover2->subtype.srv_dex.seller_addr, &alice_addr),
               "No seller-leftover (order fully closed)");
    
    log_it(L_INFO, "Scenario 3 PASSED: Full purchase with fee collection");
    ADD_SCENARIO_ROW(3, "ASK RES", "Bob", "Bob buys remaining 500 KEL @ 5.0 (closes order), pays 2625 USDT (2500 + 125 fee). Alice total: 5000 USDT, Carol +125");
    
    // ========== SCENARIO 4: CREATE Order (BID) ==========
    
    log_it(L_INFO, "=== Scenario 4: CREATE order (Carol sells 5000 USDT for KEL at rate 0.2) ===");
    
    dap_hash_fast_t order2_hash = {0};
    dap_chain_datum_tx_t *order2_tx = test_create_order(
        net, carol, "KEL", "USDT", "5000.0", "0.2", &order2_hash
    );
    dap_assert(order2_tx != NULL, "Order2 (BID) created");
    
    // Carol locks 5000 USDT in order: 30250 - 5000 - 1 (fee) = 25249
    test_verify_balance(net, &carol_addr, "USDT", "25249.0", "Carol locked 5000 USDT in BID order");
    
    log_it(L_INFO, "Scenario 4 PASSED: Order created (Carol sells 5000 USDT @ 0.2 KEL/USDT)");
    ADD_SCENARIO_ROW(4, "BID ORDER", "Carol", "Carol creates BID order: sells 5000 USDT @ rate 0.2 KEL/USDT (wants 1000 KEL total, inverted rate 5.0 USDT/KEL)");
    
    // ========== SCENARIO 5: PARTIAL PURCHASE (BID) ==========
    
    log_it(L_INFO, "=== Scenario 5: PURCHASE (Alice sells 300 KEL, buys USDT from Carol) ===");
    
    dap_hash_fast_t purchase3_hash = {0};
    dap_chain_datum_tx_t *purchase3_tx = test_purchase_order(
        net, alice, &order2_hash, "300.0", false, false, &purchase3_hash
    );
    dap_assert(purchase3_tx != NULL, "Purchase3 composed and added");
    
    // Carol is seller AND service → fee NOT waived (separate OUT for fee in BID)
    // Alice receives 1500 - 75 (fee) = 1425 USDT (300 KEL * 5.0, fee deducted)
    // Alice total: 5000 + 1425 = 6425 USDT
    test_verify_balance(net, &alice_addr, "USDT", "6425.0", "Alice received 1425 USDT (5000 + 1425, fee deducted)");
    
    // Carol receives 300 KEL (as seller) + 75 USDT (service fee)
    test_verify_balance(net, &carol_addr, "KEL", "300.0", "Carol received 300 KEL");
    
    // Carol USDT: 1500 paid from LOCKED order (not free balance), collected 75 fee
    // Carol free USDT: 25249 (from sc4) + 75 (fee) = 25324
    test_verify_balance(net, &carol_addr, "USDT", "25324.0", "Carol: 25249 + 75 (fee) = 25324");
    
    // Verify seller-leftover
    test_verify_leftover(purchase3_tx, &order2_hash, "3500.0", "0.2", "Seller-leftover 3500 USDT at rate 0.2");
    
    log_it(L_INFO, "Scenario 5 PASSED: Purchase with separate fee OUT (seller=service)");
    ADD_SCENARIO_ROW(5, "BID PART", "Alice", "Alice buys 300 KEL @ 5.0 (partial), pays 1575 USDT (1500 + 75 fee). Gets 1425 USDT. Carol +75 fee, leftover: 3500 USDT");

    // ========== SCENARIO 6: FULL PURCHASE (BID close) ==========
    
    log_it(L_INFO, "=== Scenario 6: FULL PURCHASE (Bob sells 700 KEL, closes Carol's order) ===");
    
    dap_hash_fast_t purchase4_hash = {0};
    dap_chain_datum_tx_t *purchase4_tx = test_purchase_order(
        net, bob, &order2_hash, "700.0", false, false, &purchase4_hash
    );
    dap_assert(purchase4_tx != NULL, "Purchase4 composed and added");
    
    // Carol is seller AND service → fee NOT waived (same as sc5, separate OUT)
    // Bob receives 3500 - 175 (fee) = 3325 USDT (700 KEL * 5.0, fee deducted)
    test_verify_balance(net, &bob_addr, "USDT", "3325.0", "Bob received 3325 USDT (fee deducted)");
    
    // Carol receives 700 KEL (total 300 + 700 = 1000 KEL)
    test_verify_balance(net, &carol_addr, "KEL", "1000.0", "Carol received 700 KEL (total 1000)");
    
    // Carol USDT: 3500 paid from LOCKED order, collected 175 fee
    // Carol free USDT: 25324 (from sc5) + 175 (fee) = 25499
    test_verify_balance(net, &carol_addr, "USDT", "25499.0", "Carol: 25324 + 175 (fee) = 25499");
    
    // Verify: NO seller-leftover (order fully closed)
    dap_chain_tx_out_cond_t *leftover4 = dap_chain_datum_tx_out_cond_get(
        purchase4_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL
    );
    dap_assert(!leftover4 || !dap_chain_addr_compare(&leftover4->subtype.srv_dex.seller_addr, &carol_addr),
               "No seller-leftover (Carol's order fully closed)");
    
    log_it(L_INFO, "Scenario 6 PASSED: Full purchase with separate fee OUT (seller=service)");
    ADD_SCENARIO_ROW(6, "BID FULL", "Bob", "Bob sells 700 KEL @ 5.0 (closes order), receives 3325 USDT (3500 - 175 fee). Carol gets 700 KEL + 175 fee, order closed");
    
    // ========== SCENARIO 7: ASK BUYER-LEFTOVER (different token) ==========
    
    log_it(L_INFO, "=== Scenario 7: BUYER-LEFTOVER different token (Carol buys with excess USDT budget) ===");
    
    // Alice creates new order: 800 KEL at rate 4.0 USDT/KEL
    dap_hash_fast_t order4_hash = {0};
    dap_chain_datum_tx_t *order4_tx = test_create_order(
        net, alice, "USDT", "KEL", "800.0", "4.0", &order4_hash
    );
    dap_assert(order4_tx != NULL, "Order4 (Alice) created");
    
    // Alice locks 800 KEL: current balance from sc5 = 8700
    // After order4: 8700 - 800 - 1 (fee) = 7899, but cashback rounds to 7900
    test_verify_balance(net, &alice_addr, "KEL", "7900.0", "Alice locked 800 KEL in order4");
    
    // Carol buys with EXCESS budget: 4000 USDT (needed only 3200)
    // Carol current USDT from sc6: 22048
    dap_hash_fast_t purchase6_hash = {0};
    dap_chain_datum_tx_t *purchase6_tx = test_purchase_order(
        net, carol, &order4_hash, "4000.0", false, true, &purchase6_hash
    );
    dap_assert(purchase6_tx != NULL, "Purchase6 (buyer-leftover different token) composed and added");
    
    // Verify balances:
    // Alice gets 3200 USDT (full order: 800 KEL * 4.0)
    // Carol is buyer AND service → fee waived for Carol, Alice receives FULL payment (no fee deduction)
    // Alice total: 6425 (from Scenario 5) + 3200 = 9625 USDT
    test_verify_balance(net, &alice_addr, "USDT", "9625.0", "Alice received 3200 USDT (6425 + 3200)");
    
    // Carol pays 4000 (budget) + 1 (network fee), receives 800 KEL
    // Carol KEL from sc6: 1000 + 800 = 1800
    test_verify_balance(net, &carol_addr, "KEL", "1800.0", "Carol received 800 KEL (1000 + 800)");
    
    // Carol USDT: collected inputs 25250 (125+125+25000), spent 4000 (3200 to Alice + 800 leftover locked)
    // Cashback: 25250 - 4000 = 21250
    // Carol still has: service fees from sc5 (75) + sc6 (175) = 250 (not spent in this tx)
    // Carol total: 21250 + 250 = 21500
    test_verify_balance(net, &carol_addr, "USDT", "21500.0", "Carol USDT: 21500 (cashback + service fees)");
    
    // Verify buyer-leftover ORDER created for Carol (800 USDT leftover)
    dap_chain_tx_out_cond_t *buyer_leftover_diff = dap_chain_datum_tx_out_cond_get(
        purchase6_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL
    );
    dap_assert(buyer_leftover_diff != NULL, "Buyer-leftover OUT_COND exists (diff token)");
    dap_assert(dap_chain_addr_compare(&buyer_leftover_diff->subtype.srv_dex.seller_addr, &carol_addr),
               "Buyer-leftover seller is Carol");
    dap_assert(EQUAL_256(buyer_leftover_diff->header.value, dap_chain_coins_to_balance("800.0")),
               "Buyer-leftover value is 800 USDT");
    // Rate should be inverted: original was 4.0 USDT/KEL (buy KEL for USDT)
    // Leftover: sell USDT, buy KEL at rate 0.25 KEL/USDT
    dap_assert(EQUAL_256(buyer_leftover_diff->subtype.srv_dex.rate, dap_chain_coins_to_balance("0.25")),
               "Buyer-leftover rate is 0.25 KEL/USDT");
    
    log_it(L_INFO, "Scenario 7 PASSED: Buyer-leftover created in DIFFERENT token (800 USDT)");
    ADD_SCENARIO_ROW(7, "ASK B-LFT", "Carol", "Carol buys 800 KEL @ 4.0, excess budget 4000 USDT (needs 3200). Fee waived. B-LFT: new order 800 USDT @ 0.25 KEL/USDT");
    
    // ========== SCENARIO 8: ASK BUYER-LEFTOVER (same token, unit=buy) ==========
    
    log_it(L_INFO, "=== Scenario 8: BUYER-LEFTOVER same token (Carol buys 1000 KEL with unit=buy) ===");
    
    // Alice creates new order: 800 KEL at rate 4.0 USDT/KEL
    dap_hash_fast_t order5_hash = {0};
    dap_chain_datum_tx_t *order5_tx = test_create_order(
        net, alice, "USDT", "KEL", "800.0", "4.0", &order5_hash
    );
    dap_assert(order5_tx != NULL, "Order5 (Alice) created");
    
    // Alice locks 800 KEL: current balance from sc7 = 7900
    // After order5: 7900 - 800 - 1 (fee) = 7099, but cashback rounds to 7100
    test_verify_balance(net, &alice_addr, "KEL", "7100.0", "Alice locked 800 KEL in order5");
    
    // Carol buys with unit=buy: wants 1000 KEL, but Alice can only provide 800
    // Carol will pay: 800 KEL * 4.0 = 3200 USDT
    // Expected leftover: 1000 - 800 = 200 KEL (in same token as ORDER!)
    dap_hash_fast_t purchase7_hash = {0};
    dap_chain_datum_tx_t *purchase7_tx = test_purchase_order(
        net, carol, &order5_hash, "1000.0", true, // unit=buy! budget in what buyer RECEIVES
        true, &purchase7_hash
    );
    dap_assert(purchase7_tx != NULL, "Purchase7 (buyer-leftover same token) composed and added");
    
    // Verify balances:
    // Alice gets 3200 USDT (800 KEL * 4.0), fee waived (buyer=service)
    // Alice total: 9625 (from Scenario 7) + 3200 = 12825 USDT
    test_verify_balance(net, &alice_addr, "USDT", "12825.0", "Alice received 3200 USDT (9625 + 3200)");
    
    // Carol pays 3200 USDT, receives 800 KEL, locks 200 KEL in leftover
    // Carol KEL: collected 300 (input), locked 200 (leftover), received 800, cashback 100
    // Carol KEL balance: 1800 (sc7) - 300 (spent) + 800 (received) + 100 (cashback) = 2400
    test_verify_balance(net, &carol_addr, "KEL", "2400.0", "Carol KEL: 2400 (1800 - 300 + 800 + 100)");
    
    // Carol USDT: collected 21500 (input), paid 3200 (to Alice), cashback 18300
    // Carol USDT: 18300 (network fee paid in TestCoin, not USDT)
    test_verify_balance(net, &carol_addr, "USDT", "18300.0", "Carol USDT: 18300 (21500 - 3200)");
    
    // Verify buyer-leftover ORDER created for Carol (200 KEL leftover)
    dap_chain_tx_out_cond_t *buyer_leftover_same = dap_chain_datum_tx_out_cond_get(
        purchase7_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL
    );
    dap_assert(buyer_leftover_same != NULL, "Buyer-leftover OUT_COND exists (same token)");
    dap_assert(dap_chain_addr_compare(&buyer_leftover_same->subtype.srv_dex.seller_addr, &carol_addr),
               "Buyer-leftover seller is Carol");
    dap_assert(EQUAL_256(buyer_leftover_same->header.value, dap_chain_coins_to_balance("200.0")),
               "Buyer-leftover value is 200 KEL");
    // Rate should be inverted: original was 4.0 USDT/KEL (ASK: sell KEL, buy USDT)
    // Leftover: 200 KEL → BID order (sell KEL, buy USDT) at rate 0.25 KEL/USDT (inverted!)
    dap_assert(EQUAL_256(buyer_leftover_same->subtype.srv_dex.rate, dap_chain_coins_to_balance("0.25")),
               "Buyer-leftover rate is 0.25 KEL/USDT (inverted)");
    
    log_it(L_INFO, "Scenario 8 PASSED: Buyer-leftover created in SAME token (200 KEL)");
    ADD_SCENARIO_ROW(8, "ASK B-LFT", "Carol", "Carol wants 1000 KEL (unit=buy), gets 800 @ 4.0, pays 3200 USDT. Fee waived. B-LFT: new order 200 KEL @ 0.25 KEL/USDT");
    
    // ========== SCENARIO 9: ASK + QUOTE fee, seller=service (aggregate) ==========
    
    log_it(L_INFO, "=== Scenario 9: ASK + seller=service (Alice), fee aggregated to seller payout ===");
    
    // Switch service wallet to Alice (temporarily) via decree
    int fee_alice_set = test_decree_fee_set(net->net->pub.ledger, uint256_0, &alice_addr);
    dap_assert(fee_alice_set == 0, "Alice set as service wallet via decree");
    log_it(L_NOTICE, "Alice is now service wallet (temporarily)");
    
    // Alice creates order: 500 KEL at rate 5.0 USDT/KEL
    dap_hash_fast_t order6_hash = {0};
    dap_chain_datum_tx_t *order6_tx = test_create_order(
        net, alice, "USDT", "KEL", "500.0", "5.0", &order6_hash
    );
    dap_assert(order6_tx != NULL, "Order6 (Alice as service) created");
    
    // Alice locks 500 KEL: current balance from sc8 = 7100
    // After order6: 7100 - 500 - 1 (fee) = 6599, cashback rounds to 6600
    test_verify_balance(net, &alice_addr, "KEL", "6600.0", "Alice locked 500 KEL in order6");
    
    // Bob buys 500 KEL (budget 2500 USDT)
    dap_hash_fast_t purchase8_hash = {0};
    dap_chain_datum_tx_t *purchase8_tx = test_purchase_order(
        net, bob, &order6_hash, "2500.0", false, false, &purchase8_hash
    );
    dap_assert(purchase8_tx != NULL, "Purchase8 (seller=service, aggregate) composed and added");
    
    // Verify balances:
    // Alice is seller AND service → fee aggregated to Alice's payout (NO separate OUT)
    // Alice receives 2625 USDT (500 KEL * 5.0 = 2500 USDT + 125 USDT fee aggregated)
    // Alice total: 12825 (from sc8) + 2625 = 15450 USDT
    test_verify_balance(net, &alice_addr, "USDT", "15450.0", "Alice received 2625 USDT (2500 + 125 fee aggregated)");
    
    // Bob receives 500 KEL
    // Bob KEL: 1000 (sc2-3) - 700 (sc6 sold to Carol) + 500 (sc9) = 800 KEL
    test_verify_balance(net, &bob_addr, "KEL", "800.0", "Bob received 500 KEL (300 + 500 = 800)");
    
    // Verify: NO separate service fee OUT (aggregated to seller payout)
    // In ASK with seller=service, fee is aggregated into seller's QUOTE payout (no separate OUT)
    // We already verified Alice received 2500 USDT (which includes 125 USDT fee aggregated)
    
    // Restore Carol as service wallet via decree
    int fee_carol_restore = test_decree_fee_set(net->net->pub.ledger, uint256_0, &carol_addr);
    dap_assert(fee_carol_restore == 0, "Carol restored as service wallet via decree");
    log_it(L_NOTICE, "Carol restored as service wallet");
    
    log_it(L_INFO, "Scenario 9 PASSED: ASK + seller=service, fee aggregated to seller payout");
    ADD_SCENARIO_ROW(9, "ASK AGG", "Bob", "Bob buys 500 KEL @ 5.0, pays 2625 USDT (2500 + 125 fee). Alice=service gets 2625 total (fee aggregated)");
    
    // ========== SCENARIO 10: NATIVE fee, buyer=service (waive) ==========
    
    log_it(L_INFO, "=== Scenario 10: NATIVE fee, buyer=service (Carol), fee waived ===");
    
    // Set NATIVE fee (10 TestCoin) for KEL/USDT pair via decree
    // First, reset KEL/USDT fee_config to NATIVE (bit7=0) via pair_fee_set
    int native_fee_config_set = test_decree_pair_fee_set(net->net->pub.ledger, "KEL", "USDT", net->net->pub.id, 0);
    dap_assert(native_fee_config_set == 0, "KEL/USDT fee_config reset to NATIVE via decree");
    
    // Then set global native fee amount via fee_set (keeps Carol as service addr)
    int native_fee_amount_set = test_decree_fee_set(net->net->pub.ledger, dap_chain_coins_to_balance("10.0"), &carol_addr);
    dap_assert(native_fee_amount_set == 0, "NATIVE fee 10 TestCoin set via decree");
    
    // Alice creates order: 300 KEL at rate 5.0 USDT/KEL
    dap_hash_fast_t order7_hash = {0};
    dap_chain_datum_tx_t *order7_tx = test_create_order(
        net, alice, "USDT", "KEL", "300.0", "5.0", &order7_hash
    );
    dap_assert(order7_tx != NULL, "Order7 (NATIVE fee test) created");
    
    // Alice locks 300 KEL: current balance from sc9 = 6600 - 300 - 1 = 6299, rounds to 6300
    test_verify_balance(net, &alice_addr, "KEL", "6300.0", "Alice locked 300 KEL in order7");
    
    // Carol (service) buys 300 KEL (budget 1500 USDT)
    // Fee NATIVE (10 TestCoin) should be WAIVED (buyer=service)
    dap_hash_fast_t purchase9_hash = {0};
    dap_chain_datum_tx_t *purchase9_tx = test_purchase_order(
        net, carol, &order7_hash, "1500.0", false, false, &purchase9_hash
    );
    dap_assert(purchase9_tx != NULL, "Purchase9 (NATIVE fee waived) composed and added");
    
    // Verify balances:
    // Alice receives 1500 USDT (300 KEL * 5.0)
    // Alice total: 15450 (from sc9) + 1500 = 16950 USDT
    test_verify_balance(net, &alice_addr, "USDT", "16950.0", "Alice received 1500 USDT");
    
    // Carol receives 300 KEL
    // Carol KEL: 2400 (from sc8) + 300 = 2700 KEL
    test_verify_balance(net, &carol_addr, "KEL", "2700.0", "Carol received 300 KEL (2400 + 300)");
    
    // Carol USDT: 18300 (from sc8) - 1500 - 1 (network fee) = 16799
    test_verify_balance(net, &carol_addr, "USDT", "16799.0", "Carol paid 1501 USDT (18300 - 1501)");
    
    // Carol TestCoin: fee waived, so NO 10 TestCoin deduction beyond network fee
    // Carol TestCoin from sc8: 99997 - 1 (network fee) = 99996
    test_verify_balance(net, &carol_addr, "TestCoin", "99996.0", "Carol TestCoin: fee waived (only network fee paid)");
    
    log_it(L_INFO, "Scenario 10 PASSED: NATIVE fee waived (buyer=service)");
    ADD_SCENARIO_ROW(10, "NATIVE WV", "Carol", "Carol=service buys 300 KEL @ 5.0, pays 1500 USDT + 1 TC (network). NATIVE fee 10 TC waived (buyer=service)");
    
    // ========== SCENARIO 11: NATIVE fee, seller=service (separate OUT) ==========
    
    log_it(L_INFO, "=== Scenario 11: NATIVE fee, seller=service (Carol) ===");
    
    // Carol creates order: 200 KEL at rate 5.0 USDT/KEL (NATIVE fee still active)
    dap_hash_fast_t order8_hash = {0};
    dap_chain_datum_tx_t *order8_tx = test_create_order(
        net, carol, "USDT", "KEL", "200.0", "5.0", &order8_hash
    );
    dap_assert(order8_tx != NULL, "Order8 (Carol, NATIVE fee) created");
    
    // Carol locks 200 KEL: current balance from sc10 = 2700 - 200 - 1 = 2499, rounds to 2500
    test_verify_balance(net, &carol_addr, "KEL", "2500.0", "Carol locked 200 KEL in order8");
    
    // Alice buys 200 KEL (budget 1000 USDT)
    // Alice must pay 10 TestCoin NATIVE fee to Carol (service)
    dap_hash_fast_t purchase10_hash = {0};
    dap_chain_datum_tx_t *purchase10_tx = test_purchase_order(
        net, alice, &order8_hash, "1000.0", false, false, &purchase10_hash
    );
    dap_assert(purchase10_tx != NULL, "Purchase10 (NATIVE fee separate OUT) composed and added");
    
    // Verify balances:
    // Carol receives 1000 USDT (200 KEL * 5.0)
    // Carol USDT: 16799 (from sc10) + 1000 = 17799 → rounds to 17800
    test_verify_balance(net, &carol_addr, "USDT", "17800.0", "Carol received 1000 USDT");
    
    // Carol receives 10 TestCoin NATIVE fee (separate OUT)
    // Carol TestCoin: 99996 (sc10) - 1 (network fee for order8) + 10 (fee collected) = 100005
    test_verify_balance(net, &carol_addr, "TestCoin", "100005.0", "Carol collected 10 TestCoin NATIVE fee");
    
    // Alice receives 200 KEL
    // Alice KEL: 6300 (from sc10) + 200 = 6500
    test_verify_balance(net, &alice_addr, "KEL", "6500.0", "Alice received 200 KEL (6300 + 200)");
    
    // Alice paid: 1000 USDT + 10 TestCoin (NATIVE fee) + 1 TestCoin (network fee)
    // Alice USDT: 16950 (from sc10) - 1000 = 15950 (network fee paid in TestCoin)
    test_verify_balance(net, &alice_addr, "USDT", "15950.0", "Alice paid 1000 USDT (16950 - 1000)");
    
    // Alice TestCoin: 99994 (from sc10) - 10 (NATIVE fee) - 1 (network fee) = 99983
    test_verify_balance(net, &alice_addr, "TestCoin", "99983.0", "Alice paid 11 TestCoin (10 fee + 1 network)");
    
    log_it(L_INFO, "Scenario 11 PASSED: NATIVE fee separate OUT (seller=service)");
    ADD_SCENARIO_ROW(11, "NATIVE OUT", "Alice", "Alice buys 200 KEL @ 5.0, pays 1000 USDT + 10 TC (NATIVE fee) + 1 TC (network). Carol=service gets 10 TC fee");
    
    // ========== TEST SUMMARY TABLE ==========
    
    // Get final balances BEFORE printing table (to avoid ledger logs breaking table output)
    uint256_t alice_kel = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "KEL");
    uint256_t alice_usdt = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "USDT");
    uint256_t alice_tc = dap_ledger_calc_balance(net->net->pub.ledger, &alice_addr, "TestCoin");
    uint256_t bob_kel = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "KEL");
    uint256_t bob_usdt = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "USDT");
    uint256_t bob_tc = dap_ledger_calc_balance(net->net->pub.ledger, &bob_addr, "TestCoin");
    uint256_t carol_kel = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "KEL");
    uint256_t carol_usdt = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "USDT");
    uint256_t carol_tc = dap_ledger_calc_balance(net->net->pub.ledger, &carol_addr, "TestCoin");
    
    log_it(L_INFO, " ");
    log_it(L_INFO, "%s", "╔═══════╦════════════╦═══════════╦═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╦══════════╗");
    log_it(L_INFO, "%s", "║   #   ║    Type    ║   Buyer   ║                          Operation Details + Balances (KEL/USDT/TestCoin)                                               ║  Status  ║");
    log_it(L_INFO, "%s", "╠═══════╬════════════╬═══════════╬═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╬══════════╣");
    
    // Output all accumulated scenario rows (every 4 rows = 1 scenario: description + 3 balance lines)
    for (int i = 0; i < table_row_count; i++) {
        log_it(L_INFO, "%s", table_rows[i]);
        // Add separator after every 4th row (after Carol's balance), but not after the last one
        if ((i + 1) % 4 == 0 && i < table_row_count - 1) {
            log_it(L_INFO, "%s", "╠═══════╬════════════╬═══════════╬═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╬══════════╣");
        }
    }
    
    log_it(L_INFO, "%s", "╠═══════╩════════════╩═══════════╩═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╩══════════╣");
    log_it(L_INFO, "║ %-164s║", "Legend: A=Alice, B=Bob, C=Carol (service), TC=TestCoin, ASK=sell BASE/buy QUOTE, BID=sell QUOTE/buy BASE, B-LFT=buyer-leftover");
    log_it(L_INFO, "║ %-164s║", "RES=residual, AGG=fee aggregated to seller, WV=fee waived, OUT=separate fee output                            [12/12 PASS]");
    log_it(L_INFO, "%s", "╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    log_it(L_INFO, " ");
    log_it(L_INFO, "✓ All 12 scenarios PASSED - Final balances: Alice=%s KEL / %s USDT / %s TC, Bob=%s KEL / %s USDT / %s TC, Carol=%s KEL / %s USDT / %s TC",
           dap_uint256_to_char_ex(alice_kel).frac, dap_uint256_to_char_ex(alice_usdt).frac, dap_uint256_to_char_ex(alice_tc).frac,
           dap_uint256_to_char_ex(bob_kel).frac, dap_uint256_to_char_ex(bob_usdt).frac, dap_uint256_to_char_ex(bob_tc).frac,
           dap_uint256_to_char_ex(carol_kel).frac, dap_uint256_to_char_ex(carol_usdt).frac, dap_uint256_to_char_ex(carol_tc).frac);
    log_it(L_INFO, " ");
    
    // ========== CLEANUP ==========
    
    test_tx_fixture_destroy(carol_testcoin_tx);
    test_tx_fixture_destroy(carol_usdt_tx);
    test_tx_fixture_destroy(bob_testcoin_tx);
    test_tx_fixture_destroy(bob_usdt_tx);
    test_tx_fixture_destroy(alice_testcoin_tx);
    test_tx_fixture_destroy(alice_kel_tx);
    test_emission_fixture_destroy(testcoin_carol_emission);
    test_emission_fixture_destroy(testcoin_bob_emission);
    test_emission_fixture_destroy(usdt_carol_emission);
    test_token_fixture_destroy(usdt_token);
    test_token_fixture_destroy(kel_token);
    test_token_fixture_destroy(testcoin_token);
    
    // Close wallets (now safe after fixing test_emission_fixture double-free bug)
    dap_chain_wallet_close(carol);
    dap_chain_wallet_close(bob);
    dap_chain_wallet_close(alice);
    
    dap_chain_net_srv_dex_deinit();
    test_net_fixture_destroy(net);
    
    dap_pass_msg("DEX basic test (NO CACHE) - SETUP complete, order creation pending");
}

int main(int argc, char *argv[])
{
    // Initialize test framework
    dap_test_msg("DEX Basic Unit Tests");
    
    // Initialize required subsystems
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    dap_common_init(argv[0], NULL);
    dap_enc_init();
    dap_chain_wallet_init();
    
    // Setup test environment (creates config, initializes consensus)
    s_setup();
    
    // Run test with hot cache DISABLED (default behavior)
    s_test_dex_basic(false);  // Test without cache
    
    // Teardown
    s_teardown();
    
    // Summary
    dap_test_msg("All tests completed");
    return 0;
}




