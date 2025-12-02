/**
 * @file dex_test_common.c
 * @brief Common helper functions for DEX integration tests
 * @details
 * Implements decree helpers, order tracking, balance verification,
 * and order creation/purchase/cancel functions.
 * 
 * @author Cellframe Development Team
 * @date 2025
 */

#include <string.h>
#include "dex_test_common.h"
#include "dap_chain_net_srv_dex.h"
#include "dap_chain_net_tx.h"
#include "dap_hash.h"
#include "dap_tsd.h"
#include "dap_test.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_wallet_internal.h"
#include "../fixtures/test_emission_fixtures.h"
#include "../fixtures/test_transaction_fixtures.h"

// ============================================================================
// DECREE HELPERS
// ============================================================================

int test_decree_pair_add(dap_ledger_t *a_ledger, const char *a_token_base, const char *a_token_quote,
                         dap_chain_net_id_t a_net_id, uint8_t a_fee_config)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    uint8_t l_method = (uint8_t)DEX_DECREE_PAIR_ADD;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_BASE, a_token_base, dap_strlen(a_token_base)+1);
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_QUOTE, a_token_quote, dap_strlen(a_token_quote)+1);
    
    uint64_t l_net_id = a_net_id.uint64;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_BASE, &l_net_id, sizeof(uint64_t));
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_QUOTE, &l_net_id, sizeof(uint64_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &a_fee_config, sizeof(uint8_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(a_ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

int test_decree_pair_fee_set(dap_ledger_t *a_ledger, const char *a_token_base, const char *a_token_quote,
                             dap_chain_net_id_t a_net_id, uint8_t a_fee_config)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    uint8_t l_method = (uint8_t)DEX_DECREE_PAIR_FEE_SET;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_BASE, a_token_base, dap_strlen(a_token_base)+1);
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_TOKEN_QUOTE, a_token_quote, dap_strlen(a_token_quote)+1);
    
    uint64_t l_net_id = a_net_id.uint64;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_BASE, &l_net_id, sizeof(uint64_t));
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_NET_QUOTE, &l_net_id, sizeof(uint64_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_CONFIG, &a_fee_config, sizeof(uint8_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(a_ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

int test_decree_fee_set(dap_ledger_t *a_ledger, uint256_t a_fee_amount, const dap_chain_addr_t *a_service_addr)
{
    byte_t l_tsd_buf[1024] = {0};
    byte_t *l_ptr = l_tsd_buf;
    
    uint8_t l_method = (uint8_t)DEX_DECREE_FEE_SET;
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_METHOD, &l_method, sizeof(uint8_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_AMOUNT, &a_fee_amount, sizeof(uint256_t));
    
    l_ptr = dap_tsd_write(l_ptr, DEX_DECREE_TSD_FEE_ADDR, a_service_addr, sizeof(dap_chain_addr_t));
    
    size_t l_tsd_size = l_ptr - l_tsd_buf;
    
    return dap_chain_net_srv_dex_decree_callback(a_ledger, true, (dap_tsd_t*)l_tsd_buf, l_tsd_size);
}

// ============================================================================
// NETWORK FEE COLLECTOR MANAGEMENT
// ============================================================================

void test_set_net_fee_collector(dex_test_fixture_t *fixture, net_fee_collector_t collector)
{
    const dap_chain_addr_t *addr = NULL;
    const char *name = NULL;
    
    switch (collector) {
        case NET_FEE_DAVE:
            addr = &fixture->dave_addr;
            name = "Dave (neutral)";
            break;
        case NET_FEE_ALICE:
            addr = &fixture->alice_addr;
            name = "Alice (seller)";
            break;
        case NET_FEE_BOB:
            addr = &fixture->bob_addr;
            name = "Bob (seller)";
            break;
        default:
            log_it(L_ERROR, "Unknown net fee collector: %d", collector);
            return;
    }
    
    fixture->net_fee_collector = collector;
    dap_chain_net_tx_set_fee(fixture->net->net->pub.id, fixture->network_fee, *addr);
    log_it(L_NOTICE, "Network fee collector changed to: %s", name);
}

const dap_chain_addr_t* test_get_net_fee_addr(dex_test_fixture_t *fixture)
{
    switch (fixture->net_fee_collector) {
        case NET_FEE_DAVE:  return &fixture->dave_addr;
        case NET_FEE_ALICE: return &fixture->alice_addr;
        case NET_FEE_BOB:   return &fixture->bob_addr;
        default:            return &fixture->dave_addr;
    }
}

// ============================================================================
// TEST PARAMETERIZATION
// ============================================================================

/**
 * @brief Standard test pair configurations
 * @details Covers all critical combinations of native/non-native tokens and fee policies.
 * Uses 4 tokens: CELL, KEL, USDT (non-native), TestCoin (native for network fees).
 * All pairs are unique to avoid policy conflicts.
 */
static const test_pair_config_t TEST_PAIRS[] = {
    // Configuration 0: Baseline - QUOTE % fee, non-native
    {
        .base_token = "KEL",
        .quote_token = "USDT",
        .quote_is_native = false,
        .base_is_native = false,
        .fee_config = 0x80 | 2,  // 2% QUOTE
        .description = "KEL/USDT (2% QUOTE fee)"
    },
    
    // Configuration 1: Native as QUOTE - QUOTE % fee
    {
        .base_token = "KEL",
        .quote_token = "TestCoin",
        .quote_is_native = true,
        .base_is_native = false,
        .fee_config = 0x80 | 2,  // 2% QUOTE (native)
        .description = "KEL/TestCoin (2% QUOTE fee, native as QUOTE+fee)"
    },
    
    // Configuration 2: Native as BASE - QUOTE % fee
    {
        .base_token = "TestCoin",
        .quote_token = "USDT",
        .quote_is_native = false,
        .base_is_native = true,
        .fee_config = 0x80 | 2,  // 2% QUOTE
        .description = "TestCoin/USDT (2% QUOTE fee, native base)"
    },
    
    // Configuration 3: NATIVE absolute fee, non-native pair
    {
        .base_token = "CELL",
        .quote_token = "USDT",
        .quote_is_native = false,
        .base_is_native = false,
        .fee_config = 2,  // 2 TestCoin (absolute)
        .description = "CELL/USDT (2 TestCoin absolute fee)"
    },
    
    // Configuration 4: NATIVE absolute fee, native as QUOTE
    {
        .base_token = "CELL",
        .quote_token = "TestCoin",
        .quote_is_native = true,
        .base_is_native = false,
        .fee_config = 5,  // 5 TestCoin (absolute)
        .description = "CELL/TestCoin (5 TestCoin absolute, native as QUOTE+fee)"
    },
    
    // Configuration 5: NATIVE absolute fee, cross-pair
    {
        .base_token = "CELL",
        .quote_token = "KEL",
        .quote_is_native = false,
        .base_is_native = false,
        .fee_config = 3,  // 3 TestCoin (absolute)
        .description = "CELL/KEL (3 TestCoin absolute fee)"
    }
};

#define TEST_PAIRS_COUNT (sizeof(TEST_PAIRS) / sizeof(TEST_PAIRS[0]))

/**
 * @brief Run a test scenario with multiple token pair configurations
 * @details Iterates through provided configurations, sets up each pair via decree,
 * and executes the scenario function for each configuration.
 * 
 * @param f Test fixture
 * @param test_name Test name for logging
 * @param scenario Scenario function to execute
 * @param pairs Array of pair configurations
 * @param num_pairs Number of configurations in array
 */
void test_run_parameterized(
    dex_test_fixture_t *f,
    const char *test_name,
    test_scenario_fn scenario,
    const test_pair_config_t *pairs,
    size_t num_pairs)
{
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "  PARAMETERIZED TEST: %s", test_name);
    log_it(L_NOTICE, "  Configurations: %zu", num_pairs);
    log_it(L_NOTICE, "════════════════════════════════════════════════════════");
    
    size_t failed = 0;
    for (size_t i = 0; i < num_pairs; i++) {
        log_it(L_INFO, "");
        log_it(L_INFO, "┌────────────────────────────────────────────────────┐");
        log_it(L_INFO, "│  Configuration %zu/%zu: %s", i+1, num_pairs, pairs[i].description);
        log_it(L_INFO, "│  Pair: %s/%s", pairs[i].base_token, pairs[i].quote_token);
        log_it(L_INFO, "│  Fee: 0x%02X %s", pairs[i].fee_config,
               (pairs[i].fee_config & 0x80) ? "(QUOTE %)" : "(NATIVE absolute)");
        log_it(L_INFO, "└────────────────────────────────────────────────────┘");
        
        int ret = scenario(f, &pairs[i]);
        if (ret != 0) {
            log_it(L_ERROR, "✗ Configuration %zu/%zu FAILED: %s (error code: %d)", 
                   i+1, num_pairs, pairs[i].description, ret);
            failed++;
            continue;
        }
        
        log_it(L_INFO, "✓ Configuration %zu/%zu completed: %s", 
               i+1, num_pairs, pairs[i].description);
    }
    
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "════════════════════════════════════════════════════════");
    if (failed == 0) {
        log_it(L_NOTICE, "  ✓✓✓ ALL %zu CONFIGURATIONS PASSED", num_pairs);
    } else {
        log_it(L_ERROR, "  ✗✗✗ %zu/%zu CONFIGURATIONS FAILED", failed, num_pairs);
    }
    log_it(L_NOTICE, "  Test: %s", test_name);
    log_it(L_NOTICE, "════════════════════════════════════════════════════════");
    log_it(L_NOTICE, "");
}

/**
 * @brief Get standard pair configurations for full coverage
 * @return Pointer to TEST_PAIRS array
 */
const test_pair_config_t* test_get_standard_pairs(void)
{
    return TEST_PAIRS;
}

/**
 * @brief Get count of standard pair configurations
 * @return Number of configurations
 */
size_t test_get_standard_pairs_count(void)
{
    return TEST_PAIRS_COUNT;
}

/**
 * @brief Get stratified sample of pair configurations (minimum coverage)
 * @param out_count Output parameter for sample size
 * @return Pointer to stratified sample array
 * 
 * @details Sample covers 4 critical scenarios:
 * - Baseline: QUOTE % fee, non-native tokens (KEL/USDT)
 * - Native as QUOTE: QUOTE % fee in native TestCoin (KEL/TestCoin)
 * - NATIVE absolute fee: non-native pair (CELL/USDT)
 * - Native as QUOTE + absolute fee: (CELL/TestCoin)
 * 
 * This ensures comprehensive coverage of:
 * - Native token as both QUOTE and fee token (configs 1, 4)
 * - Both percentage and absolute fee policies
 * - Service fee collection in native vs. non-native tokens
 * - Multiple token pairs without conflicts
 */
const test_pair_config_t* test_get_stratified_sample(size_t *out_count)
{
    // Stratified sample: 5 configurations covering critical paths
    // Note: CELL/KEL excluded - requires Bob to have KEL for BID creation
    static const test_pair_config_t STRATIFIED_SAMPLE[] = {
        TEST_PAIRS[0],  // KEL/USDT (2% QUOTE) - baseline, non-native BASE+QUOTE
        TEST_PAIRS[1],  // KEL/TestCoin (2% QUOTE) - native as QUOTE + fee token
        TEST_PAIRS[2],  // TestCoin/USDT (2% QUOTE) - native as BASE (unique scenario!)
        TEST_PAIRS[3],  // CELL/USDT (2 TC absolute) - absolute fee, non-native
        TEST_PAIRS[4]   // CELL/TestCoin (5 TC absolute) - native as QUOTE + absolute fee
    };
    
    *out_count = sizeof(STRATIFIED_SAMPLE) / sizeof(STRATIFIED_SAMPLE[0]);
    return STRATIFIED_SAMPLE;
}

// ============================================================================
// ORDER LOOKUP (from ledger)
// ============================================================================

int test_dex_order_get_info(dap_ledger_t *ledger, const dap_hash_fast_t *hash, dex_order_info_t *out)
{
    dap_return_val_if_fail(ledger && hash && out, -1);
    
    memset(out, 0, sizeof(*out));
    
    dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(ledger, (dap_chain_hash_fast_t *)hash);
    if (!l_tx)
        return -2;
    
    dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
    if (!l_out)
        return -3;
    
    // Get root hash (blank for ORDER tx, non-blank for UPDATE/residual)
    dap_hash_fast_t l_root = dap_ledger_get_first_chain_tx_hash(ledger, l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX);
    if (dap_hash_fast_is_blank(&l_root))
        l_root = *hash;  // ORDER: root=tail
    out->root = l_root;
    out->tail = *hash;
    
    // Copy fields from out_cond
    out->price = l_out->subtype.srv_dex.rate;
    out->value = l_out->header.value;
    out->seller_addr = l_out->subtype.srv_dex.seller_addr;
    out->min_fill = l_out->subtype.srv_dex.min_fill;
    dap_strncpy(out->token_buy, l_out->subtype.srv_dex.buy_token, sizeof(out->token_buy) - 1);
    
    // Get sell token from ledger
    const char *l_sell_tok = dap_ledger_tx_get_token_ticker_by_hash(ledger, (dap_chain_hash_fast_t *)hash);
    if (l_sell_tok)
        dap_strncpy(out->token_sell, l_sell_tok, sizeof(out->token_sell) - 1);
    
    // Determine side: ASK sells BASE for QUOTE, BID sells QUOTE for BASE
    // If sell_token < buy_token (lexicographically), it's ASK; otherwise BID
    out->side = (strcmp(out->token_sell, out->token_buy) < 0) ? 0 : 1;
    
    return 0;
}

// ============================================================================
// TAMPERING HELPER
// ============================================================================

int test_dex_tamper_and_verify_rejection(
    dex_test_fixture_t *fixture,
    dap_chain_datum_tx_t *tx_template,
    dap_chain_wallet_t *wallet,
    tamper_callback_fn tamper_fn,
    void *tamper_data,
    const char *tamper_description)
{
    dap_ret_val_if_any(-1, !fixture, !tx_template, !wallet, !tamper_fn);
    
    // 1. Strip signatures: copy TX up to first SIG item
    uint8_t *l_first_sig = dap_chain_datum_tx_item_get(tx_template, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
    if (!l_first_sig) {
        log_it(L_ERROR, "No signature found in template TX");
        return -2;
    }
    
    size_t l_tx_size_without_sigs = (size_t)(l_first_sig - (uint8_t*)tx_template);
    dap_chain_datum_tx_t *l_tampered_tx = DAP_DUP_SIZE(tx_template, l_tx_size_without_sigs);
    if (!l_tampered_tx) {
        log_it(L_ERROR, "Failed to duplicate TX");
        return -3;
    }
    l_tampered_tx->header.tx_items_size = l_tx_size_without_sigs - sizeof(dap_chain_datum_tx_t);
    
    // 2. Apply tampering via callback (returns true if applied, false if skipped)
    bool l_tamper_applied = tamper_fn(l_tampered_tx, tamper_data);
    if (!l_tamper_applied) {
        // Tampering skipped (required OUT not found), this is OK for some TX configurations
        log_it(L_DEBUG, "Tamper '%s' skipped: required OUT not present", tamper_description);
        dap_chain_datum_tx_delete(l_tampered_tx);
        return 0;
    }
    
    // 3. Re-sign tampered TX
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet, 0);
    if (!l_key || dap_chain_datum_tx_add_sign_item(&l_tampered_tx, l_key) <= 0) {
        dap_chain_datum_tx_delete(l_tampered_tx);
        log_it(L_ERROR, "Failed to sign tampered TX");
        return -4;
    }
    DAP_DELETE(l_key);
    // 4. Try to add tampered TX → expect rejection
    dap_hash_fast_t l_hash_tampered = {0};
    dap_hash_fast(l_tampered_tx, dap_chain_datum_tx_get_size(l_tampered_tx), &l_hash_tampered);
    int ret = dap_ledger_tx_add(fixture->net->net->pub.ledger, l_tampered_tx, &l_hash_tampered, false, NULL);
    
    if (ret == 0) {
        log_it(L_ERROR, "✗ Tampered TX was ACCEPTED (should be REJECTED): %s", tamper_description);
        dap_chain_datum_tx_delete(l_tampered_tx);
        return -5;
    }
    
    log_it(L_NOTICE, "✓ Tampered TX rejected: %s", tamper_description);
    dap_chain_datum_tx_delete(l_tampered_tx);
    return 0;
}

int test_dex_add_tx(dex_test_fixture_t *fixture, dap_chain_datum_tx_t *tx)
{
    dap_ret_val_if_any(-1, !fixture, !tx);
    
    dap_hash_fast_t l_hash = {0};
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), &l_hash);
    int ret = dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, &l_hash, false, NULL);
    
    if (ret != 0) {
        log_it(L_ERROR, "✗ TX rejected");
        return -2;
    }
    
    log_it(L_NOTICE, "✓ TX accepted");
    return 0;
}

// ============================================================================
// WALLET FUNDING HELPER
// ============================================================================

int test_dex_fund_wallet(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_ticker,
    const char *amount_str)
{
    dap_ret_val_if_any(-1, !fixture, !wallet, !token_ticker, !amount_str);
    
    dap_chain_wallet_internal_t *l_wallet_int = DAP_CHAIN_WALLET_INTERNAL(wallet);
    dap_cert_t *l_cert = l_wallet_int->certs[0];
    dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(wallet, fixture->net->net->pub.id);
    if (!l_addr) {
        log_it(L_ERROR, "Failed to get wallet address");
        return -2;
    }
    
    // Save and disable network fee (emission tx cannot pay fee)
    dap_chain_net_id_t l_net_id = fixture->net->net->pub.id;
    uint256_t l_saved_fee = {};
    dap_chain_addr_t l_saved_fee_addr = {};
    bool l_had_fee = dap_chain_net_tx_get_fee(l_net_id, &l_saved_fee, &l_saved_fee_addr);
    if (l_had_fee)
        dap_chain_net_tx_set_fee(l_net_id, uint256_0, c_dap_chain_addr_blank);
    
    // Create emission
    dap_chain_hash_fast_t l_emission_hash = {0};
    test_emission_fixture_t *l_emission = test_emission_fixture_create_with_cert(
        token_ticker, dap_chain_coins_to_balance(amount_str), l_addr, l_cert
    );
    if (!l_emission) {
        if (l_had_fee) dap_chain_net_tx_set_fee(l_net_id, l_saved_fee, l_saved_fee_addr);
        DAP_DELETE(l_addr);
        log_it(L_ERROR, "Failed to create emission for %s", token_ticker);
        return -3;
    }
    
    if (test_emission_fixture_add_to_ledger(fixture->net->ledger, l_emission) != 0) {
        if (l_had_fee) dap_chain_net_tx_set_fee(l_net_id, l_saved_fee, l_saved_fee_addr);
        test_emission_fixture_destroy(l_emission);
        DAP_DELETE(l_addr);
        log_it(L_ERROR, "Failed to add emission to ledger");
        return -4;
    }
    
    if (!test_emission_fixture_get_hash(l_emission, &l_emission_hash)) {
        if (l_had_fee) dap_chain_net_tx_set_fee(l_net_id, l_saved_fee, l_saved_fee_addr);
        test_emission_fixture_destroy(l_emission);
        DAP_DELETE(l_addr);
        log_it(L_ERROR, "Failed to get emission hash");
        return -5;
    }
    
    // Create transaction from emission
    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        fixture->net->ledger, &l_emission_hash, token_ticker, amount_str, l_addr, l_cert
    );
    if (!l_tx) {
        if (l_had_fee) dap_chain_net_tx_set_fee(l_net_id, l_saved_fee, l_saved_fee_addr);
        test_emission_fixture_destroy(l_emission);
        DAP_DELETE(l_addr);
        log_it(L_ERROR, "Failed to create transaction from emission");
        return -6;
    }
    
    int l_ret = test_tx_fixture_add_to_ledger(fixture->net->ledger, l_tx);
    
    // Restore fee before returning
    if (l_had_fee)
        dap_chain_net_tx_set_fee(l_net_id, l_saved_fee, l_saved_fee_addr);
    
    if (l_ret != 0) {
        test_tx_fixture_destroy(l_tx);
        test_emission_fixture_destroy(l_emission);
        DAP_DELETE(l_addr);
        log_it(L_ERROR, "Failed to add transaction to ledger");
        return -7;
    }
    
    log_it(L_NOTICE, "✓ Funded wallet with %s %s", amount_str, token_ticker);
    
    test_tx_fixture_destroy(l_tx);
    test_emission_fixture_destroy(l_emission);
    DAP_DELETE(l_addr);
    return 0;
}

// ============================================================================
// ORDER CREATION
// ============================================================================

int test_dex_order_create_ex(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_buy,
    const char *token_sell,
    const char *amount_sell,
    const char *rate,
    uint8_t min_fill,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !wallet, !token_buy, !token_sell, !amount_sell, !rate, !out_hash);
    
    uint256_t value = dap_chain_coins_to_balance(amount_sell);
    uint256_t rate_value = dap_chain_coins_to_balance(rate);
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_create_error_t err = dap_chain_net_srv_dex_create(
        fixture->net->net, token_buy, token_sell, value, rate_value, min_fill, network_fee, wallet, &tx
    );
    
    if (err != DEX_CREATE_ERROR_OK || !tx) {
        log_it(L_ERROR, "CREATE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add order to ledger");
        return -3;
    }
    
    log_it(L_INFO, "Order created: %s %s for %s @ rate %s (min_fill=%d%%)", amount_sell, token_sell, token_buy, rate, min_fill);
    return 0;
}

int test_dex_order_create(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_buy,
    const char *token_sell,
    const char *amount_sell,
    const char *rate,
    dap_hash_fast_t *out_hash)
{
    return test_dex_order_create_ex(fixture, wallet, token_buy, token_sell, amount_sell, rate, 0, out_hash);
}

// ============================================================================
// ORDER PURCHASE (Direct)
// ============================================================================

int test_dex_order_purchase(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const dap_hash_fast_t *order_hash,
    const char *budget_str,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !wallet, !order_hash, !budget_str, !out_hash);
    
    uint256_t budget = dap_chain_coins_to_balance(budget_str);
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase(
        fixture->net->net, order_hash, budget, true, network_fee, wallet, 
        false, uint256_0, &tx
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "PURCHASE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add purchase to ledger");
        return -3;
    }
    
    log_it(L_INFO, "Purchase completed: budget=%s", budget_str);
    return 0;
}

// ============================================================================
// ORDER PURCHASE (Auto-Match)
// ============================================================================

int test_dex_order_purchase_auto(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *buyer,
    const char *token_buy,
    const char *token_sell,
    const char *amount,
    bool use_sell_budget,
    bool create_buyer_leftover,
    dap_hash_fast_t *out_hash,
    uint256_t *out_leftover_quote)
{
    dap_ret_val_if_any(-1, !fixture, !buyer, !token_sell, !token_buy, !amount, !out_hash);
    
    uint256_t budget = dap_chain_coins_to_balance(amount);
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dex_match_table_entry_t *matches = NULL;
    dap_chain_net_srv_dex_purchase_error_t err = dap_chain_net_srv_dex_purchase_auto(
        fixture->net->net, token_sell, token_buy, budget, !use_sell_budget, network_fee, uint256_0,
        buyer, create_buyer_leftover, uint256_0, &tx, &matches
    );
    
    if (err != DEX_PURCHASE_ERROR_OK || !tx) {
        log_it(L_ERROR, "AUTO-PURCHASE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add auto-purchase to ledger");
        return -3;
    }
    
    log_it(L_INFO, "Auto-purchase completed: budget=%s", amount);
    return 0;
}

// ============================================================================
// ORDER CANCEL
// ============================================================================

int test_dex_order_cancel(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *owner,
    const dap_hash_fast_t *order_hash,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !owner, !order_hash, !out_hash);
    
    uint256_t network_fee = fixture->network_fee;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_remove_error_t err = dap_chain_net_srv_dex_remove(
        fixture->net->net, order_hash, network_fee, owner, &tx
    );
    
    if (err != DEX_REMOVE_ERROR_OK || !tx) {
        log_it(L_ERROR, "CANCEL failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add cancel to ledger");
        return -3;
    }
    
    log_it(L_INFO, "Order cancelled successfully: %s", dap_chain_hash_fast_to_str_static(order_hash));
    return 0;
}

// ============================================================================
// ORDER CANCEL ALL (Stub - to be implemented when needed)
// ============================================================================

int test_dex_order_cancel_all(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const char *token_sell,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !wallet, !token_sell, !out_hash);
    log_it(L_WARNING, "test_dex_order_cancel_all: NOT YET IMPLEMENTED");
    return -1;
}

// ============================================================================
// ORDER UPDATE
// ============================================================================

int test_dex_order_update(
    dex_test_fixture_t *fixture,
    dap_chain_wallet_t *wallet,
    const dap_hash_fast_t *order_hash,
    const char *new_rate,
    const char *new_value,
    dap_hash_fast_t *out_hash)
{
    dap_ret_val_if_any(-1, !fixture, !wallet, !order_hash, !out_hash);
    
    // Note: DEX API currently only supports value updates, not rate
    // new_rate parameter is reserved for future use
    UNUSED(new_rate);
    
    bool l_has_new_value = new_value != NULL;
    uint256_t l_new_value = l_has_new_value ? dap_chain_coins_to_balance(new_value) : uint256_0;
    
    dap_chain_datum_tx_t *tx = NULL;
    dap_chain_net_srv_dex_update_error_t err = dap_chain_net_srv_dex_update(
        fixture->net->net, (dap_hash_fast_t*)order_hash,
        l_has_new_value, l_new_value,
        fixture->network_fee, wallet, &tx
    );
    
    if (err != DEX_UPDATE_ERROR_OK || !tx) {
        log_it(L_ERROR, "UPDATE failed: err=%d", err);
        return -2;
    }
    
    dap_hash_fast(tx, dap_chain_datum_tx_get_size(tx), out_hash);
    
    if (dap_ledger_tx_add(fixture->net->net->pub.ledger, tx, out_hash, false, NULL) != 0) {
        log_it(L_ERROR, "Failed to add update to ledger");
        return -3;
    }
    
    log_it(L_INFO, "Order updated: hash=%s, new_value=%s",
           dap_chain_hash_fast_to_str_static(order_hash),
           new_value ? new_value : "(unchanged)");
    return 0;
}

// ============================================================================
// BALANCE VERIFICATION
// ============================================================================

bool test_dex_verify_balance(dex_test_fixture_t *f, const dap_chain_addr_t *addr,
                             const char *token, const char *expected)
{
    dap_ret_val_if_any(false, !f, !addr, !token, !expected);
    
    uint256_t balance = dap_ledger_calc_balance(f->net->net->pub.ledger, addr, token);
    uint256_t expected_val = dap_chain_coins_to_balance(expected);
    
    bool match = EQUAL_256(balance, expected_val);
    log_it(match ? L_INFO : L_ERROR, "Balance %s %s: expected %s, got %s",
           dap_chain_addr_to_str_static(addr), token, expected,
           dap_uint256_to_char_ex(balance).frac);
    
    return match;
}

void test_dex_dump_balances(dex_test_fixture_t *f, const char *label)
{
    dap_ret_if_any(!f, !label);
    
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "========== BALANCE DUMP: %s ==========", label);
    
    log_it(L_NOTICE, "Alice: KEL=%s, USDT=%s, TC=%s",
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "KEL")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "USDT")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->alice_addr, "TestCoin")).frac);
    
    log_it(L_NOTICE, "Bob:   KEL=%s, USDT=%s, TC=%s",
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "KEL")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "USDT")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->bob_addr, "TestCoin")).frac);
    
    log_it(L_NOTICE, "Carol (srv): KEL=%s, USDT=%s, TC=%s",
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "KEL")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "USDT")).frac,
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->carol_addr, "TestCoin")).frac);
    
    log_it(L_NOTICE, "Dave (net): TC=%s",
           dap_uint256_to_char_ex(dap_ledger_calc_balance(f->net->net->pub.ledger, &f->dave_addr, "TestCoin")).frac);

    log_it(L_NOTICE, "========================================");
    log_it(L_NOTICE, "");
}

void test_dex_dump_orderbook(dex_test_fixture_t *f, const char *label)
{
    dap_ret_if_any(!f, !label);
    
    log_it(L_NOTICE, "");
    log_it(L_NOTICE, "========== ORDERBOOK DUMP: %s ==========", label);
    
    // Dump from cache
    log_it(L_NOTICE, "--- CACHE ---");
    dap_chain_net_srv_dex_dump_orders_cache();
    
    // Dump from ledger
    log_it(L_NOTICE, "--- LEDGER ---");
    dap_ledger_t *ledger = f->net->net->pub.ledger;
    dap_ledger_datum_iter_t *it = dap_ledger_datum_iter_create(f->net->net);
    if (!it) {
        log_it(L_NOTICE, "  (iterator failed)");
        log_it(L_NOTICE, "========================================");
        return;
    }
    
    size_t count = 0;
    for (dap_chain_datum_tx_t *tx = dap_ledger_datum_iter_get_first(it); tx; tx = dap_ledger_datum_iter_get_next(it)) {
        int l_out_idx = 0;
        dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, &l_out_idx);
        if (!l_out || dap_ledger_tx_hash_is_used_out_item(ledger, &it->cur_hash, l_out_idx, NULL))
            continue;
        
        const char *sell_tok = dap_ledger_tx_get_token_ticker_by_hash(ledger, &it->cur_hash);
        const char *buy_tok = l_out->subtype.srv_dex.buy_token;
        int side = (sell_tok && buy_tok && strcmp(sell_tok, buy_tok) < 0) ? 0 : 1;
        
        log_it(L_NOTICE, "  [%zu] %s %s: %s/%s value=%s rate=%s minfill=%d%%%s",
               count++,
               dap_hash_fast_is_blank(&l_out->subtype.srv_dex.order_root_hash) ? dap_hash_fast_to_str_static(&it->cur_hash) : dap_hash_fast_to_str_static(&l_out->subtype.srv_dex.order_root_hash),
               side == 0 ? "ASK" : "BID",
               sell_tok ? sell_tok : "?", buy_tok,
               dap_uint256_to_char_ex(l_out->header.value).frac,
               dap_uint256_to_char_ex(l_out->subtype.srv_dex.rate).frac,
               l_out->subtype.srv_dex.min_fill & 0x7F, (l_out->subtype.srv_dex.min_fill & 0x80) ? " of origin" : ""
            );
    }
    
    dap_ledger_datum_iter_delete(it);
    
    if (count == 0)
        log_it(L_NOTICE, "  (empty - no active orders)");
    
    log_it(L_NOTICE, "========================================");
    log_it(L_NOTICE, "");
}

int test_dex_adjust_minfill(dex_test_fixture_t *fixture, const dap_hash_fast_t *a_order_tail,
                            uint8_t a_new_minfill, uint8_t *a_out_old_minfill)
{
    dap_return_val_if_fail(fixture && a_order_tail, -1);
    
    bool l_cache_enabled = dap_config_get_item_bool_default(g_config, "srv_dex", "memcached", false);
    
    if (l_cache_enabled) {
        return dap_chain_net_srv_dex_cache_adjust_minfill(
            fixture->net->net, a_order_tail, a_new_minfill, a_out_old_minfill);
    } else {
        dap_chain_datum_tx_t *l_tx = dap_ledger_tx_find_by_hash(
            fixture->net->net->pub.ledger, (dap_chain_hash_fast_t *)a_order_tail);
        if (!l_tx)
            return -2;
        
        dap_chain_tx_out_cond_t *l_out = dap_chain_datum_tx_out_cond_get(
            l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_DEX, NULL);
        if (!l_out)
            return -2;
        
        if (a_out_old_minfill)
            *a_out_old_minfill = l_out->subtype.srv_dex.min_fill;
        l_out->subtype.srv_dex.min_fill = a_new_minfill;
        return 0;
    }
}

// ============================================================================
// BALANCE SNAPSHOTS
// ============================================================================

static uint256_t s_get_balance(dap_ledger_t *ledger, const dap_chain_addr_t *addr, const char *token)
{
    if (!ledger || !addr || !token || !token[0])
        return uint256_0;
    return dap_ledger_calc_balance(ledger, addr, token);
}

balance_snapshot_t test_dex_take_snapshot(
    dex_test_fixture_t *f,
    const char *base_token,
    const char *quote_token,
    const char *fee_token)
{
    balance_snapshot_t snap = {0};
    dap_return_val_if_fail(f && base_token && quote_token, snap);
    
    dap_ledger_t *ledger = f->net->net->pub.ledger;
    const char *fee_tok = fee_token ? fee_token : "TestCoin";
    
    dap_strncpy(snap.base_token, base_token, sizeof(snap.base_token) - 1);
    dap_strncpy(snap.quote_token, quote_token, sizeof(snap.quote_token) - 1);
    dap_strncpy(snap.fee_token, fee_tok, sizeof(snap.fee_token) - 1);
    
    snap.alice.base = s_get_balance(ledger, &f->alice_addr, base_token);
    snap.alice.quote = s_get_balance(ledger, &f->alice_addr, quote_token);
    snap.alice.fee_token = s_get_balance(ledger, &f->alice_addr, fee_tok);
    
    snap.bob.base = s_get_balance(ledger, &f->bob_addr, base_token);
    snap.bob.quote = s_get_balance(ledger, &f->bob_addr, quote_token);
    snap.bob.fee_token = s_get_balance(ledger, &f->bob_addr, fee_tok);
    
    snap.carol.base = s_get_balance(ledger, &f->carol_addr, base_token);
    snap.carol.quote = s_get_balance(ledger, &f->carol_addr, quote_token);
    snap.carol.fee_token = s_get_balance(ledger, &f->carol_addr, fee_tok);
    
    return snap;
}

// ============================================================================
// MIN_FILL CALCULATION
// ============================================================================

void test_dex_calc_minfill(
    uint256_t origin_value,
    uint256_t current_value,
    uint8_t min_fill,
    minfill_calc_t *out)
{
    dap_return_if_fail(out);
    memset(out, 0, sizeof(*out));
    
    out->origin_value = origin_value;
    out->current_value = current_value;
    out->pct = min_fill & 0x7F;
    out->from_origin = (min_fill & 0x80) != 0;
    
    if (out->pct == 0)
        return;
    
    // min = value * pct / 100
    uint256_t pct256 = GET_256_FROM_64((uint64_t)out->pct);
    uint256_t hundred = GET_256_FROM_64(100ULL);
    uint256_t tmp;
    
    MULT_256_256(origin_value, pct256, &tmp);
    DIV_256(tmp, hundred, &out->min_from_origin);
    
    MULT_256_256(current_value, pct256, &tmp);
    DIV_256(tmp, hundred, &out->min_from_current);
    
    // Calculate test value between min_from_current and min_from_origin
    // This value should pass from_current check but fail from_origin check
    if (compare256(out->min_from_origin, out->min_from_current) > 0) {
        // Midpoint: (min_from_current + min_from_origin) / 2
        SUM_256_256(out->min_from_current, out->min_from_origin, &tmp);
        uint256_t two = GET_256_FROM_64(2ULL);
        DIV_256(tmp, two, &out->test_between);
        
        // Ensure it's strictly greater than min_from_current
        if (compare256(out->test_between, out->min_from_current) <= 0) {
            uint256_t one = GET_256_FROM_64(1ULL);
            SUM_256_256(out->min_from_current, one, &out->test_between);
        }
    }
}

// ============================================================================
// BALANCE SNAPSHOTS
// ============================================================================

void test_dex_snap_take(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
                        const char *a_base_token, const char *a_quote_token,
                        balance_snap_t *a_snap)
{
    a_snap->base = dap_ledger_calc_balance(a_ledger, a_addr, a_base_token);
    a_snap->quote = dap_ledger_calc_balance(a_ledger, a_addr, a_quote_token);
    a_snap->fee = dap_ledger_calc_balance(a_ledger, a_addr, "TestCoin");
}

int test_dex_snap_verify(const char *label,
                         const balance_snap_t *before, const balance_snap_t *after,
                         uint128_t delta_base, bool base_decreased,
                         uint128_t delta_quote, bool quote_decreased)
{
    char lbl[128];
    snprintf(lbl, sizeof(lbl), "%s BASE", label);
    if (test_dex_verify_delta(lbl, before->base, after->base, delta_base, base_decreased) != 0)
        return -1;
    snprintf(lbl, sizeof(lbl), "%s QUOTE", label);
    if (test_dex_verify_delta(lbl, before->quote, after->quote, delta_quote, quote_decreased) != 0)
        return -2;
    return 0;
}

int test_dex_snap_verify_fee(const char *label,
                             const balance_snap_t *before, const balance_snap_t *after,
                             uint128_t delta_fee, bool fee_decreased)
{
    char lbl[128];
    snprintf(lbl, sizeof(lbl), "%s FEE", label);
    return test_dex_verify_delta(lbl, before->fee, after->fee, delta_fee, fee_decreased);
}

// ============================================================================
// DELTA VERIFICATION (uint128 arithmetic)
// ============================================================================

int test_dex_verify_delta(const char *label, uint256_t before, uint256_t after,
                          uint128_t expected, bool decreased)
{
    uint256_t actual_diff;
    if (decreased) {
        if (compare256(before, after) < 0) {
            log_it(L_ERROR, "%s: balance increased, expected decrease", label);
            return -1;
        }
        SUBTRACT_256_256(before, after, &actual_diff);
    } else {
        if (compare256(after, before) < 0) {
            log_it(L_ERROR, "%s: balance decreased, expected increase", label);
            return -1;
        }
        SUBTRACT_256_256(after, before, &actual_diff);
    }
    
    uint256_t expected_256 = GET_256_FROM_128(expected);
    if (!EQUAL_256(actual_diff, expected_256)) {
        log_it(L_ERROR, "%s: delta %s, expected %s", label,
               dap_uint256_to_char_ex(actual_diff).frac,
               dap_uint256_to_char_ex(expected_256).frac);
        return -1;
    }
    
    log_it(L_DEBUG, "%s: OK (delta %s)", label, dap_uint256_to_char_ex(actual_diff).frac);
    return 0;
}

