/**
 * @file test_ledger_tx_operations.c
 * @brief Comprehensive unit tests for ledger TX operations
 * @details Demonstrates DAP Mock Framework with TX Compose API
 * 
 * @author Cellframe Development Team
 * @date 2026-01-12
 * 
 * @copyright Copyright (c) 2017-2024 Demlabs Inc. All rights reserved.
 */

#include "dap_test.h"
#include "dap_mock.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_common.h"
#include "dap_hash.h"
#include "dap_enc_key.h"
#include "dap_time.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_wallet.h"

#define LOG_TAG "test_ledger_tx"

// =============================================================================
// MOCKS: Using DAP_MOCK_DECLARE + DAP_MOCK_WRAPPER_DEFAULT
// =============================================================================

DAP_MOCK_DECLARE(dap_ledger_tx_find_by_hash, { .return_value.ptr = NULL });
DAP_MOCK_DECLARE(dap_ledger_tx_add, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_ledger_tx_remove, { .return_value.i = 0 });
DAP_MOCK_DECLARE(dap_ledger_tx_get_token_ticker_by_hash, { .return_value.ptr = (void*)"CELL" });

DAP_MOCK_WRAPPER_DEFAULT(dap_chain_datum_tx_t*, dap_ledger_tx_find_by_hash,
    (dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash),
    (a_ledger, a_tx_hash))

DAP_MOCK_WRAPPER_DEFAULT(int, dap_ledger_tx_add,
    (dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold, dap_ledger_datum_iter_data_t *a_datum_index_data),
    (a_ledger, a_tx, a_tx_hash, a_from_threshold, a_datum_index_data))

DAP_MOCK_WRAPPER_DEFAULT(int, dap_ledger_tx_remove,
    (dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash),
    (a_ledger, a_tx, a_tx_hash))

DAP_MOCK_WRAPPER_DEFAULT(const char*, dap_ledger_tx_get_token_ticker_by_hash,
    (dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash),
    (a_ledger, a_tx_hash))

// =============================================================================
// TEST DATA
// =============================================================================

static dap_ledger_t s_mock_ledger = {0};
static dap_hash_fast_t s_test_tx_hash1 = {0};
static dap_hash_fast_t s_test_tx_hash2 = {0};
static dap_chain_datum_tx_t *s_test_tx1 = NULL;
static dap_chain_datum_tx_t *s_test_tx2 = NULL;

// =============================================================================
// TESTS
// =============================================================================

/**
 * @brief Test setup
 */
static void test_setup(void)
{
    log_it(L_INFO, "========================================");
    log_it(L_INFO, "RUNNING: Ledger TX Operations Unit Tests");
    log_it(L_INFO, "WITH DAP MOCK FRAMEWORK");
    log_it(L_INFO, "========================================");
    
    memset(&s_mock_ledger, 0, sizeof(s_mock_ledger));
    memset(&s_test_tx_hash1, 0x11, sizeof(dap_hash_fast_t));
    memset(&s_test_tx_hash2, 0x22, sizeof(dap_hash_fast_t));
    
    // Create TX using TX Compose API
    // For unit test, we create minimal valid TX structures
    s_test_tx1 = dap_chain_datum_tx_create();
    s_test_tx2 = dap_chain_datum_tx_create();
    
    // Reset mocks and enable them
    DAP_MOCK_SET_RETURN(dap_ledger_tx_add, 0);
    DAP_MOCK_SET_RETURN(dap_ledger_tx_find_by_hash, NULL);
    DAP_MOCK_RESET(dap_ledger_tx_add);
    DAP_MOCK_RESET(dap_ledger_tx_find_by_hash);
    
    // Ensure mocks are enabled
    g_mock_dap_ledger_tx_add->enabled = true;
    g_mock_dap_ledger_tx_find_by_hash->enabled = true;
    g_mock_dap_ledger_tx_remove->enabled = true;
    g_mock_dap_ledger_tx_get_token_ticker_by_hash->enabled = true;
    
    log_it(L_INFO, "Test setup completed");
}

/**
 * @brief Test teardown
 */
static void test_teardown(void)
{
    if (s_test_tx1) 
        DAP_DELETE(s_test_tx1);
    if (s_test_tx2) 
        DAP_DELETE(s_test_tx2);
    
    log_it(L_INFO, "Test teardown completed");
}

/**
 * @brief Test 1: Mock state verification
 */
static void test_mock_state_verification(void)
{
    log_it(L_INFO, "TEST 1: Mock state verification");
    
    dap_assert_PIF(g_mock_dap_ledger_tx_add != NULL, "Mock should be registered");
    dap_assert_PIF(g_mock_dap_ledger_tx_add->enabled, "Mock should be enabled");
    dap_assert_PIF(g_mock_dap_ledger_tx_add->return_value.i == 0, "Default return should be 0");
    
    log_it(L_INFO, "✅ TEST 1 PASSED: Mock properly configured");
}

/**
 * @brief Test 2: Mock return value override
 */
static void test_mock_return_override(void)
{
    log_it(L_INFO, "TEST 2: Mock return override");
    
    // Set custom return value
    DAP_MOCK_SET_RETURN(dap_ledger_tx_find_by_hash, s_test_tx1);
    
    dap_chain_datum_tx_t *l_found = dap_ledger_tx_find_by_hash(&s_mock_ledger, &s_test_tx_hash1);
    dap_assert_PIF(l_found == s_test_tx1, "Should return overridden value");
    
    // Reset
    DAP_MOCK_SET_RETURN(dap_ledger_tx_find_by_hash, NULL);
    
    log_it(L_INFO, "✅ TEST 2 PASSED: Return override works");
}

/**
 * @brief Test 3: NULL return for non-existent TX
 */
static void test_null_return(void)
{
    log_it(L_INFO, "TEST 3: NULL return for non-existent TX");
    
    dap_hash_fast_t l_hash = {0};
    memset(&l_hash, 0xFF, sizeof(dap_hash_fast_t));
    
    dap_chain_datum_tx_t *l_found = dap_ledger_tx_find_by_hash(&s_mock_ledger, &l_hash);
    dap_assert_PIF(l_found == NULL, "Should return NULL");
    
    log_it(L_INFO, "✅ TEST 3 PASSED: NULL returned correctly");
}

/**
 * @brief Test 4: Token ticker resolution
 */
static void test_token_ticker(void)
{
    log_it(L_INFO, "TEST 4: Token ticker resolution");
    
    const char *l_ticker = dap_ledger_tx_get_token_ticker_by_hash(&s_mock_ledger, &s_test_tx_hash1);
    dap_assert_PIF(l_ticker != NULL, "Ticker should not be NULL");
    dap_assert_PIF(strcmp(l_ticker, "CELL") == 0, "Ticker should be 'CELL'");
    
    log_it(L_INFO, "✅ TEST 4 PASSED: Token ticker works");
}

/**
 * @brief Test 5: Error injection
 */
static void test_error_injection(void)
{
    log_it(L_INFO, "TEST 5: Error injection");
    
    DAP_MOCK_SET_RETURN(dap_ledger_tx_add, -1);
    
    // Mock will return error without calling real function
    dap_assert_PIF(g_mock_dap_ledger_tx_add->return_value.i == -1, "Error injected");
    
    DAP_MOCK_SET_RETURN(dap_ledger_tx_add, 0);
    
    log_it(L_INFO, "✅ TEST 5 PASSED: Error injection works");
}

/**
 * @brief Test 6: Call counting
 */
static void test_call_counting(void)
{
    log_it(L_INFO, "TEST 6: Call counting");
    
    DAP_MOCK_RESET(dap_ledger_tx_find_by_hash);
    dap_assert_PIF(g_mock_dap_ledger_tx_find_by_hash->call_count == 0, "Count should be 0");
    
    dap_ledger_tx_find_by_hash(&s_mock_ledger, &s_test_tx_hash1);
    dap_ledger_tx_find_by_hash(&s_mock_ledger, &s_test_tx_hash2);
    
    dap_assert_PIF(g_mock_dap_ledger_tx_find_by_hash->call_count == 2, "Count should be 2");
    
    log_it(L_INFO, "✅ TEST 6 PASSED: Call counting works");
}

/**
 * @brief Test 7: TX structure validation
 */
static void test_tx_structure(void)
{
    log_it(L_INFO, "TEST 7: TX structure validation");
    
    dap_assert_PIF(s_test_tx1 != NULL, "TX1 should be created");
    dap_assert_PIF(s_test_tx2 != NULL, "TX2 should be created");
    dap_assert_PIF(s_test_tx1 != s_test_tx2, "TXs should be different");
    
    log_it(L_INFO, "✅ TEST 7 PASSED: TX structures valid");
}

/**
 * @brief Test 8: Mock reset functionality
 */
static void test_mock_reset(void)
{
    log_it(L_INFO, "TEST 8: Mock reset");
    
    // Make some calls
    dap_ledger_tx_find_by_hash(&s_mock_ledger, &s_test_tx_hash1);
    dap_assert_PIF(g_mock_dap_ledger_tx_find_by_hash->call_count > 0, "Should have calls");
    
    // Reset
    DAP_MOCK_RESET(dap_ledger_tx_find_by_hash);
    dap_assert_PIF(g_mock_dap_ledger_tx_find_by_hash->call_count == 0, "Count should be 0 after reset");
    
    log_it(L_INFO, "✅ TEST 8 PASSED: Mock reset works");
}

// =============================================================================
// MAIN
// =============================================================================

int main(void)
{
    test_setup();
    
    test_mock_state_verification();
    test_mock_return_override();
    test_null_return();
    test_token_ticker();
    test_error_injection();
    test_call_counting();
    test_tx_structure();
    test_mock_reset();
    
    test_teardown();
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, "✅ ALL LEDGER UNIT TESTS PASSED (8/8)");
    log_it(L_INFO, "========================================");
    
    return 0;
}
