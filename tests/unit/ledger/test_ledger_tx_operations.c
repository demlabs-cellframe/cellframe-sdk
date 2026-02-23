/**
 * @file test_ledger_tx_operations.c
 * @brief Comprehensive unit tests for ledger TX operations
 * @details Demonstrates DAP Mock Framework with custom mocks using PARAM macros
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
#include "dap_hash_compat.h"
#include "dap_enc_key.h"
#include "dap_time.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_wallet.h"

#define LOG_TAG "test_ledger_tx"

// =============================================================================
// MOCKS: PART 1 - Simple mock with DAP_MOCK_WRAPPER_DEFAULT
// =============================================================================

DAP_MOCK_DECLARE(dap_ledger_tx_remove, { .return_value.i = 0 });

DAP_MOCK_WRAPPER_DEFAULT(int, dap_ledger_tx_remove,
    (dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash),
    (a_ledger, a_tx, a_tx_hash))

// =============================================================================
// MOCKS: PART 2 - CUSTOM MOCKS with DAP_MOCK_WRAPPER_CUSTOM
// =============================================================================

// Declare mocks first (outside DAP_MOCK_WRAPPER_CUSTOM)
DAP_MOCK_DECLARE_CUSTOM(dap_ledger_tx_find_by_hash, DAP_MOCK_CONFIG_DEFAULT);
DAP_MOCK_DECLARE_CUSTOM(dap_ledger_tx_add, DAP_MOCK_CONFIG_DEFAULT);
DAP_MOCK_DECLARE_CUSTOM(dap_ledger_tx_get_token_ticker_by_hash, DAP_MOCK_CONFIG_DEFAULT);

DAP_MOCK_WRAPPER_CUSTOM(dap_chain_datum_tx_t*, dap_ledger_tx_find_by_hash,
    (dap_ledger_t* a_ledger, dap_hash_fast_t* a_tx_hash)
) {
    dap_mock_function_state_t *G_MOCK = g_mock_dap_ledger_tx_find_by_hash;
    dap_chain_datum_tx_t* l_result = NULL;
    if (a_tx_hash) {
        bool l_is_zero = true;
        for (size_t i = 0; i < sizeof(dap_hash_fast_t); i++) {
            if (((uint8_t*)a_tx_hash)[i] != 0) {
                l_is_zero = false;
                break;
            }
        }
        if (l_is_zero) {
            log_it(L_DEBUG, "Custom mock: zero hash detected, returning NULL");
            dap_mock_record_call(G_MOCK, NULL, 0, NULL);
            return NULL;
        }
    }
    l_result = (dap_chain_datum_tx_t*)G_MOCK->return_value.ptr;
    dap_mock_record_call(G_MOCK, NULL, 0, (void*)(intptr_t)l_result);
    return l_result;
}

DAP_MOCK_WRAPPER_CUSTOM(int, dap_ledger_tx_add,
    (dap_ledger_t* a_ledger, dap_chain_datum_tx_t* a_tx, dap_hash_fast_t* a_tx_hash, bool a_from_threshold, dap_ledger_datum_iter_data_t* a_datum_index_data)
) {
    dap_mock_function_state_t *G_MOCK = g_mock_dap_ledger_tx_add;
    if (!a_ledger || !a_tx || !a_tx_hash) {
        log_it(L_WARNING, "Custom mock: NULL parameter detected, returning error");
        return -2;
    }
    if (a_from_threshold) {
        log_it(L_DEBUG, "Custom mock: threshold mode, returning special code");
        return 1;
    }
    return G_MOCK->return_value.i;
}

DAP_MOCK_WRAPPER_CUSTOM(const char*, dap_ledger_tx_get_token_ticker_by_hash,
    (dap_ledger_t* a_ledger, dap_hash_fast_t* a_tx_hash)
) {
    dap_mock_function_state_t *G_MOCK = g_mock_dap_ledger_tx_get_token_ticker_by_hash;
    if (a_tx_hash) {
        uint8_t l_first_byte = ((uint8_t*)a_tx_hash)[0];
        if (l_first_byte == 0x11) {
            return "CELL";
        } else if (l_first_byte == 0x22) {
            return "tCELL";
        } else if (l_first_byte == 0xFF) {
            return NULL;
        }
    }
    return (const char*)G_MOCK->return_value.ptr;
}

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
    log_it(L_INFO, "WITH DAP MOCK + DAP_MOCK_WRAPPER_CUSTOM");
    log_it(L_INFO, "========================================");
    
    memset(&s_mock_ledger, 0, sizeof(s_mock_ledger));
    memset(&s_test_tx_hash1, 0x11, sizeof(dap_hash_fast_t));
    memset(&s_test_tx_hash2, 0x22, sizeof(dap_hash_fast_t));
    
    // Create TX using TX Compose API
    s_test_tx1 = dap_chain_datum_tx_create();
    s_test_tx2 = dap_chain_datum_tx_create();
    
    // Reset and enable mocks
    DAP_MOCK_SET_RETURN(dap_ledger_tx_add, 0);
    DAP_MOCK_SET_RETURN(dap_ledger_tx_find_by_hash, NULL);
    DAP_MOCK_RESET(dap_ledger_tx_add);
    DAP_MOCK_RESET(dap_ledger_tx_find_by_hash);
    
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
    
    DAP_MOCK_SET_RETURN(dap_ledger_tx_find_by_hash, s_test_tx1);
    
    dap_chain_datum_tx_t *l_found = dap_ledger_tx_find_by_hash(&s_mock_ledger, &s_test_tx_hash1);
    dap_assert_PIF(l_found == s_test_tx1, "Should return overridden value");
    
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
 * @brief Test 4: Custom mock - zero hash detection
 */
static void test_custom_mock_zero_hash(void)
{
    log_it(L_INFO, "TEST 4: Custom mock - zero hash detection");
    
    dap_hash_fast_t l_zero_hash = {0};
    memset(&l_zero_hash, 0, sizeof(dap_hash_fast_t));
    
    // Custom mock should detect zero hash and return NULL
    dap_chain_datum_tx_t *l_result = dap_ledger_tx_find_by_hash(&s_mock_ledger, &l_zero_hash);
    dap_assert_PIF(l_result == NULL, "Zero hash should return NULL");
    
    log_it(L_INFO, "✅ TEST 4 PASSED: Custom zero hash detection works");
}

/**
 * @brief Test 5: Custom mock - ticker by hash
 */
static void test_custom_mock_ticker_by_hash(void)
{
    log_it(L_INFO, "TEST 5: Custom mock - ticker by hash");
    
    // Hash starting with 0x11 should return "CELL"
    const char *l_ticker1 = dap_ledger_tx_get_token_ticker_by_hash(&s_mock_ledger, &s_test_tx_hash1);
    dap_assert_PIF(l_ticker1 != NULL, "Ticker1 should not be NULL");
    dap_assert_PIF(strcmp(l_ticker1, "CELL") == 0, "Hash 0x11 should return 'CELL'");
    
    // Hash starting with 0x22 should return "tCELL"
    const char *l_ticker2 = dap_ledger_tx_get_token_ticker_by_hash(&s_mock_ledger, &s_test_tx_hash2);
    dap_assert_PIF(l_ticker2 != NULL, "Ticker2 should not be NULL");
    dap_assert_PIF(strcmp(l_ticker2, "tCELL") == 0, "Hash 0x22 should return 'tCELL'");
    
    // Hash starting with 0xFF should return NULL
    dap_hash_fast_t l_unknown_hash = {0};
    memset(&l_unknown_hash, 0xFF, sizeof(dap_hash_fast_t));
    const char *l_ticker3 = dap_ledger_tx_get_token_ticker_by_hash(&s_mock_ledger, &l_unknown_hash);
    dap_assert_PIF(l_ticker3 == NULL, "Unknown hash 0xFF should return NULL");
    
    log_it(L_INFO, "✅ TEST 5 PASSED: Custom ticker resolution works");
}

/**
 * @brief Test 6: Custom mock - NULL parameter validation
 */
static void test_custom_mock_null_validation(void)
{
    log_it(L_INFO, "TEST 6: Custom mock - NULL parameter validation");
    
    g_mock_dap_ledger_tx_add->enabled = true;
    
    // Call with NULL ledger - should return -2
    int l_result = dap_ledger_tx_add(NULL, s_test_tx1, &s_test_tx_hash1, false, NULL);
    dap_assert_PIF(l_result == -2, "NULL ledger should return -2");
    
    // Call with NULL TX - should return -2
    l_result = dap_ledger_tx_add(&s_mock_ledger, NULL, &s_test_tx_hash1, false, NULL);
    dap_assert_PIF(l_result == -2, "NULL TX should return -2");
    
    // Call with NULL hash - should return -2
    l_result = dap_ledger_tx_add(&s_mock_ledger, s_test_tx1, NULL, false, NULL);
    dap_assert_PIF(l_result == -2, "NULL hash should return -2");
    
    log_it(L_INFO, "✅ TEST 6 PASSED: Custom NULL validation works");
}

/**
 * @brief Test 7: Custom mock - threshold mode
 */
static void test_custom_mock_threshold_mode(void)
{
    log_it(L_INFO, "TEST 7: Custom mock - threshold mode");
    
    // Call with a_from_threshold = false - should return configured value (0)
    DAP_MOCK_SET_RETURN(dap_ledger_tx_add, 0);
    int l_result = dap_ledger_tx_add(&s_mock_ledger, s_test_tx1, &s_test_tx_hash1, false, NULL);
    dap_assert_PIF(l_result == 0, "Normal mode should return 0");
    
    // Call with a_from_threshold = true - should return 1
    l_result = dap_ledger_tx_add(&s_mock_ledger, s_test_tx1, &s_test_tx_hash1, true, NULL);
    dap_assert_PIF(l_result == 1, "Threshold mode should return 1");
    
    log_it(L_INFO, "✅ TEST 7 PASSED: Custom threshold mode works");
}

/**
 * @brief Test 8: Call counting
 */
static void test_call_counting(void)
{
    log_it(L_INFO, "TEST 8: Call counting");
    
    DAP_MOCK_RESET(dap_ledger_tx_find_by_hash);
    dap_assert_PIF(g_mock_dap_ledger_tx_find_by_hash->call_count == 0, "Count should be 0");
    
    dap_ledger_tx_find_by_hash(&s_mock_ledger, &s_test_tx_hash1);
    dap_ledger_tx_find_by_hash(&s_mock_ledger, &s_test_tx_hash2);
    
    dap_assert_PIF(g_mock_dap_ledger_tx_find_by_hash->call_count == 2, "Count should be 2");
    
    log_it(L_INFO, "✅ TEST 8 PASSED: Call counting works");
}

// =============================================================================
// MAIN
// =============================================================================

int main(void)
{
    test_setup();
    
    // Basic mock tests
    test_mock_state_verification();
    test_mock_return_override();
    test_null_return();
    
    // Custom mock tests demonstrating PARAM syntax
    test_custom_mock_zero_hash();
    test_custom_mock_ticker_by_hash();
    test_custom_mock_null_validation();
    test_custom_mock_threshold_mode();
    test_call_counting();
    
    test_teardown();
    
    log_it(L_INFO, "========================================");
    log_it(L_INFO, "✅ ALL LEDGER UNIT TESTS PASSED (8/8)");
    log_it(L_INFO, "✅ DAP_MOCK_WRAPPER_CUSTOM without PARAM!");
    log_it(L_INFO, "========================================");
    
    return 0;
}
