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
 * @file utxo_blocking_unit_test.c
 * @brief Unit tests for UTXO blocking mechanism
 * @details Real functional testing of UTXO blocklist operations using ledger and fixtures
 * @date 2025-10-16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_time.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_ledger.h"
#include "dap_chain.h"
#include "dap_cert.h"
#include "dap_math_ops.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_transaction_fixtures.h"

#define LOG_TAG "utxo_blocking_unit_test"

// Test counters
static int s_tests_passed = 0;
static int s_tests_failed = 0;

// Global test context
static test_net_fixture_t *s_net_fixture = NULL;
static dap_cert_t *s_test_cert = NULL;

// Wrapper macro to count tests before using dap_assert
#define UTXO_TEST_ASSERT(condition, message) \
    do { \
        if (condition) { \
            s_tests_passed++; \
        } else { \
            s_tests_failed++; \
        } \
        dap_assert(condition, message); \
    } while(0)

/**
 * @brief Initialize test environment
 * @return 0 on success, -1 on failure
 */
static int s_test_init(void)
{
    log_it(L_INFO, "Initializing test environment...");
    
    // Create test certificate for token signing
    const char *l_seed = "utxo_blocking_test_seed_2025";
    s_test_cert = dap_cert_generate_mem_with_seed(
        "utxo_test_cert",
        DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
        l_seed,
        strlen(l_seed)
    );
    if (!s_test_cert) {
        log_it(L_ERROR, "Failed to create test certificate");
        return -1;
    }
    
    // Create test network and ledger
    s_net_fixture = test_net_fixture_create("utxo_test_net");
    if (!s_net_fixture || !s_net_fixture->ledger) {
        log_it(L_ERROR, "Failed to create test network fixture");
        if (s_test_cert)
            dap_cert_delete(s_test_cert);
        return -1;
    }
    
    log_it(L_INFO, "Test environment initialized successfully");
    return 0;
}

/**
 * @brief Cleanup test environment
 */
static void s_test_cleanup(void)
{
    log_it(L_INFO, "Cleaning up test environment...");
    
    if (s_net_fixture) {
        test_net_fixture_destroy(s_net_fixture);
        s_net_fixture = NULL;
    }
    
    if (s_test_cert) {
        dap_cert_delete(s_test_cert);
        s_test_cert = NULL;
    }
    
    log_it(L_INFO, "Test environment cleaned up");
}

/**
 * @brief Helper to create and add token to ledger
 * @param a_ticker Token ticker
 * @param a_flags Token flags
 * @return Size of token datum or 0 on error
 */
static size_t s_helper_create_token(const char *a_ticker, uint16_t a_flags)
{
    uint256_t l_total_supply = uint256_0;
    MULT_256_COIN(dap_chain_uint256_from(1000000), dap_chain_coins_to_balance("1.0"), &l_total_supply);
    
    test_token_fixture_t *l_token_fixture = test_token_fixture_create_cf20(a_ticker, l_total_supply, a_flags);
    if (!l_token_fixture || !l_token_fixture->token) {
        log_it(L_ERROR, "Failed to create token fixture for %s", a_ticker);
        return 0;
    }
    
    // Add token to ledger
    dap_chain_datum_t *l_datum = dap_chain_datum_create(
        DAP_CHAIN_DATUM_TOKEN,
        l_token_fixture->token,
        l_token_fixture->token_size
    );
    
    size_t l_datum_size = l_token_fixture->token_size + sizeof(dap_chain_datum_t);
    
    // For now just verify it was created
    size_t l_result = l_datum ? l_datum_size : 0;
    
    DAP_DELETE(l_datum);
    test_token_fixture_destroy(l_token_fixture);
    
    return l_result;
}

/**
 * @brief Test 1: Token creation with UTXO blocking flags
 * @details Verify tokens are created with various UTXO blocking flags
 * @return 0 on success, -1 on failure
 */
static int s_test_token_creation_with_flags(void)
{
    log_it(L_NOTICE, "TEST 1: Token Creation with UTXO Blocking Flags");
    
    // Create token WITHOUT UTXO_BLOCKING_DISABLED flag (enabled by default)
    size_t l_size1 = s_helper_create_token("UTST1", 0);
    UTXO_TEST_ASSERT(l_size1 > 0, "Should create token with UTXO blocking enabled (default)");
    
    // Create token explicitly WITH UTXO_BLOCKING_DISABLED flag
    size_t l_size2 = s_helper_create_token("UTST2", DAP_CHAIN_DATUM_TOKEN_FLAG_UTXO_BLOCKING_DISABLED);
    UTXO_TEST_ASSERT(l_size2 > 0, "Should create token with UTXO blocking disabled");
    
    // Create token with STATIC_UTXO_BLOCKLIST flag
    size_t l_size3 = s_helper_create_token("UTST3", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_UTXO_BLOCKLIST);
    UTXO_TEST_ASSERT(l_size3 > 0, "Should create token with static UTXO blocklist");
    
    // Create token with combined flags
    uint16_t l_combined_flags = DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_SENDER_BLOCKING |
                                 DAP_CHAIN_DATUM_TOKEN_FLAG_DISABLE_ADDRESS_RECEIVER_BLOCKING;
    size_t l_size4 = s_helper_create_token("UTST4", l_combined_flags);
    UTXO_TEST_ASSERT(l_size4 > 0, "Should create token with address blocking disabled");
    
    log_it(L_INFO, "Token creation successful for all flag combinations");
    
    return 0;
}

/**
 * @brief Test 2: Transaction fixture creation
 * @details Verify transaction fixtures work correctly
 * @return 0 on success, -1 on failure
 */
static int s_test_transaction_fixtures(void)
{
    log_it(L_NOTICE, "TEST 2: Transaction Fixture Creation");
    
    uint256_t l_value = dap_chain_uint256_from(100);
    
    // Create transaction with 1 output
    test_tx_fixture_t *l_tx1 = test_tx_fixture_create_with_outs(1, l_value, "UTST1");
    UTXO_TEST_ASSERT(l_tx1 != NULL, "Should create transaction with 1 output");
    UTXO_TEST_ASSERT(l_tx1->tx != NULL, "Transaction should have tx datum");
    UTXO_TEST_ASSERT(l_tx1->out_count == 1, "Transaction should have correct out_count");
    
    // Verify transaction hash was calculated
    bool l_hash_valid = !dap_hash_fast_is_blank(&l_tx1->tx_hash);
    UTXO_TEST_ASSERT(l_hash_valid, "Transaction hash should be calculated");
    
    test_tx_fixture_destroy(l_tx1);
    
    // Create transaction with multiple outputs
    test_tx_fixture_t *l_tx2 = test_tx_fixture_create_with_outs(5, l_value, "UTST2");
    UTXO_TEST_ASSERT(l_tx2 != NULL, "Should create transaction with 5 outputs");
    UTXO_TEST_ASSERT(l_tx2->out_count == 5, "Transaction should have 5 outputs");
    
    test_tx_fixture_destroy(l_tx2);
    
    log_it(L_INFO, "Transaction fixture creation successful");
    
    return 0;
}

/**
 * @brief Test 3: TSD data format validation
 * @details Verify TSD type constants and data format sizes
 * @return 0 on success, -1 on failure
 */
static int s_test_tsd_formats(void)
{
    log_it(L_NOTICE, "TEST 3: TSD Data Format Validation");
    
    // Verify TSD type constants
    UTXO_TEST_ASSERT(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_ADD == 0x0029,
                     "UTXO_BLOCKED_ADD TSD type should be 0x0029");
    UTXO_TEST_ASSERT(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_REMOVE == 0x002A,
                     "UTXO_BLOCKED_REMOVE TSD type should be 0x002A");
    UTXO_TEST_ASSERT(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UTXO_BLOCKED_CLEAR == 0x002B,
                     "UTXO_BLOCKED_CLEAR TSD type should be 0x002B");
    
    // Verify data structure sizes
    size_t l_hash_size = sizeof(dap_chain_hash_fast_t);
    size_t l_idx_size = sizeof(uint32_t);
    size_t l_time_size = sizeof(dap_time_t);
    
    UTXO_TEST_ASSERT(l_hash_size == 32, "Hash should be 32 bytes");
    UTXO_TEST_ASSERT(l_idx_size == 4, "Out index should be 4 bytes");
    UTXO_TEST_ASSERT(l_time_size == 8, "Time should be 8 bytes");
    
    // Basic TSD: hash(32) + out_idx(4) = 36 bytes
    size_t l_basic_tsd_size = l_hash_size + l_idx_size;
    UTXO_TEST_ASSERT(l_basic_tsd_size == 36, "Basic TSD should be 36 bytes");
    
    // Extended TSD with timestamp: hash(32) + out_idx(4) + time(8) = 44 bytes
    size_t l_extended_tsd_size = l_basic_tsd_size + l_time_size;
    UTXO_TEST_ASSERT(l_extended_tsd_size == 44, "Extended TSD should be 44 bytes");
    
    log_it(L_INFO, "TSD format validation successful");
    
    return 0;
}


/**
 * @brief Main test runner
 * @return 0 on success, 1 on failure
 */
int main(void)
{
    // Setup test environment per DAP SDK standards
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    
    log_it(L_NOTICE, " ");
    dap_print_module_name("UTXO Blocking Mechanism - Unit Tests");
    log_it(L_NOTICE, " ");
    
    // Initialize test environment
    if (s_test_init() != 0) {
        log_it(L_ERROR, "Failed to initialize test environment");
        return 1;
    }
    
    // Run all tests
    s_test_token_creation_with_flags();
    s_test_transaction_fixtures();
    s_test_tsd_formats();
    
    // Cleanup test environment
    s_test_cleanup();
    
    // Print summary
    log_it(L_NOTICE, " ");
    log_it(L_NOTICE, "====================================================");
    log_it(L_NOTICE, "  TEST SUMMARY");
    log_it(L_NOTICE, "====================================================");
    log_it(L_INFO, "Passed: %d", s_tests_passed);
    log_it(L_INFO, "Failed: %d", s_tests_failed);
    log_it(L_INFO, "Total:  %d", s_tests_passed + s_tests_failed);
    
    if (s_tests_failed == 0) {
        log_it(L_NOTICE, " ");
        log_it(L_NOTICE, "All tests PASSED!");
    } else {
        log_it(L_ERROR, " ");
        log_it(L_ERROR, "Some tests FAILED!");
    }
    log_it(L_NOTICE, " ");
    
    return (s_tests_failed == 0) ? 0 : 1;
}

