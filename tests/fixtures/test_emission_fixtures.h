/**
 * @file test_emission_fixtures.h
 * @brief Test fixtures for token emission management
 * @details Provides helper functions for creating and managing token emissions in tests.
 *          All functions use ONLY public ledger API - no access to internal structures.
 * 
 * @date 2025-10-16
 * @copyright Copyright (c) 2017-2025 Demlabs Ltd. All rights reserved.
 */

#ifndef TEST_EMISSION_FIXTURES_H
#define TEST_EMISSION_FIXTURES_H

#include "dap_chain_datum_token.h"
#include "dap_chain_ledger.h"
#include "dap_cert.h"
#include "dap_enc_key.h"
#include "dap_math_ops.h"

/**
 * @brief Emission test fixture structure
 * @details Contains all data needed for emission testing
 */
typedef struct test_emission_fixture {
    dap_chain_datum_token_emission_t *emission;  ///< Emission datum
    dap_chain_hash_fast_t emission_hash;         ///< Emission hash
    size_t emission_size;                        ///< Emission size in bytes
    char *token_ticker;                          ///< Token ticker (owned)
    dap_chain_addr_t *addr;                      ///< Emission address (owned)
    dap_cert_t *cert;                            ///< Certificate for signing (owned)
} test_emission_fixture_t;

/**
 * @brief Create emission fixture with simple parameters
 * @param a_token_ticker Token ticker
 * @param a_value_str Emission value as string (e.g. "1000.0")
 * @param a_addr Emission address
 * @param a_sign If true, creates and signs with test certificate
 * @return Emission fixture or NULL on error
 * 
 * @note Caller must call test_emission_fixture_destroy() to free resources
 * @note Uses dap_chain_datum_emission_create() and dap_chain_datum_emission_add_sign()
 */
test_emission_fixture_t *test_emission_fixture_create_simple(
    const char *a_token_ticker,
    const char *a_value_str,
    dap_chain_addr_t *a_addr,
    bool a_sign
);

/**
 * @brief Create emission fixture with certificate
 * @param a_token_ticker Token ticker
 * @param a_value Emission value as uint256_t
 * @param a_addr Emission address
 * @param a_cert Certificate for signing (will be cloned internally)
 * @return Emission fixture or NULL on error
 * 
 * @note Caller must call test_emission_fixture_destroy() to free resources
 * @note Uses dap_chain_datum_emission_create() and dap_chain_datum_emission_add_sign()
 */
test_emission_fixture_t *test_emission_fixture_create_with_cert(
    const char *a_token_ticker,
    uint256_t a_value,
    dap_chain_addr_t *a_addr,
    dap_cert_t *a_cert
);

/**
 * @brief Add emission to ledger
 * @param a_ledger Ledger instance
 * @param a_fixture Emission fixture
 * @return Ledger error code (0 = success)
 * 
 * @note Uses ONLY public API: dap_ledger_token_emission_add()
 * @note Does not modify internal ledger structures
 */
int test_emission_fixture_add_to_ledger(
    dap_ledger_t *a_ledger,
    test_emission_fixture_t *a_fixture
);

/**
 * @brief Destroy emission fixture and free all resources
 * @param a_fixture Emission fixture to destroy
 * 
 * @note Safe to call with NULL
 */
void test_emission_fixture_destroy(test_emission_fixture_t *a_fixture);

/**
 * @brief Get emission hash from fixture
 * @param a_fixture Emission fixture
 * @param a_hash_out Output parameter for hash
 * @return true if hash retrieved, false if fixture invalid
 */
bool test_emission_fixture_get_hash(
    test_emission_fixture_t *a_fixture,
    dap_chain_hash_fast_t *a_hash_out
);

#endif // TEST_EMISSION_FIXTURES_H

