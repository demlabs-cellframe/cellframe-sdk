/**
 * @file test_token_fixtures.h
 * @brief Test fixtures for CF20 tokens
 * @details Provides helper functions for creating test tokens
 * 
 * @author Cellframe Team
 * @date 2025-01-16
 */

#pragma once

#include "dap_chain_datum_token.h"
#include "dap_chain_ledger.h"
#include "test_ledger_fixtures.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Test token fixture structure
 */
typedef struct test_token_fixture {
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    char *token_ticker;
    dap_chain_datum_token_t *token;
    size_t token_size;
    uint16_t flags;
    dap_cert_t *owner_cert;
} test_token_fixture_t;

/**
 * @brief Create test token and add to ledger
 * @param a_ledger Ledger to add token to
 * @param a_ticker Token ticker
 * @param a_total_supply_str Total supply as string
 * @return Created token fixture or NULL on error
 */
test_token_fixture_t *test_token_fixture_create(
    dap_ledger_t *a_ledger,
    const char *a_ticker,
    const char *a_total_supply_str
);

/**
 * @brief Create test CF20 token
 * @param a_ticker Token ticker
 * @param a_total_supply Total supply
 * @param a_flags Token flags
 * @return Created token fixture or NULL on error
 */
test_token_fixture_t *test_token_fixture_create_cf20(
    const char *a_ticker,
    uint256_t a_total_supply,
    uint32_t a_flags
);

/**
 * @brief Create test CF20 token with UTXO blocking enabled
 * @param a_ticker Token ticker
 * @param a_total_supply Total supply
 * @return Created token fixture or NULL on error
 */
test_token_fixture_t *test_token_fixture_create_with_utxo_blocking(
    const char *a_ticker,
    uint256_t a_total_supply
);

/**
 * @brief Create token with emission automatically
 * @param a_ledger Ledger to add token and emission to
 * @param a_ticker Token ticker
 * @param a_total_supply_str Total supply as string
 * @param a_emission_value_str Emission value as string (can be same as total supply)
 * @param a_addr Emission address
 * @param a_emission_hash_out Output parameter for emission hash (can be NULL)
 * @return Created token fixture or NULL on error
 * 
 * @note This function:
 *       1. Creates token using test_token_fixture_create()
 *       2. Creates emission using test_emission_fixtures
 *       3. Adds emission to ledger
 *       4. Returns token fixture with owner_cert for further operations
 * @note Uses ONLY public API (via test_emission_fixtures)
 */
test_token_fixture_t *test_token_fixture_create_with_emission(
    dap_ledger_t *a_ledger,
    const char *a_ticker,
    const char *a_total_supply_str,
    const char *a_emission_value_str,
    dap_chain_addr_t *a_addr,
    dap_cert_t *a_emission_cert,
    dap_chain_hash_fast_t *a_emission_hash_out
);

/**
 * @brief Cleanup token fixture
 * @param a_fixture Fixture to cleanup
 */
void test_token_fixture_destroy(test_token_fixture_t *a_fixture);

#ifdef __cplusplus
}
#endif

