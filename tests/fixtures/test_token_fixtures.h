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
    uint16_t a_flags
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
 * @brief Cleanup token fixture
 * @param a_fixture Fixture to cleanup
 */
void test_token_fixture_destroy(test_token_fixture_t *a_fixture);

#ifdef __cplusplus
}
#endif

