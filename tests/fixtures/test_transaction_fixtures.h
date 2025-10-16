/**
 * @file test_transaction_fixtures.h
 * @brief Test fixtures for transactions and UTXO
 * @details Provides helper functions for creating test transactions
 * 
 * @author Cellframe Team
 * @date 2025-01-16
 */

#pragma once

#include "dap_chain_datum_tx.h"
#include "dap_chain_common.h"
#include "test_ledger_fixtures.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Test transaction fixture structure
 */
typedef struct test_tx_fixture {
    dap_chain_datum_tx_t *tx;
    dap_chain_hash_fast_t tx_hash;
    uint32_t out_count;
    dap_chain_addr_t *addr;  ///< Address for transaction outputs
} test_tx_fixture_t;

/**
 * @brief Create simple test transaction and add to ledger
 * @param a_ledger Ledger to add transaction to
 * @param a_token_ticker Token ticker
 * @param a_value_str Value as string
 * @return Created transaction fixture or NULL on error
 */
test_tx_fixture_t *test_tx_fixture_create_simple(
    dap_ledger_t *a_ledger,
    const char *a_token_ticker,
    const char *a_value_str
);

/**
 * @brief Create test transaction with outputs
 * @param a_out_count Number of outputs to create
 * @param a_value_per_out Value per output
 * @param a_token_ticker Token ticker
 * @return Created transaction fixture or NULL on error
 */
test_tx_fixture_t *test_tx_fixture_create_with_outs(
    uint32_t a_out_count,
    uint256_t a_value_per_out,
    const char *a_token_ticker
);

/**
 * @brief Cleanup transaction fixture
 * @param a_fixture Fixture to cleanup
 */
void test_tx_fixture_destroy(test_tx_fixture_t *a_fixture);

#ifdef __cplusplus
}
#endif

