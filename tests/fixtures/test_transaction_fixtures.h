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
 * @brief Create simple test transaction (mock - not added to ledger)
 * @param a_ledger Ledger (unused in mock mode)
 * @param a_token_ticker Token ticker
 * @param a_value_str Value as string
 * @return Created transaction fixture or NULL on error
 * @note This creates a mock transaction for testing UTXO blocking without real inputs
 */
test_tx_fixture_t *test_tx_fixture_create_simple(
    dap_ledger_t *a_ledger,
    const char *a_token_ticker,
    const char *a_value_str
);

/**
 * @brief Create transaction from emission (real transaction)
 * @param a_ledger Ledger to query emission value
 * @param a_emission_hash Emission hash
 * @param a_token_ticker Token ticker
 * @param a_value_str Value as string (output amount, change calculated automatically)
 * @param a_addr_to Recipient address (also used for change)
 * @param a_cert Certificate for signing
 * @return Created transaction fixture or NULL on error
 * @note This creates a REAL transaction with IN_EMS input from emission
 * @note Automatically adds change output if emission value > requested value
 * @note Use test_tx_fixture_add_to_ledger() to add to ledger
 */
test_tx_fixture_t *test_tx_fixture_create_from_emission(
    dap_ledger_t *a_ledger,
    dap_chain_hash_fast_t *a_emission_hash,
    const char *a_token_ticker,
    const char *a_value_str,
    dap_chain_addr_t *a_addr_to,
    dap_cert_t *a_cert
);

/**
 * @brief Add transaction to ledger using public API
 * @param a_ledger Ledger instance
 * @param a_fixture Transaction fixture
 * @return Ledger error code (0 = success)
 * @note Uses ONLY public API: dap_ledger_tx_add()
 */
int test_tx_fixture_add_to_ledger(
    dap_ledger_t *a_ledger,
    test_tx_fixture_t *a_fixture
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

