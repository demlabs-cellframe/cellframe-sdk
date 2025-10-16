/**
 * @file test_transaction_fixtures.c
 * @brief Implementation of transaction test fixtures
 */

#include "test_transaction_fixtures.h"
#include "dap_common.h"

#define LOG_TAG "test_transaction_fixtures"

test_tx_fixture_t *test_tx_fixture_create_with_outs(
    uint32_t a_out_count,
    uint256_t a_value_per_out,
    const char *a_token_ticker)
{
    if (!a_token_ticker || a_out_count == 0) {
        log_it(L_ERROR, "Invalid parameters");
        return NULL;
    }

    test_tx_fixture_t *l_fixture = DAP_NEW_Z(test_tx_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    l_fixture->out_count = a_out_count;
    
    // TODO: Create actual transaction with outputs (placeholder)
    // l_fixture->tx = dap_chain_datum_tx_create_with_outs(...);
    // dap_chain_datum_tx_calc_hash(l_fixture->tx, &l_fixture->tx_hash);
    
    log_it(L_INFO, "Test transaction fixture created with %u outputs", a_out_count);
    return l_fixture;
}

void test_tx_fixture_destroy(test_tx_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    if (a_fixture->tx)
        DAP_DELETE(a_fixture->tx);
    
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test transaction fixture destroyed");
}

