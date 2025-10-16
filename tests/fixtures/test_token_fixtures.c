/**
 * @file test_token_fixtures.c
 * @brief Implementation of token test fixtures
 */

#include "test_token_fixtures.h"
#include "dap_common.h"

#define LOG_TAG "test_token_fixtures"

test_token_fixture_t *test_token_fixture_create_cf20(
    const char *a_ticker,
    uint256_t a_total_supply,
    uint16_t a_flags)
{
    if (!a_ticker) {
        log_it(L_ERROR, "Token ticker is NULL");
        return NULL;
    }

    test_token_fixture_t *l_fixture = DAP_NEW_Z(test_token_fixture_t);
    if (!l_fixture) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }

    dap_strncpy(l_fixture->ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    l_fixture->flags = a_flags;
    
    // TODO: Create actual token datum (placeholder)
    // l_fixture->token = dap_chain_datum_token_create_cf20(...);
    // l_fixture->token_size = dap_chain_datum_token_get_size(l_fixture->token);
    
    log_it(L_INFO, "Test CF20 token fixture created: %s", a_ticker);
    return l_fixture;
}

test_token_fixture_t *test_token_fixture_create_with_utxo_blocking(
    const char *a_ticker,
    uint256_t a_total_supply)
{
    // Create token with UTXO_BLOCKING_ENABLED flag (BIT(16))
    return test_token_fixture_create_cf20(a_ticker, a_total_supply, (1 << 16));
}

void test_token_fixture_destroy(test_token_fixture_t *a_fixture)
{
    if (!a_fixture)
        return;

    if (a_fixture->token)
        DAP_DELETE(a_fixture->token);
    
    DAP_DELETE(a_fixture);
    
    log_it(L_INFO, "Test token fixture destroyed");
}

