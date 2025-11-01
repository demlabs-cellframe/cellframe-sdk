/**
 * @file test_ledger_fixtures.h
 * @brief Test fixtures for ledger initialization and cleanup
 * @details Provides helper functions for setting up test environments
 * 
 * @author Cellframe Team
 * @date 2025-01-16
 */

#pragma once

#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain.h"
#include "dap_test.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Test network fixture structure
 */
typedef struct test_net_fixture {
    dap_chain_net_t *net;
    dap_ledger_t *ledger;
    dap_chain_t *chain_zero;       ///< Zero chain (like in production networks)
    dap_chain_t *chain_main;        ///< Master/main chain (like in production networks)
    char *net_name;
} test_net_fixture_t;

/**
 * @brief Initialize test network and ledger
 * @param a_net_name Test network name
 * @return Initialized fixture or NULL on error
 */
test_net_fixture_t *test_net_fixture_create(const char *a_net_name);

/**
 * @brief Cleanup test network and ledger
 * @param a_fixture Fixture to cleanup
 */
void test_net_fixture_destroy(test_net_fixture_t *a_fixture);

/**
 * @brief Get first emission hash for token (for testing)
 * @param a_ledger Ledger instance
 * @param a_token_ticker Token ticker
 * @param a_emission_hash Output emission hash
 * @return true if emission found, false otherwise
 * @note This function uses internal ledger structures for testing purposes
 */
bool test_ledger_get_token_emission_hash(dap_ledger_t *a_ledger, 
                                          const char *a_token_ticker,
                                          dap_chain_hash_fast_t *a_emission_hash);

#ifdef __cplusplus
}
#endif

