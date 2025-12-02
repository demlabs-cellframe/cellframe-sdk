/**
 * @file dex_test_fixture.h
 * @brief Test fixture management for DEX integration tests
 * @details
 * Provides functions to create and manage the test environment:
 * network initialization, wallet creation, token emissions, and DEX configuration.
 * 
 * @author Cellframe Development Team
 * @date 2025
 */

#pragma once

#include "dex_test_common.h"

// ============================================================================
// FIXTURE MANAGEMENT API
// ============================================================================

/**
 * @brief Create test fixture with preconfigured network, wallets, and tokens
 * @return Pointer to fixture or NULL on failure
 */
dex_test_fixture_t* dex_test_fixture_create(void);

/**
 * @brief Destroy test fixture and cleanup resources
 * @param fixture Fixture to destroy
 */
void dex_test_fixture_destroy(dex_test_fixture_t *fixture);

/**
 * @brief Print current balances for debugging (reads directly from ledger)
 * @param f Fixture
 * @param label Label for log output
 */
void dex_print_balances(dex_test_fixture_t *f, const char *label);

