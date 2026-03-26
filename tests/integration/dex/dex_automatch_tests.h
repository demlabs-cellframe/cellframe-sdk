/**
 * @file dex_automatch_tests.h
 * @brief Auto-matcher tests for purchase_auto function
 */

#pragma once

#include "dex_test_scenarios.h"

// ============================================================================
// TEST TEMPLATE STRUCTURE
// ============================================================================

typedef struct {
    const char *name;           // "A01", "B02", etc.
    
    // Direction
    const char *sell_token;     // Token buyer spends
    const char *buy_token;      // Token buyer wants
    
    // Budget
    const char *budget;         // String representation, "0" for unlimited
    bool is_budget_buy;         // true = budget in buy_token
    
    // Rate filter
    const char *min_rate;       // "0" for no filter
    
    // Leftover
    bool create_leftover;
    const char *leftover_rate;  // Rate for leftover order
    
    // Expected results
    int expected_match_count;   // -1 = don't check
    const char *expected_exec_sell;
    const char *expected_exec_buy;
    bool expect_leftover_order;
    bool expect_cashback;
    int expected_error;         // 0 = success
    
    // Buyer wallet
    wallet_id_t buyer;          // WALLET_BOB, WALLET_CAROL, etc.
} automatch_test_template_t;

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * @brief Run all auto-matcher tests
 * @param f Test fixture with seeded orderbook
 * @return 0 on success, negative on failure
 */
int run_automatch_tests(dex_test_fixture_t *f);

/**
 * @brief Run single automatch test with rollback
 * @param f Test fixture
 * @param tmpl Test template
 * @return 0 on success
 */
int run_automatch_test(dex_test_fixture_t *f, const automatch_test_template_t *tmpl);



