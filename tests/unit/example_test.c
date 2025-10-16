/**
 * @file example_test.c
 * @brief Example unit test demonstrating test framework usage
 * @details This test demonstrates how to use dap_test.h framework
 * 
 * @author Cellframe Team
 * @date 2025-01-16
 */

#include "dap_test.h"
#include "dap_common.h"
#include "test_ledger_fixtures.h"

#define LOG_TAG "example_test"

/**
 * @brief Test basic fixture creation
 */
static void test_fixture_creation(void)
{
    dap_print_module_name("Fixture Creation");
    
    // Test network fixture creation
    test_net_fixture_t *l_fixture = test_net_fixture_create("test_net");
    dap_assert(l_fixture != NULL, "Network fixture created");
    dap_assert(l_fixture->net_name != NULL, "Network name set");
    dap_assert(dap_strcmp(l_fixture->net_name, "test_net") == 0, "Network name correct");
    
    // Cleanup
    test_net_fixture_destroy(l_fixture);
    dap_pass_msg("Fixture cleanup");
}

/**
 * @brief Test basic assertions
 */
static void test_basic_assertions(void)
{
    dap_print_module_name("Basic Assertions");
    
    dap_assert(1 == 1, "Integer equality");
    dap_assert(1 != 2, "Integer inequality");
    dap_assert(true, "Boolean true");
    dap_assert(!false, "Boolean false negation");
    
    const char *str1 = "hello";
    const char *str2 = "hello";
    dap_assert(dap_str_equals(str1, str2), "String equality");
}

/**
 * @brief Main test runner
 */
int main(void)
{
    // Initialize logging
    dap_log_level_set(L_DEBUG);
    
    printf("\n");
    printf("================================================\n");
    printf("  Cellframe SDK Example Test Suite\n");
    printf("================================================\n\n");
    
    // Run tests
    test_fixture_creation();
    test_basic_assertions();
    
    printf("\n");
    printf("================================================\n");
    printf("  All tests PASSED! ✓\n");
    printf("================================================\n\n");
    
    return 0;
}

