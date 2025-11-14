/**
 * @file utxo_blocking_integration_test.c
 * @brief Main entry point for UTXO blocking integration tests
 * @details Orchestrates all UTXO blocking and arbitrage transaction tests
 * @date 2025-01-16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>
#include "dap_common.h"
#include "dap_config.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"
#include "dap_chain_ledger.h"
#include "dap_test.h"
#include "test_ledger_fixtures.h"
#include "utxo_blocking_test_helpers.h"
#include "utxo_blocking_basic_tests.h"
#include "utxo_blocking_arbitrage_tests.h"

#define LOG_TAG "utxo_blocking_integration"

// Global test context (shared across all test modules)
test_net_fixture_t *s_net_fixture = NULL;

/**
 * @brief Setup: Initialize test environment
 */
static void s_setup(void)
{
    log_it(L_NOTICE, "=== UTXO Blocking Integration Tests Setup ===");
    
    // Step 0: Clean up from previous runs (critical for CI where tests may not cleanup properly)
    system("rm -rf /tmp/intg_test_gdb");
    system("rm -rf /tmp/intg_test_certs");
    system("rm -rf /tmp/intg_test_config");
    
    // Step 1: Create minimal config for ledger debug
    const char *l_config_dir = "/tmp/intg_test_config";
    mkdir(l_config_dir, 0755);
    
    const char *l_config_content = 
        "[general]\n"
        "debug=true\n"
        "[ledger]\n"
        "debug_more=true\n"
        "[global_db]\n"
        "driver=mdbx\n"
        "path=/tmp/intg_test_gdb\n"
        "debug_more=false\n"
        "[resources]\n"
        "ca_folders=/tmp/intg_test_certs\n";
    
    char l_config_path[256];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", l_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if (l_config_file) {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    
    // Create certificate folder
    mkdir("/tmp/intg_test_certs", 0755);
    
    // Step 2: Initialize test environment (config, certs, global DB, events, proc threads)
    int l_env_res = test_env_init(l_config_dir, "/tmp/intg_test_gdb");
    dap_assert(l_env_res == 0, "Test environment initialization");
    
    // Step 3: Initialize ledger (reads debug_more from config)
    dap_ledger_init();
    
    // Step 4: Initialize consensus modules (using 'none' consensus in fixtures)
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_nonconsensus_init(); // Required for 'none' consensus
    
    // Step 5: Create test network
    s_net_fixture = test_net_fixture_create("intg_test_net");
    dap_assert(s_net_fixture != NULL, "Network fixture initialization");
    dap_assert(s_net_fixture->ledger != NULL, "Ledger initialization");
    
    log_it(L_NOTICE, "✓ Test environment initialized");
}

/**
 * @brief Teardown: Cleanup test environment
 */
static void s_teardown(void)
{
    if (s_net_fixture) {
        test_net_fixture_destroy(s_net_fixture);
        s_net_fixture = NULL;
    }
    
    // Clean up test environment (global DB, certs, events, proc threads)
    test_env_deinit();
    
    // Remove test files
    unlink("/tmp/intg_test_config/test.cfg");
    rmdir("/tmp/intg_test_config");
    system("rm -rf /tmp/intg_test_gdb");
    system("rm -rf /tmp/intg_test_certs");
    
    log_it(L_NOTICE, "✓ Test environment cleaned up");
}

int main(void)
{
    // Initialize logging output FIRST - BEFORE any log_it calls
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    
    // Initialize logging level
    dap_log_level_set(L_DEBUG);
    
    dap_print_module_name("UTXO Blocking Integration Tests");
    
    // Setup
    s_setup();
    
    // Run all integration tests
    int l_test_count = 0;
    
    // Basic UTXO blocking tests (Tests 1-6)
    utxo_blocking_test_full_utxo_blocking_lifecycle();              l_test_count++; // Test 1: Full lifecycle
    utxo_blocking_test_utxo_unblocking();                           l_test_count++; // Test 2: Unblocking
    utxo_blocking_test_delayed_activation();                        l_test_count++; // Test 3: Delayed activation
    utxo_blocking_test_utxo_clear_operation();                      l_test_count++; // Test 4: CLEAR operation
    utxo_blocking_test_irreversible_flags();                        l_test_count++; // Test 5: Irreversible flags
    utxo_blocking_test_utxo_blocking_disabled_behaviour();           l_test_count++; // Test 6: UTXO_BLOCKING_DISABLED flag
    
    // Arbitrage transaction tests (Tests 7-14)
    utxo_blocking_test_arbitrage_validation();                      l_test_count++; // Test 7: Arbitrage transaction validation
    utxo_blocking_test_arbitrage_disabled_flag();                   l_test_count++; // Test 8: Arbitrage disabled flag
    utxo_blocking_test_arbitrage_no_fee_address();                  l_test_count++; // Test 9: Arbitrage without fee address
    utxo_blocking_test_arbitrage_bypasses_address_blocking();        l_test_count++; // Test 10: Arbitrage bypasses address blocking
    utxo_blocking_test_arbitrage_without_emission_owner_signature(); l_test_count++; // Test 11: Arbitrage without emission owner signature
    utxo_blocking_test_arbitrage_without_token_owner_signature();    l_test_count++; // Test 12: Arbitrage without token owner signature
    utxo_blocking_test_arbitrage_multiple_outputs_mixed_addresses(); l_test_count++; // Test 13: Arbitrage with multiple outputs (mixed)
    utxo_blocking_test_arbitrage_without_tsd_marker();              l_test_count++; // Test 14: Arbitrage without TSD marker
    
    // Teardown
    s_teardown();
    
    log_it(L_NOTICE, "✅ All UTXO blocking integration tests completed (%d tests)!", l_test_count);
    
    return 0;
}
