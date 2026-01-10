/**
 * @file dap_chain_tx_compose_test.c
 * @brief Unit tests for TX compose functionality
 * @details Tests TX composition with mock UTXO generation
 * @date 2026
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dap_test.h"
#include "dap_chain_tx_compose_api.h"
#include "dap_chain_ledger.h"
#include "dap_chain_utxo.h"
#include "dap_chain_datum_tx.h"
#include "dap_list.h"
#include "rand/dap_rand.h"

#define LOG_TAG "tx_compose_test"

/**
 * @brief Mock UTXO generator for TX compose testing
 * @details This mock was moved from production code (dap_chain_ledger_json.c)
 *          where it was under #ifdef DAP_CHAIN_TX_COMPOSE_TEST
 * 
 * @param a_count Number of random UTXOs to generate
 * @return List of mock dap_chain_tx_used_out_item_t items
 */
static dap_list_t *s_mock_generate_random_utxos(size_t a_count) {
    dap_list_t *l_ret = NULL;
    
    for (size_t i = 0; i < a_count; ++i) {
        dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
        if (!l_item) {
            log_it(L_ERROR, "Failed to allocate mock UTXO item");
            dap_list_free_full(l_ret, free);
            return NULL;
        }
        
        // Generate random data for testing
        randombytes(l_item, sizeof(dap_chain_tx_used_out_item_t));
        
        l_ret = dap_list_append(l_ret, l_item);
    }
    
    log_it(L_DEBUG, "Generated %zu mock UTXOs", a_count);
    return l_ret;
}

/**
 * @brief Test basic mock UTXO generation
 */
static void test_mock_utxo_generation(void) {
    log_it(L_INFO, "Testing mock UTXO generation...");
    
    // Generate 5 mock UTXOs
    dap_list_t *l_utxos = s_mock_generate_random_utxos(5);
    dap_assert_PIF(l_utxos != NULL, "Mock UTXO generation failed");
    
    // Check count
    size_t l_count = dap_list_length(l_utxos);
    dap_assert_PIF(l_count == 5, "Expected 5 UTXOs, got %zu", l_count);
    
    // Verify each item is allocated
    dap_list_t *l_iter = l_utxos;
    size_t l_idx = 0;
    while (l_iter) {
        dap_chain_tx_used_out_item_t *l_item = (dap_chain_tx_used_out_item_t *)l_iter->data;
        dap_assert_PIF(l_item != NULL, "UTXO item %zu is NULL", l_idx);
        l_iter = l_iter->next;
        l_idx++;
    }
    
    // Cleanup
    dap_list_free_full(l_utxos, free);
    
    dap_pass_msg("Mock UTXO generation successful");
}

/**
 * @brief Test mock UTXO generation with variable count
 */
static void test_mock_utxo_variable_count(void) {
    log_it(L_INFO, "Testing variable count mock UTXO generation...");
    
    // Test different counts
    size_t l_counts[] = {1, 10, 100};
    for (size_t i = 0; i < sizeof(l_counts) / sizeof(l_counts[0]); ++i) {
        dap_list_t *l_utxos = s_mock_generate_random_utxos(l_counts[i]);
        dap_assert_PIF(l_utxos != NULL, "Failed to generate %zu UTXOs", l_counts[i]);
        
        size_t l_actual_count = dap_list_length(l_utxos);
        dap_assert_PIF(l_actual_count == l_counts[i], 
                       "Expected %zu UTXOs, got %zu", l_counts[i], l_actual_count);
        
        dap_list_free_full(l_utxos, free);
    }
    
    dap_pass_msg("Variable count UTXO generation successful");
}

/**
 * @brief Test mock UTXO with zero count
 */
static void test_mock_utxo_zero_count(void) {
    log_it(L_INFO, "Testing zero count mock UTXO generation...");
    
    dap_list_t *l_utxos = s_mock_generate_random_utxos(0);
    dap_assert_PIF(l_utxos == NULL, "Expected NULL for zero count");
    
    dap_pass_msg("Zero count UTXO generation successful");
}

/**
 * @brief Run all TX compose tests
 */
int dap_chain_tx_compose_tests_run(void) {
    dap_print_module_name("TX Compose");
    
    // Initialize random number generator
    srand(time(NULL));
    
    test_mock_utxo_generation();
    test_mock_utxo_variable_count();
    test_mock_utxo_zero_count();
    
    return 0;
}
