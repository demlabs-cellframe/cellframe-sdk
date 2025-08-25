/**
 * @file test_concurrent_sessions.c
 * @date 22 Jan 2025
 * @author Cellframe Team
 * @details Simplified stress tests for concurrent billing sessions
 * 
 * Tests concurrent session handling with the simplified billing module.
 */

#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include "dap_common.h"
#include "dap_stream_ch_chain_net_srv_memory_manager.h"

#define LOG_TAG "billing_stress_test"

// Stress test configuration (reduced for simplified system)
#define STRESS_TEST_THREADS 4
#define STRESS_TEST_SESSIONS_PER_THREAD 50 
#define STRESS_TEST_OPERATIONS_PER_SESSION 10
#define STRESS_TEST_DURATION_SEC 30

// Test control variables
static volatile bool stress_test_stop = false;
static pthread_mutex_t stress_stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t stress_test_successes = 0;
static uint32_t stress_test_errors = 0;

/**
 * @brief Worker thread for stress testing concurrent sessions
 */
static void* stress_test_worker_thread(void* arg)
{
    int thread_id = *(int*)arg;
    uint32_t local_successes = 0;
    uint32_t local_errors = 0;
    
    for (int session = 0; session < STRESS_TEST_SESSIONS_PER_THREAD && !stress_test_stop; session++) {
        
        // Simplified session operations - no complex resource management
        for (int op = 0; op < STRESS_TEST_OPERATIONS_PER_SESSION && !stress_test_stop; op++) {
            
            // Test grace creation/destruction with simplified API
            dap_chain_net_srv_usage_t dummy_usage = {0};
            dap_hash_fast_t dummy_hash = {0};
            dummy_hash.raw[0] = thread_id;
            dummy_hash.raw[1] = session;
            dummy_hash.raw[2] = op;
            
            // Create grace item using simplified API
            dap_chain_net_srv_grace_usage_t* grace_item = dap_billing_grace_item_create_safe(&dummy_usage);
            if (grace_item) {
                
                // Brief operation simulation
                usleep(rand() % 100); // 0-100 microseconds
                
                // Cleanup using simplified API
                dap_memory_manager_result_t result = dap_billing_grace_item_destroy_safe(grace_item);
                if (result == DAP_MEMORY_MANAGER_SUCCESS) {
                    local_successes++;
                } else {
                    local_errors++;
                }
            } else {
                local_errors++;
            }
        }
    }
    
    // Update global statistics
    pthread_mutex_lock(&stress_stats_mutex);
    stress_test_successes += local_successes;
    stress_test_errors += local_errors;
    pthread_mutex_unlock(&stress_stats_mutex);
    
    log_it(L_DEBUG, "Thread %d completed: %u successes, %u errors", 
           thread_id, local_successes, local_errors);
    
    return NULL;
}

/**
 * @brief Simple stress test for basic memory operations
 */
static test_result_t test_stress_basic_memory_operations()
{
    log_it(L_INFO, "Starting basic memory stress test");
    
    // Initialize system
    TEST_ASSERT_EQUAL(0, dap_billing_memory_manager_init());
    
    const int num_allocations = 1000;
    dap_chain_net_srv_grace_usage_t** allocations = calloc(num_allocations, sizeof(void*));
    TEST_ASSERT_NOT_NULL(allocations);
    
    int successful_allocations = 0;
    int successful_deallocations = 0;
    
    // Allocate many grace items quickly
    for (int i = 0; i < num_allocations && !stress_test_stop; i++) {
        dap_chain_net_srv_usage_t dummy_usage = {0};
        allocations[i] = dap_billing_grace_item_create_safe(&dummy_usage);
        if (allocations[i] != NULL) {
            successful_allocations++;
        }
        
        // Occasionally free some to test concurrent alloc/free
        if (i % 10 == 9 && i > 20) {
            int free_index = i - 10;
            if (allocations[free_index] != NULL) {
                if (dap_billing_grace_item_destroy_safe(allocations[free_index]) == DAP_MEMORY_MANAGER_SUCCESS) {
                    successful_deallocations++;
                }
                allocations[free_index] = NULL;
            }
        }
    }
    
    // Clean up remaining allocations
    int freed_count = 0;
    for (int i = 0; i < num_allocations; i++) {
        if (allocations[i] != NULL) {
            if (dap_billing_grace_item_destroy_safe(allocations[i]) == DAP_MEMORY_MANAGER_SUCCESS) {
                freed_count++;
            }
        }
    }
    
    log_it(L_INFO, "Memory stress test completed: %d allocs, %d deallocs, %d final freed", 
           successful_allocations, successful_deallocations, freed_count);
    
    TEST_ASSERT(successful_allocations > num_allocations * 0.9); // 90% success rate
    
    free(allocations);
    dap_billing_memory_manager_deinit();
    return TEST_RESULT_PASS;
}

/**
 * @brief Simplified concurrent sessions stress test
 */
static test_result_t test_stress_concurrent_sessions()
{
    log_it(L_INFO, "Starting simplified concurrent sessions stress test");
    
    TEST_ASSERT_EQUAL(0, dap_billing_memory_manager_init());
    
    // Reset global stats
    stress_test_successes = 0;
    stress_test_errors = 0;
    stress_test_stop = false;
    
    pthread_t threads[STRESS_TEST_THREADS];
    int thread_ids[STRESS_TEST_THREADS];
    
    // Create worker threads
    for (int i = 0; i < STRESS_TEST_THREADS; i++) {
        thread_ids[i] = i;
        int rc = pthread_create(&threads[i], NULL, stress_test_worker_thread, &thread_ids[i]);
        TEST_ASSERT_EQUAL(0, rc);
    }
    
    // Let test run for specified duration
    sleep(STRESS_TEST_DURATION_SEC);
    stress_test_stop = true;
    
    // Wait for all threads to complete
    for (int i = 0; i < STRESS_TEST_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    log_it(L_INFO, "Stress test completed: %u total successes, %u total errors", 
           stress_test_successes, stress_test_errors);
    
    // Validate results - allow some errors but expect mostly successes
    TEST_ASSERT(stress_test_successes > 0);
    TEST_ASSERT(stress_test_errors < stress_test_successes / 2); // Less than 50% error rate
    
    dap_billing_memory_manager_deinit();
    return TEST_RESULT_PASS;
}

/**
 * @brief Run all stress tests (only if STRESS flag is enabled)
 */
int main(int argc, char** argv)
{
    // Initialize random seed
    srand(time(NULL));
    
    log_it(L_INFO, "Starting simplified billing stress tests");
    
    test_result_t result1 = test_stress_basic_memory_operations();
    if (result1 != TEST_RESULT_PASS) {
        log_it(L_ERROR, "Basic memory stress test failed");
        return 1;
    }
    
    test_result_t result2 = test_stress_concurrent_sessions();
    if (result2 != TEST_RESULT_PASS) {
        log_it(L_ERROR, "Concurrent sessions stress test failed");
        return 1;
    }
    
    log_it(L_INFO, "All simplified stress tests passed successfully");
    return 0;
}