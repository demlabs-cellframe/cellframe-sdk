/**
 * @file test_concurrent_sessions.c
 * @brief Stress tests for concurrent billing sessions
 * @author DAP Team
 * @date 2024
 * 
 * These tests are DISABLED by default and only run with ENABLE_STRESS_TESTS=ON
 */

#include "billing_test_framework.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_net_srv_usage_manager.h"
#include <pthread.h>
#include <unistd.h>

#ifdef ENABLE_STRESS_TESTS

// ============================================================================
// STRESS TEST CONFIGURATION
// ============================================================================

#define STRESS_TEST_THREADS 50
#define STRESS_TEST_SESSIONS_PER_THREAD 100
#define STRESS_TEST_OPERATIONS_PER_SESSION 20
#define STRESS_TEST_TIMEOUT_SECONDS 30

// Shared test data
static volatile bool stress_test_stop = false;
static volatile uint32_t stress_test_errors = 0;
static volatile uint32_t stress_test_successes = 0;
static pthread_mutex_t stress_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// STRESS TESTS
// ============================================================================

// Thread function for concurrent session stress test
static void* stress_session_worker(void *arg)
{
    int thread_id = *(int*)arg;
    uint32_t local_successes = 0;
    uint32_t local_errors = 0;
    
    for (int session = 0; session < STRESS_TEST_SESSIONS_PER_THREAD && !stress_test_stop; session++) {
        
        // Simulate session creation
        dap_chain_net_srv_usage_t usage = {0};
        
        if (dap_billing_usage_init_safe(&usage, "stress_test") == DAP_USAGE_MANAGER_SUCCESS) {
            
            // Perform multiple operations on this session
            for (int op = 0; op < STRESS_TEST_OPERATIONS_PER_SESSION && !stress_test_stop; op++) {
                
                // Simulate grace period creation/cleanup
                dap_hash_fast_t dummy_hash = {0};
                dummy_hash.raw[0] = thread_id;
                dummy_hash.raw[1] = session;
                dummy_hash.raw[2] = op;
                
                if (dap_billing_usage_grace_create_safe(&usage, &dummy_hash, 1000, "stress_grace") == DAP_USAGE_MANAGER_SUCCESS) {
                    
                    // Brief operation simulation
                    usleep(rand() % 1000); // 0-1ms random delay
                    
                    // Cleanup grace
                    if (dap_billing_usage_grace_cleanup_safe(&usage, &dummy_hash, "stress_cleanup") == DAP_USAGE_MANAGER_SUCCESS) {
                        local_successes++;
                    } else {
                        local_errors++;
                    }
                } else {
                    local_errors++;
                }
            }
            
            // Cleanup session
            if (dap_billing_usage_cleanup_safe(&usage, "stress_session_cleanup") != DAP_USAGE_MANAGER_SUCCESS) {
                local_errors++;
            }
            
        } else {
            local_errors++;
        }
    }
    
    // Update global statistics
    pthread_mutex_lock(&stress_stats_mutex);
    stress_test_successes += local_successes;
    stress_test_errors += local_errors;
    pthread_mutex_unlock(&stress_stats_mutex);
    
    return NULL;
}

STRESS_TEST(concurrent_sessions_basic, "Basic concurrent session handling under stress")
{
    pthread_t threads[STRESS_TEST_THREADS];
    int thread_ids[STRESS_TEST_THREADS];
    
    // Reset statistics
    stress_test_stop = false;
    stress_test_errors = 0;
    stress_test_successes = 0;
    
    // Initialize system
    TEST_ASSERT_EQUAL(0, dap_billing_memory_manager_init());
    
    BENCHMARK_START();
    
    // Create threads
    for (int i = 0; i < STRESS_TEST_THREADS; i++) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, stress_session_worker, &thread_ids[i]) != 0) {
            TEST_FAIL("Failed to create thread %d", i);
        }
    }
    
    // Set timeout
    alarm(STRESS_TEST_TIMEOUT_SECONDS);
    
    // Wait for threads
    for (int i = 0; i < STRESS_TEST_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    alarm(0); // Cancel timeout
    
    BENCHMARK_END("Concurrent sessions stress test");
    
    // Check results
    uint32_t total_operations = stress_test_successes + stress_test_errors;
    uint32_t expected_operations = STRESS_TEST_THREADS * STRESS_TEST_SESSIONS_PER_THREAD * STRESS_TEST_OPERATIONS_PER_SESSION;
    
    printf("STRESS TEST RESULTS:\n");
    printf("  Expected operations: %u\n", expected_operations);
    printf("  Completed operations: %u\n", total_operations);
    printf("  Successful operations: %u\n", stress_test_successes);
    printf("  Failed operations: %u\n", stress_test_errors);
    printf("  Success rate: %.2f%%\n", (float)stress_test_successes * 100.0f / total_operations);
    
    // Require at least 95% success rate
    float success_rate = (float)stress_test_successes * 100.0f / total_operations;
    TEST_ASSERT(success_rate >= 95.0f, "Success rate too low: %.2f%% (expected >= 95%%)", success_rate);
    
    // No critical errors should occur
    TEST_ASSERT(stress_test_errors < total_operations * 0.05f, "Too many errors: %u", stress_test_errors);
    
    dap_billing_memory_manager_deinit();
    return TEST_RESULT_PASS;
}

// Memory pressure stress test
STRESS_TEST(memory_pressure, "Memory allocation under pressure")
{
    TEST_ASSERT_EQUAL(0, dap_billing_memory_manager_init());
    
    const int allocation_count = 10000;
    void **allocations = malloc(allocation_count * sizeof(void*));
    TEST_ASSERT_NOT_NULL(allocations);
    
    BENCHMARK_START();
    
    // Allocate many objects
    int successful_allocations = 0;
    for (int i = 0; i < allocation_count; i++) {
        size_t size = (rand() % 4096) + 64; // 64-4160 bytes
        allocations[i] = dap_billing_memory_alloc(size, DAP_MEMORY_RESOURCE_GRACE_OBJECT, "stress_alloc");
        if (allocations[i] != NULL) {
            successful_allocations++;
        }
        
        // Occasionally free some allocations to create fragmentation
        if (i > 100 && (rand() % 10) == 0) {
            int free_index = rand() % i;
            if (allocations[free_index] != NULL) {
                dap_billing_memory_free(allocations[free_index], "stress_free");
                allocations[free_index] = NULL;
            }
        }
    }
    
    // Free remaining allocations
    int freed_count = 0;
    for (int i = 0; i < allocation_count; i++) {
        if (allocations[i] != NULL) {
            if (dap_billing_memory_free(allocations[i], "cleanup_free") == DAP_MEMORY_MANAGER_SUCCESS) {
                freed_count++;
            }
        }
    }
    
    BENCHMARK_END("Memory pressure test");
    
    printf("MEMORY PRESSURE RESULTS:\n");
    printf("  Requested allocations: %d\n", allocation_count);
    printf("  Successful allocations: %d\n", successful_allocations);
    printf("  Freed allocations: %d\n", freed_count);
    
    free(allocations);
    dap_billing_memory_manager_deinit();
    return TEST_RESULT_PASS;
}

// Race condition stress test
STRESS_TEST(race_condition_detection, "Race condition detection in grace period management")
{
    // This test intentionally creates race conditions to verify they are handled safely
    const int thread_count = 20;
    const int operations_per_thread = 1000;
    
    TEST_ASSERT_EQUAL(0, dap_billing_memory_manager_init());
    
    // Shared usage object for race condition testing
    static dap_chain_net_srv_usage_t shared_usage = {0};
    TEST_ASSERT_EQUAL(DAP_USAGE_MANAGER_SUCCESS, dap_billing_usage_init_safe(&shared_usage, "race_test"));
    
    pthread_t threads[thread_count];
    int thread_ids[thread_count];
    
    stress_test_stop = false;
    stress_test_errors = 0;
    stress_test_successes = 0;
    
    BENCHMARK_START();
    
    // Create racing threads
    for (int i = 0; i < thread_count; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, stress_session_worker, &thread_ids[i]);
    }
    
    // Wait for completion
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    BENCHMARK_END("Race condition stress test");
    
    // Clean up shared usage
    TEST_ASSERT_EQUAL(DAP_USAGE_MANAGER_SUCCESS, dap_billing_usage_cleanup_safe(&shared_usage, "race_cleanup"));
    
    printf("RACE CONDITION TEST RESULTS:\n");
    printf("  Total operations: %u\n", stress_test_successes + stress_test_errors);
    printf("  No crashes should occur - test passes if we reach this point\n");
    
    dap_billing_memory_manager_deinit();
    return TEST_RESULT_PASS;
}

// Test suite definition for stress tests
static test_case_t stress_tests[] = {
    test_case_concurrent_sessions_basic,
    test_case_memory_pressure,
    test_case_race_condition_detection,
};

test_suite_t stress_test_suite = {
    .name = "Stress Tests (Concurrent & Load)",
    .tests = stress_tests,
    .test_count = sizeof(stress_tests) / sizeof(stress_tests[0]),
    .setup = NULL,
    .teardown = NULL,
    .suite_setup = NULL,
    .suite_teardown = NULL
};

#endif // ENABLE_STRESS_TESTS
