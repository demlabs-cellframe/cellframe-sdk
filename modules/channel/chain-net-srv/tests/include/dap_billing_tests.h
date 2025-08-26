/**
 * @file dap_billing_tests.h
 * @brief Header for Billing Module Tests
 * @details Test suite for validating all aspects of the billing module
 * @authors Dmitriy Gerasimov
 * @date 2025
 * @copyright (c) 2017-2025 Demlabs Ltd
 */

#pragma once

// #include "dap_test.h" - создаём упрощенные макросы
#include "dap_common.h"
#include <stdio.h>

// Simple test macros
#define dap_test_msg(format, ...) printf("[TEST] " format "\n", ##__VA_ARGS__)
#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("[FAIL] %s: %s\n", __func__, message); \
            return; \
        } else { \
            printf("[PASS] %s: %s\n", __func__, message); \
        } \
    } while(0)
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_stream_ch_chain_net_srv_memory_manager.h"
#include "dap_chain_net_srv.h"

/**
 * @brief Main entry point for all billing tests
 */
void dap_billing_tests_run(void);

// Category 1: Memory Manager Tests
void test_memory_allocation_basic(void);
void test_memory_double_free_protection(void);
void test_memory_null_pointer_handling(void);
void test_memory_large_allocation(void);
void test_grace_object_factory_basic(void);
void test_grace_object_factory_null_usage(void);
void test_grace_object_lifecycle(void);
void test_memory_stress_allocation_deallocation(void);

void test_memory_allocation_failure_simulation(void);
void test_memory_concurrent_access(void);

// Category 2: Grace Timer Tests
void test_grace_timer_management(void);
void test_grace_timer_cleanup_safe(void);

// Category 3: Usage Manager Tests
void test_usage_manager_configure_client_basic(void);
void test_usage_manager_configure_client_null_params(void);
void test_usage_manager_error_handling(void);
void test_usage_manager_resource_allocation(void);
void test_usage_manager_lifecycle(void);

// Category 4: Error Handling Tests
void test_error_code_network_not_found(void);
void test_error_code_service_not_found(void);
void test_error_code_cant_add_usage(void);
void test_error_code_alloc_memory_error(void);
void test_error_string_conversion(void);

// Category 5: Network Service Tests  
void test_network_service_validation(void);
void test_service_role_checking(void);
void test_service_discovery(void);
void test_network_id_validation(void);

// Category 6: Price Calculation Tests
void test_price_calculation_basic(void);
void test_price_from_order_lookup(void);
void test_price_validation(void);

// Category 7: Payment & Transaction Tests
void test_payment_sufficient_funds(void);
void test_payment_insufficient_funds(void);
void test_payment_tx_not_found_in_ledger(void);
void test_payment_tx_no_cond_output(void);
void test_payment_mempool_creation_error(void);
void test_grace_period_success_scenario(void);
void test_grace_period_timeout_scenario(void);
void test_grace_period_with_insufficient_funds(void);
void test_service_termination_on_payment_failure(void);
void test_service_continuation_after_failed_payment(void);
void test_multiple_payment_cycles(void);
void test_tx_hash_validation(void);

// Test utilities and helpers
typedef struct {
    uint32_t test_id;
    char context[64];
    bool cleanup_called;
} test_context_t;

// Mock objects and test data
typedef struct {
    dap_chain_net_srv_usage_t *usage;
    test_context_t *test_ctx;
} mock_usage_t;

// Test result tracking
typedef struct {
    uint32_t total_tests;
    uint32_t passed_tests; 
    uint32_t failed_tests;
    uint32_t skipped_tests;
} dap_billing_test_results_t;

extern dap_billing_test_results_t g_billing_test_results;
