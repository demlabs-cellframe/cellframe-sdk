/**
 * @file billing_test_framework.h
 * @brief Billing module test framework with category support
 * @author DAP Team
 * @date 2024
 */

#pragma once

#include "dap_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>

// Test categories
#define TEST_CATEGORY_FAST          (1 << 0)  // Fast unit tests (< 100ms each)
#define TEST_CATEGORY_INTEGRATION   (1 << 1)  // Integration tests (< 1s each)
#define TEST_CATEGORY_STRESS        (1 << 2)  // Stress tests (variable time)
#define TEST_CATEGORY_PERFORMANCE   (1 << 3)  // Performance benchmarks
#define TEST_CATEGORY_LONG_RUNNING  (1 << 4)  // Long running tests (> 10s)

// Combined categories
#define TEST_CATEGORY_DEFAULT       (TEST_CATEGORY_FAST | TEST_CATEGORY_INTEGRATION)
#define TEST_CATEGORY_ALL           (TEST_CATEGORY_FAST | TEST_CATEGORY_INTEGRATION | \
                                     TEST_CATEGORY_STRESS | TEST_CATEGORY_PERFORMANCE | \
                                     TEST_CATEGORY_LONG_RUNNING)

// Test timeouts (in milliseconds)
#define TEST_TIMEOUT_FAST          100
#define TEST_TIMEOUT_INTEGRATION   1000
#define TEST_TIMEOUT_STRESS        30000
#define TEST_TIMEOUT_PERFORMANCE   60000
#define TEST_TIMEOUT_LONG_RUNNING  300000

// Test result codes
typedef enum {
    TEST_RESULT_PASS = 0,
    TEST_RESULT_FAIL,
    TEST_RESULT_SKIP,
    TEST_RESULT_TIMEOUT,
    TEST_RESULT_CRASH,
    TEST_RESULT_ERROR
} test_result_t;

// Test function signature
typedef test_result_t (*test_function_t)(void);

// Test case structure
typedef struct {
    const char *name;
    const char *description;
    test_function_t function;
    uint32_t category;
    uint32_t timeout_ms;
    bool enabled;
} test_case_t;

// Test suite structure
typedef struct {
    const char *name;
    test_case_t *tests;
    size_t test_count;
    void (*setup)(void);     // Called before each test
    void (*teardown)(void);  // Called after each test
    void (*suite_setup)(void);    // Called once before all tests
    void (*suite_teardown)(void); // Called once after all tests
} test_suite_t;

// Test statistics
typedef struct {
    uint32_t total_tests;
    uint32_t passed_tests;
    uint32_t failed_tests;
    uint32_t skipped_tests;
    uint32_t timeout_tests;
    uint32_t crashed_tests;
    uint64_t total_time_ms;
    uint64_t start_time_ms;
} test_stats_t;

// Test runner configuration
typedef struct {
    uint32_t enabled_categories;
    bool verbose;
    bool stop_on_failure;
    const char *output_format;  // "console", "junit", "json"
    const char *output_file;
    uint32_t max_parallel_tests;
} test_config_t;

// ============================================================================
// MACROS FOR TEST DEFINITION
// ============================================================================

/**
 * @brief Define a test case with category
 */
#define DEFINE_TEST(name, category, description) \
    test_result_t test_##name(void); \
    static test_case_t test_case_##name = { \
        .name = #name, \
        .description = description, \
        .function = test_##name, \
        .category = category, \
        .timeout_ms = (category == TEST_CATEGORY_FAST) ? TEST_TIMEOUT_FAST : \
                      (category == TEST_CATEGORY_INTEGRATION) ? TEST_TIMEOUT_INTEGRATION : \
                      (category == TEST_CATEGORY_STRESS) ? TEST_TIMEOUT_STRESS : \
                      (category == TEST_CATEGORY_PERFORMANCE) ? TEST_TIMEOUT_PERFORMANCE : \
                      TEST_TIMEOUT_LONG_RUNNING, \
        .enabled = true \
    }; \
    test_result_t test_##name(void)

/**
 * @brief Fast unit test (< 100ms)
 */
#define FAST_TEST(name, description) \
    DEFINE_TEST(name, TEST_CATEGORY_FAST, description)

/**
 * @brief Integration test (< 1s)
 */
#define INTEGRATION_TEST(name, description) \
    DEFINE_TEST(name, TEST_CATEGORY_INTEGRATION, description)

/**
 * @brief Stress test (variable time, optional)
 */
#define STRESS_TEST(name, description) \
    DEFINE_TEST(name, TEST_CATEGORY_STRESS, description)

/**
 * @brief Performance test (benchmark)
 */
#define PERFORMANCE_TEST(name, description) \
    DEFINE_TEST(name, TEST_CATEGORY_PERFORMANCE, description)

/**
 * @brief Long running test (> 10s)
 */
#define LONG_RUNNING_TEST(name, description) \
    DEFINE_TEST(name, TEST_CATEGORY_LONG_RUNNING, description)

// ============================================================================
// ASSERTION MACROS
// ============================================================================

extern jmp_buf test_jump_buffer;
extern char test_failure_message[1024];

#define TEST_ASSERT(condition, message, ...) \
    do { \
        if (!(condition)) { \
            snprintf(test_failure_message, sizeof(test_failure_message), \
                    "ASSERTION FAILED: %s:%d: " message, __FILE__, __LINE__, ##__VA_ARGS__); \
            longjmp(test_jump_buffer, TEST_RESULT_FAIL); \
        } \
    } while(0)

#define TEST_ASSERT_EQUAL(expected, actual) \
    TEST_ASSERT((expected) == (actual), "Expected %ld, got %ld", (long)(expected), (long)(actual))

#define TEST_ASSERT_NOT_EQUAL(expected, actual) \
    TEST_ASSERT((expected) != (actual), "Expected not %ld, got %ld", (long)(expected), (long)(actual))

#define TEST_ASSERT_NULL(ptr) \
    TEST_ASSERT((ptr) == NULL, "Expected NULL, got %p", (void*)(ptr))

#define TEST_ASSERT_NOT_NULL(ptr) \
    TEST_ASSERT((ptr) != NULL, "Expected non-NULL, got NULL")

#define TEST_ASSERT_STRING_EQUAL(expected, actual) \
    TEST_ASSERT(strcmp((expected), (actual)) == 0, "Expected '%s', got '%s'", (expected), (actual))

#define TEST_ASSERT_MEMORY_EQUAL(expected, actual, size) \
    TEST_ASSERT(memcmp((expected), (actual), (size)) == 0, "Memory blocks differ")

#define TEST_SKIP(message, ...) \
    do { \
        snprintf(test_failure_message, sizeof(test_failure_message), \
                "SKIPPED: " message, ##__VA_ARGS__); \
        longjmp(test_jump_buffer, TEST_RESULT_SKIP); \
    } while(0)

#define TEST_FAIL(message, ...) \
    do { \
        snprintf(test_failure_message, sizeof(test_failure_message), \
                "FAILED: " message, ##__VA_ARGS__); \
        longjmp(test_jump_buffer, TEST_RESULT_FAIL); \
    } while(0)

// ============================================================================
// TEST RUNNER API
// ============================================================================

/**
 * @brief Initialize test framework
 */
int test_framework_init(test_config_t *config);

/**
 * @brief Register test suite
 */
int test_register_suite(test_suite_t *suite);

/**
 * @brief Run all registered tests
 */
int test_run_all(void);

/**
 * @brief Run tests from specific category
 */
int test_run_category(uint32_t category);

/**
 * @brief Run single test by name
 */
int test_run_single(const char *test_name);

/**
 * @brief Get test statistics
 */
test_stats_t* test_get_stats(void);

/**
 * @brief Clean up test framework
 */
void test_framework_cleanup(void);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get current time in milliseconds
 */
uint64_t test_get_time_ms(void);

/**
 * @brief Sleep for specified milliseconds
 */
void test_sleep_ms(uint32_t ms);

/**
 * @brief Check if category is enabled
 */
bool test_is_category_enabled(uint32_t category);

/**
 * @brief Get category name as string
 */
const char* test_category_to_string(uint32_t category);

/**
 * @brief Parse command line arguments
 */
int test_parse_args(int argc, char **argv, test_config_t *config);

// ============================================================================
// PERFORMANCE MEASUREMENT MACROS
// ============================================================================

#define BENCHMARK_START() \
    uint64_t benchmark_start_time = test_get_time_ms()

#define BENCHMARK_END(operation_name) \
    do { \
        uint64_t benchmark_end_time = test_get_time_ms(); \
        uint64_t benchmark_duration = benchmark_end_time - benchmark_start_time; \
        printf("BENCHMARK: %s took %lu ms\n", operation_name, benchmark_duration); \
    } while(0)

// ============================================================================
// CONDITIONAL COMPILATION SUPPORT
// ============================================================================

#ifdef ENABLE_STRESS_TESTS
#define IF_STRESS_ENABLED(code) code
#else
#define IF_STRESS_ENABLED(code)
#endif

#ifdef ENABLE_PERFORMANCE_TESTS
#define IF_PERFORMANCE_ENABLED(code) code
#else
#define IF_PERFORMANCE_ENABLED(code)
#endif

#ifdef ENABLE_LONG_RUNNING_TESTS
#define IF_LONG_RUNNING_ENABLED(code) code
#else
#define IF_LONG_RUNNING_ENABLED(code)
#endif

#ifdef ENABLE_VALGRIND_TESTS
#define IF_VALGRIND_ENABLED(code) code
#else
#define IF_VALGRIND_ENABLED(code)
#endif
