/**
 * @file main.c
 * @brief Main entry point for billing module tests
 * @author DAP Team
 * @date 2024
 */

#include "billing_test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

// External test suites
extern test_suite_t memory_manager_test_suite;
#ifdef ENABLE_STRESS_TESTS
extern test_suite_t stress_test_suite;
#endif

// ============================================================================
// COMMAND LINE PARSING
// ============================================================================

static void print_usage(const char *program_name)
{
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nTest Categories:\n");
    printf("  --category=CATEGORY    Run specific test category\n");
    printf("                         FAST        - Fast unit tests (< 100ms each)\n");
    printf("                         INTEGRATION - Integration tests (< 1s each)\n");
    printf("                         DEFAULT     - FAST + INTEGRATION (default)\n");
#ifdef ENABLE_STRESS_TESTS
    printf("                         STRESS      - Stress tests (variable time)\n");
#endif
#ifdef ENABLE_PERFORMANCE_TESTS
    printf("                         PERFORMANCE - Performance benchmarks\n");
#endif
#ifdef ENABLE_LONG_RUNNING_TESTS
    printf("                         LONG_RUNNING- Long running tests (> 10s)\n");
#endif
    printf("                         ALL         - All enabled categories\n");
    printf("\nOutput Options:\n");
    printf("  --output=FORMAT        Output format: console (default), junit, json\n");
    printf("  --output-file=FILE     Write output to file instead of stdout\n");
    printf("\nExecution Options:\n");
    printf("  --verbose, -v          Verbose output\n");
    printf("  --stop-on-failure, -s  Stop on first failure\n");
    printf("  --parallel=N           Max parallel tests (default: 1)\n");
    printf("  --list                 List available tests and exit\n");
    printf("  --help, -h             Show this help\n");
    
    printf("\nExamples:\n");
    printf("  %s                                    # Run default tests (fast + integration)\n", program_name);
    printf("  %s --category=FAST                    # Run only fast unit tests\n", program_name);
    printf("  %s --category=ALL --verbose           # Run all enabled tests with verbose output\n", program_name);
#ifdef ENABLE_STRESS_TESTS
    printf("  %s --category=STRESS --parallel=4     # Run stress tests with 4 parallel threads\n", program_name);
#endif
    printf("  %s --output=junit --output-file=results.xml  # Generate JUnit XML output\n", program_name);
}

static uint32_t parse_category(const char *category_str)
{
    if (!category_str) return TEST_CATEGORY_DEFAULT;
    
    if (strcmp(category_str, "FAST") == 0) {
        return TEST_CATEGORY_FAST;
    } else if (strcmp(category_str, "INTEGRATION") == 0) {
        return TEST_CATEGORY_INTEGRATION;
    } else if (strcmp(category_str, "DEFAULT") == 0) {
        return TEST_CATEGORY_DEFAULT;
    } else if (strcmp(category_str, "ALL") == 0) {
        return TEST_CATEGORY_ALL;
#ifdef ENABLE_STRESS_TESTS
    } else if (strcmp(category_str, "STRESS") == 0) {
        return TEST_CATEGORY_STRESS;
#endif
#ifdef ENABLE_PERFORMANCE_TESTS
    } else if (strcmp(category_str, "PERFORMANCE") == 0) {
        return TEST_CATEGORY_PERFORMANCE;
#endif
#ifdef ENABLE_LONG_RUNNING_TESTS
    } else if (strcmp(category_str, "LONG_RUNNING") == 0) {
        return TEST_CATEGORY_LONG_RUNNING;
#endif
    } else {
        fprintf(stderr, "Error: Unknown category '%s'\n", category_str);
        return 0;
    }
}

static int parse_command_line(int argc, char **argv, test_config_t *config)
{
    static struct option long_options[] = {
        {"category",        required_argument, 0, 'c'},
        {"output",          required_argument, 0, 'o'},
        {"output-file",     required_argument, 0, 'f'},
        {"verbose",         no_argument,       0, 'v'},
        {"stop-on-failure", no_argument,       0, 's'},
        {"parallel",        required_argument, 0, 'p'},
        {"list",            no_argument,       0, 'l'},
        {"help",            no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Set defaults
    config->enabled_categories = TEST_CATEGORY_DEFAULT;
    config->verbose = false;
    config->stop_on_failure = false;
    config->output_format = "console";
    config->output_file = NULL;
    config->max_parallel_tests = 1;
    
    int option_index = 0;
    int c;
    
    while ((c = getopt_long(argc, argv, "c:o:f:vsp:lh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                config->enabled_categories = parse_category(optarg);
                if (config->enabled_categories == 0) {
                    return -1;
                }
                break;
                
            case 'o':
                if (strcmp(optarg, "console") != 0 && 
                    strcmp(optarg, "junit") != 0 && 
                    strcmp(optarg, "json") != 0) {
                    fprintf(stderr, "Error: Invalid output format '%s'\n", optarg);
                    return -1;
                }
                config->output_format = optarg;
                break;
                
            case 'f':
                config->output_file = optarg;
                break;
                
            case 'v':
                config->verbose = true;
                break;
                
            case 's':
                config->stop_on_failure = true;
                break;
                
            case 'p':
                config->max_parallel_tests = atoi(optarg);
                if (config->max_parallel_tests < 1) {
                    config->max_parallel_tests = 1;
                }
                break;
                
            case 'l':
                // List tests flag - will be handled in main
                return 1;
                
            case 'h':
                print_usage(argv[0]);
                exit(0);
                
            case '?':
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return -1;
                
            default:
                abort();
        }
    }
    
    return 0;
}

// ============================================================================
// TEST LISTING
// ============================================================================

static void list_available_tests(void)
{
    printf("Available Test Suites and Categories:\n\n");
    
    printf("FAST TESTS (always enabled):\n");
    printf("  - Memory Manager Tests: %zu tests\n", memory_manager_test_suite.test_count);
    
    printf("\nINTEGRATION TESTS (enabled by default):\n");
    printf("  - Billing-VPN Integration Tests\n");
    printf("  - Full Service Flow Tests\n");
    
#ifdef ENABLE_STRESS_TESTS
    printf("\nSTRESS TESTS (enabled with ENABLE_STRESS_TESTS=ON):\n");
    printf("  - Concurrent Sessions: %zu tests\n", stress_test_suite.test_count);
    printf("  - Memory Pressure Tests\n");
    printf("  - Race Condition Detection\n");
#else
    printf("\nSTRESS TESTS: DISABLED (enable with ENABLE_STRESS_TESTS=ON)\n");
#endif

#ifdef ENABLE_PERFORMANCE_TESTS
    printf("\nPERFORMANCE TESTS (enabled with ENABLE_PERFORMANCE_TESTS=ON):\n");
    printf("  - Throughput Benchmarks\n");
    printf("  - Latency Measurements\n");
    printf("  - Memory Usage Profiling\n");
#else
    printf("\nPERFORMANCE TESTS: DISABLED (enable with ENABLE_PERFORMANCE_TESTS=ON)\n");
#endif

#ifdef ENABLE_LONG_RUNNING_TESTS
    printf("\nLONG RUNNING TESTS (enabled with ENABLE_LONG_RUNNING_TESTS=ON):\n");
    printf("  - Extended Session Tests\n");
    printf("  - Stability Tests\n");
#else
    printf("\nLONG RUNNING TESTS: DISABLED (enable with ENABLE_LONG_RUNNING_TESTS=ON)\n");
#endif

    printf("\nTo enable optional test categories, rebuild with:\n");
    printf("  cmake -DENABLE_STRESS_TESTS=ON -DENABLE_PERFORMANCE_TESTS=ON ..\n");
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

int main(int argc, char **argv)
{
    test_config_t config;
    int parse_result = parse_command_line(argc, argv, &config);
    
    if (parse_result < 0) {
        return EXIT_FAILURE;
    }
    
    if (parse_result == 1) {
        // List tests and exit
        list_available_tests();
        return EXIT_SUCCESS;
    }
    
    // Initialize test framework
    if (test_framework_init(&config) != 0) {
        fprintf(stderr, "Error: Failed to initialize test framework\n");
        return EXIT_FAILURE;
    }
    
    printf("Billing Module Test Suite\n");
    printf("=========================\n");
    printf("Categories: %s\n", test_category_to_string(config.enabled_categories));
    printf("Output: %s\n", config.output_format);
    if (config.output_file) {
        printf("Output file: %s\n", config.output_file);
    }
    printf("Parallel tests: %u\n", config.max_parallel_tests);
    printf("\n");
    
    // Register test suites
    test_register_suite(&memory_manager_test_suite);
    
#ifdef ENABLE_STRESS_TESTS
    if (config.enabled_categories & TEST_CATEGORY_STRESS) {
        test_register_suite(&stress_test_suite);
    }
#endif
    
    // Run tests
    int result = test_run_category(config.enabled_categories);
    
    // Print final statistics
    test_stats_t *stats = test_get_stats();
    printf("\n");
    printf("Test Results Summary:\n");
    printf("====================\n");
    printf("Total tests: %u\n", stats->total_tests);
    printf("Passed: %u\n", stats->passed_tests);
    printf("Failed: %u\n", stats->failed_tests);
    printf("Skipped: %u\n", stats->skipped_tests);
    printf("Timeouts: %u\n", stats->timeout_tests);
    printf("Crashes: %u\n", stats->crashed_tests);
    printf("Total time: %lu ms\n", stats->total_time_ms);
    
    if (stats->failed_tests > 0 || stats->crashed_tests > 0) {
        printf("\nResult: FAILURE\n");
        result = EXIT_FAILURE;
    } else {
        printf("\nResult: SUCCESS\n");
        result = EXIT_SUCCESS;
    }
    
    // Cleanup
    test_framework_cleanup();
    
    return result;
}
