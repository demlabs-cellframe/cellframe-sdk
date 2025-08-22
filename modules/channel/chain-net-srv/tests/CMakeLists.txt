# ============================================================================
# BILLING MODULE UNIT TESTS
# ============================================================================

cmake_minimum_required(VERSION 3.10)
project(dap_billing_tests)

# Test configuration options
option(ENABLE_BILLING_TESTS "Enable billing module tests" ON)
option(ENABLE_STRESS_TESTS "Enable stress and load tests" OFF)
option(ENABLE_PERFORMANCE_TESTS "Enable performance benchmarks" OFF)
option(ENABLE_LONG_RUNNING_TESTS "Enable long running tests" OFF)
option(ENABLE_VALGRIND_TESTS "Enable valgrind memory tests" OFF)

# Test categories configuration
set(TEST_CATEGORIES "FAST|INTEGRATION")

if(ENABLE_STRESS_TESTS)
    set(TEST_CATEGORIES "${TEST_CATEGORIES}|STRESS")
endif()

if(ENABLE_PERFORMANCE_TESTS)
    set(TEST_CATEGORIES "${TEST_CATEGORIES}|PERFORMANCE")
endif()

if(ENABLE_LONG_RUNNING_TESTS)
    set(TEST_CATEGORIES "${TEST_CATEGORIES}|LONG_RUNNING")
endif()

# Configure test compilation flags
add_compile_definitions(
    TEST_ENABLED_CATEGORIES="${TEST_CATEGORIES}"
    $<$<BOOL:${ENABLE_STRESS_TESTS}>:ENABLE_STRESS_TESTS>
    $<$<BOOL:${ENABLE_PERFORMANCE_TESTS}>:ENABLE_PERFORMANCE_TESTS>
    $<$<BOOL:${ENABLE_LONG_RUNNING_TESTS}>:ENABLE_LONG_RUNNING_TESTS>
    $<$<BOOL:${ENABLE_VALGRIND_TESTS}>:ENABLE_VALGRIND_TESTS>
)

# Test framework
set(TEST_FRAMEWORK_SOURCES
    test_framework/billing_test_framework.c
    test_framework/billing_test_mocks.c
    test_framework/billing_test_helpers.c
    test_framework/billing_test_runner.c
)

# Main test sources
set(TEST_SOURCES
    # Fast unit tests (always enabled)
    tests_fast/test_memory_manager.c
    tests_fast/test_timer_utils.c
    tests_fast/test_usage_manager.c
    tests_fast/test_state_transitions.c
    tests_fast/test_packet_handlers.c
    tests_fast/test_error_handling.c
    
    # Integration tests (enabled by default)
    tests_integration/test_billing_vpn_integration.c
    tests_integration/test_full_service_flow.c
    tests_integration/test_grace_period_handling.c
    tests_integration/test_payment_processing.c
    
    # Stress tests (optional)
    $<$<BOOL:${ENABLE_STRESS_TESTS}>:tests_stress/test_concurrent_sessions.c>
    $<$<BOOL:${ENABLE_STRESS_TESTS}>:tests_stress/test_memory_stress.c>
    $<$<BOOL:${ENABLE_STRESS_TESTS}>:tests_stress/test_race_conditions.c>
    
    # Performance tests (optional)
    $<$<BOOL:${ENABLE_PERFORMANCE_TESTS}>:tests_performance/test_throughput.c>
    $<$<BOOL:${ENABLE_PERFORMANCE_TESTS}>:tests_performance/test_latency.c>
    $<$<BOOL:${ENABLE_PERFORMANCE_TESTS}>:tests_performance/test_memory_usage.c>
    
    # Long running tests (optional)
    $<$<BOOL:${ENABLE_LONG_RUNNING_TESTS}>:tests_long/test_extended_sessions.c>
    $<$<BOOL:${ENABLE_LONG_RUNNING_TESTS}>:tests_long/test_stability.c>
)

# Create test executable
add_executable(billing_tests 
    ${TEST_FRAMEWORK_SOURCES}
    ${TEST_SOURCES}
    main.c
)

# Link libraries
target_link_libraries(billing_tests
    dap_chain_net_srv
    dap_stream_ch_chain_net_srv
    pthread
    m
)

# Include directories
target_include_directories(billing_tests PRIVATE
    .
    test_framework
    ../include
    ../../net/srv/include
    ../../../common/include
)

# Test targets for different categories
add_custom_target(test_fast
    COMMAND billing_tests --category=FAST
    DEPENDS billing_tests
    COMMENT "Running fast unit tests"
)

add_custom_target(test_integration
    COMMAND billing_tests --category=INTEGRATION
    DEPENDS billing_tests
    COMMENT "Running integration tests"
)

if(ENABLE_STRESS_TESTS)
    add_custom_target(test_stress
        COMMAND billing_tests --category=STRESS
        DEPENDS billing_tests
        COMMENT "Running stress tests"
    )
endif()

if(ENABLE_PERFORMANCE_TESTS)
    add_custom_target(test_performance
        COMMAND billing_tests --category=PERFORMANCE
        DEPENDS billing_tests
        COMMENT "Running performance tests"
    )
endif()

# Default test target
add_custom_target(test_default
    COMMAND billing_tests --category=DEFAULT
    DEPENDS billing_tests
    COMMENT "Running default test suite (fast + integration)"
)

# All tests (when enabled)
add_custom_target(test_all
    COMMAND billing_tests --category=ALL
    DEPENDS billing_tests
    COMMENT "Running all enabled tests"
)

# CI targets
add_custom_target(test_ci_quick
    COMMAND billing_tests --category=FAST --output=junit
    DEPENDS billing_tests
    COMMENT "Quick CI tests (fast only)"
)

add_custom_target(test_ci_full
    COMMAND billing_tests --category=DEFAULT --output=junit
    DEPENDS billing_tests
    COMMENT "Full CI tests (fast + integration)"
)

# Memory testing with valgrind (if enabled)
if(ENABLE_VALGRIND_TESTS)
    add_custom_target(test_valgrind
        COMMAND valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all 
                --track-origins=yes --verbose ./billing_tests --category=FAST
        DEPENDS billing_tests
        COMMENT "Running tests with valgrind"
    )
endif()

# Install test executable
install(TARGETS billing_tests
    DESTINATION bin/tests
)
