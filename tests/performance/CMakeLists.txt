cmake_minimum_required(VERSION 3.10)
project(cellframe_performance_tests C)

# Performance tests - NOT run by default, only on demand
# Usage: cd build && cmake .. -DBUILD_PERFORMANCE_TESTS=ON && make performance-test

if(NOT BUILD_PERFORMANCE_TESTS)
    message(STATUS "Performance tests disabled (use -DBUILD_PERFORMANCE_TESTS=ON to enable)")
    return()
endif()

message(STATUS "Building performance tests")

# TPS (Transactions Per Second) test
add_executable(tps-test
    dap_tps_test.c
)

target_link_libraries(tps-test
    dap_core
    dap_chain
    dap_chain_net
    dap_chain_mempool
    dap_chain_ledger
    cellframe_sdk
)

target_include_directories(tps-test PRIVATE
    ../../dap-sdk/module/core/include
    ../../modules/chain/include
    ../../modules/net/include
    ../../modules/mempool/include
    ../../modules/ledger/include
)

# Compile with DAP_TPS_TEST to enable TPS-specific features
target_compile_definitions(tps-test PRIVATE DAP_TPS_TEST)

# Add test to CTest (but not to 'make test' by default)
add_test(NAME performance_tps COMMAND tps-test)
set_tests_properties(performance_tps PROPERTIES
    LABELS "performance;manual"
    TIMEOUT 3600  # 1 hour for long-running performance tests
)
