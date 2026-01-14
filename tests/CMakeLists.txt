cmake_minimum_required(VERSION 3.10)
project(cellframe_sdk_tests)

# Test configuration options
option(BUILD_CELLFRAME_SDK_TESTS "Build Cellframe SDK tests" ON)
option(ENABLE_PERFORMANCE_TESTS "Enable performance tests (optional)" OFF)

if(NOT BUILD_CELLFRAME_SDK_TESTS)
    message(STATUS "Cellframe SDK tests are disabled")
    return()
endif()

message(STATUS "=== Configuring Cellframe SDK Tests ===")

# Enable testing
enable_testing()

# Include directories for tests
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures
    ${CMAKE_SOURCE_DIR}/modules/chain/include
    ${CMAKE_SOURCE_DIR}/modules/ledger/include
    ${CMAKE_SOURCE_DIR}/modules/datum/include
    ${CMAKE_SOURCE_DIR}/modules/net/include
    ${CMAKE_SOURCE_DIR}/modules/service/stake-ext/include
    ${CMAKE_SOURCE_DIR}/modules/common/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/test/include
)

# Common test libraries
set(TEST_LINK_LIBRARIES
    dap_test
    dap_sdk
    cellframe_sdk
)

# Build fixtures first
add_subdirectory(fixtures)

# Build test categories
add_subdirectory(unit)
add_subdirectory(integration)
# add_subdirectory(performance) # TODO: Enable when TPS tests are refactored

message(STATUS "=== Cellframe SDK Tests Configured ===")
