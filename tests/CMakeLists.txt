# Cellframe SDK Test Suite
# Based on dap-sdk/test-framework
cmake_minimum_required(VERSION 3.10)

project(cellframe-sdk-tests C)

# Test framework from DAP SDK
set(DAP_TEST_FRAMEWORK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/test-framework")

# Include DAP test framework headers
include_directories(
    ${DAP_TEST_FRAMEWORK_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../modules/common/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../modules/chain/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../modules/net/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/core
    ${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/crypto/include
)

# Link DAP test framework
add_library(dap_test STATIC 
    ${DAP_TEST_FRAMEWORK_DIR}/dap_test.c
    ${DAP_TEST_FRAMEWORK_DIR}/dap_test_generator.c
)

# Test fixtures - common test utilities
add_subdirectory(fixtures)

# Unit tests subdirectory
add_subdirectory(unit)

# Integration tests subdirectory  
add_subdirectory(integration)

# Enable CTest
enable_testing()

