# Cellframe SDK Test Suite
# Based on dap-sdk/test-framework
cmake_minimum_required(VERSION 3.10)

project(cellframe-sdk-tests C)

message(STATUS "Configuring Cellframe SDK tests")

# Test framework from DAP SDK is already built by dap-sdk/test-framework
# We just need to use it via target_link_libraries(... dap_test)

# Common include directories for all tests
set(CELLFRAME_TEST_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}/../modules/common/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../modules/chain/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../modules/net/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../modules/wallet/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/crypto/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/test-framework
    ${CMAKE_CURRENT_SOURCE_DIR}/../../dap-sdk/3rdparty/uthash/src
)

# Test fixtures - common test utilities
add_subdirectory(fixtures)

# Unit tests subdirectory
add_subdirectory(unit)

# Integration tests subdirectory  
add_subdirectory(integration)

