# Test Fixtures Libraries
cmake_minimum_required(VERSION 3.10)

# Include DAP Mock AutoWrap module
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

# Unit Test Fixtures (for unit tests with DAP SDK mocking)
project(unit_test_fixtures)

add_library(${PROJECT_NAME} STATIC
    unit_test_fixtures.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/modules/common/include
    ${CMAKE_SOURCE_DIR}/modules/chain/include
    ${CMAKE_SOURCE_DIR}/modules/consensus/include
    ${CMAKE_SOURCE_DIR}/modules/ledger/include
    ${CMAKE_SOURCE_DIR}/modules/net/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/core
    ${CMAKE_SOURCE_DIR}/dap-sdk/crypto/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/core/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/global-db/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/module/test/include
)

target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_crypto
    dap_common
    dap_test
)

# Apply dap_mock auto-wrapping for DAP SDK functions
dap_mock_autowrap(${PROJECT_NAME})

# Integration Test Fixtures (for integration tests with full stack)
project(test_fixtures)

add_library(${PROJECT_NAME} STATIC
    integration_test_fixtures.c
    test_fixtures.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/modules/common/include
    ${CMAKE_SOURCE_DIR}/modules/chain/include
    ${CMAKE_SOURCE_DIR}/modules/consensus/include
    ${CMAKE_SOURCE_DIR}/modules/ledger/include
    ${CMAKE_SOURCE_DIR}/modules/net/include
    ${CMAKE_SOURCE_DIR}/modules/wallet/include
    ${CMAKE_SOURCE_DIR}/modules/datum/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/core
    ${CMAKE_SOURCE_DIR}/dap-sdk/crypto/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/core/include
    ${CMAKE_SOURCE_DIR}/dap-sdk/global-db/include
)

target_link_libraries(${PROJECT_NAME}
    dap_core
    dap_crypto
    dap_common
)
