# Test Fixtures Libraries
cmake_minimum_required(VERSION 3.10)

# Include DAP Mock AutoWrap module
include(${CMAKE_SOURCE_DIR}/dap-sdk/module/test/mocks/DAPMockAutoWrap.cmake)

# Unit Test Fixtures (for unit tests with DAP SDK mocking)
project(unit_test_fixtures)

add_library(${PROJECT_NAME} OBJECT
    unit_test_fixtures.c
)

# Only expose fixture headers directory - all others propagate via modules
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME} PUBLIC
    dap_test        # Provides dap_mock headers
    dap_core        # Provides dap_common, dap_config, etc.
    dap_crypto      # Provides dap_enc, dap_sign, dap_hash
    dap_common      # Provides dap_strfuncs, dap_list, etc.
    cellframe_sdk   # Provides chain/ledger/net/consensus headers
)

# Apply dap_mock auto-wrapping for DAP SDK functions
dap_mock_autowrap(${PROJECT_NAME})

# Integration Test Fixtures (for integration tests with full stack)
project(test_fixtures)

add_library(${PROJECT_NAME} OBJECT
    integration_test_fixtures.c
    test_fixtures.c
)

# Only expose fixture headers directory - all others propagate via modules
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link modules - includes propagate automatically
target_link_libraries(${PROJECT_NAME} PUBLIC
    dap_core        # Provides dap_common, dap_config, etc.
    dap_crypto      # Provides dap_enc, dap_sign, dap_hash
    dap_common      # Provides dap_strfuncs, dap_list, etc.
    cellframe_sdk   # Provides chain/ledger/net/wallet/datum headers
)
